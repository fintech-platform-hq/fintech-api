import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { createDecipheriv, createHash } from 'crypto';
import { readFileSync } from 'fs';
import { Pool, PoolClient } from 'pg';
import { DatabaseService } from '../src/common/database/database.service';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from '../src/app.module';
import { AppleAuthError } from '../src/modules/auth/apple-auth.errors';
import {
  AppleAuthorizationExchange,
  AppleTokenService,
} from '../src/modules/auth/apple-token.service';

const databaseUrl = process.env.TEST_DATABASE_URL;
const describeWithDatabase = databaseUrl ? describe : describe.skip;
const encryptionKey = Buffer.alloc(32, 11);
const nonce = 'n'.repeat(43);

describeWithDatabase('Sign in with Apple (PostgreSQL integration)', () => {
  let app: INestApplication<App>;
  let pool: Pool;
  let nextIp = 1;
  const exchangeAuthorizationCode = jest.fn<
    Promise<AppleAuthorizationExchange>,
    [string, string, string]
  >();

  beforeAll(async () => {
    process.env.DATABASE_URL = databaseUrl;
    process.env.JWT_ACCESS_SECRET =
      'integration-test-secret-with-at-least-32-bytes';
    process.env.JWT_ISSUER = 'fintech-api-integration';
    process.env.JWT_AUDIENCE = 'fintech-clients-integration';
    process.env.APPLE_REFRESH_TOKEN_ENCRYPTION_KEY =
      encryptionKey.toString('base64url');

    pool = new Pool({ connectionString: databaseUrl });
    const database = await pool.query<{ current_database: string }>(
      'SELECT current_database()',
    );
    if (!database.rows[0].current_database.endsWith('_test')) {
      throw new Error('Integration tests require a database ending in _test');
    }

    await pool.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public');
    await pool.query(readFileSync('db.sql', 'utf8'));

    const module = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(AppleTokenService)
      .useValue({ exchangeAuthorizationCode })
      .compile();
    app = module.createNestApplication();
    const express = app.getHttpAdapter().getInstance() as {
      set(setting: string, value: unknown): void;
    };
    express.set('trust proxy', 1);
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
        validationError: { target: false, value: false },
      }),
    );
    await app.init();
  });

  beforeEach(() => exchangeAuthorizationCode.mockReset());

  afterAll(async () => {
    await app?.close();
    await pool?.end();
  });

  it('creates and reuses one Apple identity with an encrypted provider token', async () => {
    exchangeAuthorizationCode
      .mockResolvedValueOnce({
        subject: 'apple-existing-subject',
        refreshToken: 'apple-refresh-first',
        email: 'relay@privaterelay.appleid.com',
        isPrivateEmail: true,
      })
      .mockResolvedValueOnce({
        subject: 'apple-existing-subject',
        refreshToken: 'apple-refresh-second',
        isPrivateEmail: false,
      });

    const first = authBody((await postApple('first')).body as unknown);
    expect(exchangeAuthorizationCode).toHaveBeenNthCalledWith(
      1,
      'identity-first',
      'code-first',
      nonce,
    );
    const firstClaims = accessTokenClaims(first.accessToken);
    expect(firstClaims.auth_method).toBe('apple');

    const stored = await pool.query<{
      user_id: string;
      identity_id: string;
      email: string;
      password_hash: string | null;
      provider_email: string;
      is_private_email: boolean;
      ciphertext: string;
      auth_identity_id: string;
      token_hash: string;
    }>(
      `
        SELECT u.id AS user_id, ai.id AS identity_id, u.email, u.password_hash,
               ai.provider_email, ai.is_private_email,
               ai.provider_refresh_token_ciphertext AS ciphertext,
               rs.auth_identity_id, rs.token_hash
        FROM users u
        JOIN auth_identities ai ON ai.user_id = u.id
        JOIN refresh_sessions rs ON rs.user_id = u.id
        WHERE ai.provider = 'apple' AND ai.provider_subject = $1
          AND rs.token_hash = $2
      `,
      ['apple-existing-subject', hashToken(first.refreshToken)],
    );
    expect(stored.rows[0]).toMatchObject({
      email: 'relay@privaterelay.appleid.com',
      password_hash: null,
      provider_email: 'relay@privaterelay.appleid.com',
      is_private_email: true,
      auth_identity_id: stored.rows[0].identity_id,
    });
    expect(stored.rows[0].token_hash).not.toBe(first.refreshToken);
    expect(
      decryptProviderToken(
        stored.rows[0].ciphertext,
        stored.rows[0].identity_id,
      ),
    ).toBe('apple-refresh-first');

    const rotated = authBody(
      (
        await request(app.getHttpServer())
          .post('/auth/refresh')
          .send({ refreshToken: first.refreshToken })
          .expect(200)
      ).body as unknown,
    );
    expect(accessTokenClaims(rotated.accessToken).auth_method).toBe('apple');
    const rotatedSession = await pool.query<{ auth_identity_id: string }>(
      'SELECT auth_identity_id FROM refresh_sessions WHERE token_hash = $1',
      [hashToken(rotated.refreshToken)],
    );
    expect(rotatedSession.rows[0].auth_identity_id).toBe(
      stored.rows[0].identity_id,
    );

    const second = authBody((await postApple('second')).body as unknown);
    expect(accessTokenClaims(second.accessToken).sub).toBe(
      stored.rows[0].user_id,
    );
    const reused = await pool.query<{
      users: number;
      identities: number;
      provider_email: string;
      is_private_email: boolean;
      ciphertext: string;
    }>(
      `
        SELECT
          (SELECT COUNT(*)::int FROM users u JOIN auth_identities ai ON ai.user_id = u.id WHERE ai.provider_subject = $1) AS users,
          COUNT(*)::int AS identities,
          MAX(provider_email) AS provider_email,
          bool_or(is_private_email) AS is_private_email,
          MAX(provider_refresh_token_ciphertext) AS ciphertext
        FROM auth_identities
        WHERE provider = 'apple' AND provider_subject = $1
      `,
      ['apple-existing-subject'],
    );
    expect(reused.rows[0]).toMatchObject({
      users: 1,
      identities: 1,
      provider_email: 'relay@privaterelay.appleid.com',
      is_private_email: true,
    });
    expect(
      decryptProviderToken(
        reused.rows[0].ciphertext,
        stored.rows[0].identity_id,
      ),
    ).toBe('apple-refresh-second');
  });

  it('serializes concurrent first logins for the same Apple subject', async () => {
    exchangeAuthorizationCode.mockResolvedValue({
      subject: 'apple-concurrent-subject',
      refreshToken: 'apple-concurrent-refresh',
      isPrivateEmail: false,
    });

    const responses = await Promise.all([
      postApple('concurrent-one'),
      postApple('concurrent-two'),
    ]);
    expect(responses.map((response) => response.status)).toEqual([200, 200]);

    const result = await pool.query<{
      users: number;
      identities: number;
      apple_only_users: number;
    }>(
      `
        SELECT COUNT(DISTINCT ai.user_id)::int AS users,
               COUNT(*)::int AS identities,
               COUNT(*) FILTER (
                 WHERE u.email IS NULL AND u.password_hash IS NULL
               )::int AS apple_only_users
        FROM auth_identities ai
        JOIN users u ON u.id = ai.user_id
        WHERE provider = 'apple' AND provider_subject = $1
      `,
      ['apple-concurrent-subject'],
    );
    expect(result.rows[0]).toEqual({
      users: 1,
      identities: 1,
      apple_only_users: 1,
    });
  });

  it('links an Apple identity without creating a Fintech session and updates it idempotently', async () => {
    const registered = authBody(
      (
        await request(app.getHttpServer())
          .post('/auth/register')
          .set('X-Forwarded-For', `198.51.100.${nextIp++}`)
          .send({ email: 'link-owner@example.com', password: 'correct horse' })
          .expect(201)
      ).body as unknown,
    );
    const userId = accessTokenClaims(registered.accessToken).sub;
    const passwordSession = await snapshotLinkedState(
      pool,
      'apple-link-subject',
      userId,
    );
    expect(passwordSession.identity).toHaveLength(0);
    expect(passwordSession.sessions).toHaveLength(1);
    exchangeAuthorizationCode
      .mockResolvedValueOnce({
        subject: 'apple-link-subject',
        refreshToken: 'apple-link-refresh-first',
        email: 'relay@privaterelay.appleid.com',
        isPrivateEmail: true,
      })
      .mockResolvedValueOnce({
        subject: 'apple-link-subject',
        refreshToken: 'apple-link-refresh-second',
        isPrivateEmail: false,
      });

    await postAppleLink(registered.accessToken, 'link-first').expect(204);
    const firstLinked = await snapshotLinkedState(
      pool,
      'apple-link-subject',
      userId,
    );
    expect(firstLinked.sessions).toEqual(passwordSession.sessions);
    await pool.query(
      `UPDATE auth_identities SET revoked_at = now(),
         last_provider_validation_at = TIMESTAMPTZ '2026-01-01 00:00:00+00'
       WHERE provider = 'apple' AND provider_subject = $1`,
      ['apple-link-subject'],
    );
    const before = await snapshotLinkedState(
      pool,
      'apple-link-subject',
      userId,
    );
    await postAppleLink(registered.accessToken, 'link-second').expect(204);

    const stored = await pool.query<{
      user_id: string;
      provider_email: string;
      is_private_email: boolean;
      revoked_at: Date | null;
      ciphertext: string;
      identity_id: string;
      last_provider_validation_at: Date;
    }>(
      `SELECT ai.user_id, ai.provider_email, ai.is_private_email,
              ai.revoked_at, ai.provider_refresh_token_ciphertext AS ciphertext,
              ai.last_provider_validation_at,
              ai.id AS identity_id
       FROM auth_identities ai
       WHERE ai.provider = 'apple' AND ai.provider_subject = $1`,
      ['apple-link-subject'],
    );
    expect(stored.rows).toHaveLength(1);
    expect(stored.rows[0]).toMatchObject({
      user_id: userId,
      provider_email: 'relay@privaterelay.appleid.com',
      is_private_email: true,
      revoked_at: null,
    });
    expect(stored.rows[0].provider_email).toBe(
      before.identity[0].provider_email,
    );
    expect(stored.rows[0].is_private_email).toBe(
      before.identity[0].is_private_email,
    );
    expect(stored.rows[0].revoked_at).toBeNull();
    expect(stored.rows[0].identity_id).toBe(before.identity[0].id);
    expect(stored.rows[0].ciphertext).not.toBe(before.identity[0].ciphertext);
    expect(before.identity[0].last_provider_validation_at).not.toBeNull();
    expect(stored.rows[0].last_provider_validation_at).toBeInstanceOf(Date);
    expect(before.identity[0].last_provider_validation_at).toBeInstanceOf(Date);
    expect(
      stored.rows[0].last_provider_validation_at.getTime(),
    ).toBeGreaterThan(
      before.identity[0].last_provider_validation_at!.getTime(),
    );
    expect(
      decryptProviderToken(
        stored.rows[0].ciphertext,
        stored.rows[0].identity_id,
      ),
    ).toBe('apple-link-refresh-second');
    const after = await snapshotLinkedState(pool, 'apple-link-subject', userId);
    expect(after.sessions).toEqual(passwordSession.sessions);
  });

  it('does not merge an Apple email that belongs to another user', async () => {
    const first = authBody(
      (
        await request(app.getHttpServer())
          .post('/auth/register')
          .set('X-Forwarded-For', `198.51.100.${nextIp++}`)
          .send({ email: 'link-first@example.com', password: 'correct horse' })
          .expect(201)
      ).body as unknown,
    );
    const second = authBody(
      (
        await request(app.getHttpServer())
          .post('/auth/register')
          .set('X-Forwarded-For', `198.51.100.${nextIp++}`)
          .send({
            email: 'link-email-owner@example.com',
            password: 'correct horse',
          })
          .expect(201)
      ).body as unknown,
    );
    const firstUserId = accessTokenClaims(first.accessToken).sub;
    const secondUserId = accessTokenClaims(second.accessToken).sub;
    exchangeAuthorizationCode.mockResolvedValue({
      subject: 'apple-email-link-subject',
      refreshToken: 'apple-email-link-refresh',
      email: 'link-email-owner@example.com',
      isPrivateEmail: false,
    });

    await postAppleLink(first.accessToken, 'email-link').expect(204);

    const identity = await pool.query<{ user_id: string }>(
      'SELECT user_id FROM auth_identities WHERE provider_subject = $1',
      ['apple-email-link-subject'],
    );
    expect(identity.rows[0].user_id).toBe(firstUserId);
    expect(identity.rows[0].user_id).not.toBe(secondUserId);
    const users = await pool.query<{ id: string; email: string }>(
      'SELECT id, email FROM users WHERE id = ANY($1::uuid[]) ORDER BY id',
      [[firstUserId, secondUserId]],
    );
    expect(users.rows.map((row) => row.email).sort()).toEqual([
      'link-email-owner@example.com',
      'link-first@example.com',
    ]);
  });

  it('returns 409 when the Apple identity belongs to another user', async () => {
    const first = authBody(
      (
        await request(app.getHttpServer())
          .post('/auth/register')
          .set('X-Forwarded-For', `198.51.100.${nextIp++}`)
          .send({
            email: 'link-conflict-first@example.com',
            password: 'correct horse',
          })
          .expect(201)
      ).body as unknown,
    );
    const second = authBody(
      (
        await request(app.getHttpServer())
          .post('/auth/register')
          .set('X-Forwarded-For', `198.51.100.${nextIp++}`)
          .send({
            email: 'link-conflict-second@example.com',
            password: 'correct horse',
          })
          .expect(201)
      ).body as unknown,
    );
    exchangeAuthorizationCode.mockResolvedValue({
      subject: 'apple-owned-by-first',
      refreshToken: 'apple-owned-refresh',
      isPrivateEmail: false,
    });

    await postAppleLink(first.accessToken, 'owner').expect(204);
    const conflict = await postAppleLink(second.accessToken, 'other').expect(
      409,
    );
    expect((conflict.body as { message?: unknown }).message).toBe(
      'Apple identity cannot be linked',
    );
  });

  it('serializes concurrent links for one Apple subject', async () => {
    const first = authBody(
      (
        await request(app.getHttpServer())
          .post('/auth/register')
          .set('X-Forwarded-For', `198.51.100.${nextIp++}`)
          .send({
            email: 'link-race-first@example.com',
            password: 'correct horse',
          })
          .expect(201)
      ).body as unknown,
    );
    const second = authBody(
      (
        await request(app.getHttpServer())
          .post('/auth/register')
          .set('X-Forwarded-For', `198.51.100.${nextIp++}`)
          .send({
            email: 'link-race-second@example.com',
            password: 'correct horse',
          })
          .expect(201)
      ).body as unknown,
    );
    exchangeAuthorizationCode.mockResolvedValue({
      subject: 'apple-link-race-subject',
      refreshToken: 'apple-link-race-refresh',
      isPrivateEmail: false,
    });

    const responses = await Promise.all([
      postAppleLink(first.accessToken, 'race-first'),
      postAppleLink(second.accessToken, 'race-second'),
    ]);
    expect(responses.map((response) => response.status).sort()).toEqual([
      204, 409,
    ]);

    const identity = await pool.query<{ user_id: string }>(
      'SELECT user_id FROM auth_identities WHERE provider_subject = $1',
      ['apple-link-race-subject'],
    );
    expect(identity.rows).toHaveLength(1);
    const winner = responses[0].status === 204 ? first : second;
    expect(identity.rows[0].user_id).toBe(
      accessTokenClaims(winner.accessToken).sub,
    );
  });

  it.each([
    ['link acquires the lock first', true],
    ['Apple login acquires the lock first', false],
  ])('deterministically serializes %s', async (_label, linkFirst) => {
    const registered = authBody(
      (
        await request(app.getHttpServer())
          .post('/auth/register')
          .set('X-Forwarded-For', `198.51.100.${nextIp++}`)
          .send({
            email: `cross-flow-${linkFirst}@example.com`,
            password: 'correct horse',
          })
          .expect(201)
      ).body as unknown,
    );
    const subject = `apple-cross-flow-${linkFirst}`;
    const lockKey = linkFirst ? 730_402 : 730_403;
    const blocker = await pool.connect();
    const clients: PoolClient[] = [];
    const releaseSpies: jest.SpyInstance[] = [];
    let checkout: jest.SpyInstance | undefined;
    let failed = false;
    let firstResponse: Promise<request.Response> | undefined;
    let secondResponse: Promise<request.Response> | undefined;
    try {
      for (let i = 0; i < 2; i++) {
        const client = await pool.connect();
        clients.push(client);
        // The fixture owns these connections until both requests have settled.
        releaseSpies.push(
          jest.spyOn(client, 'release').mockImplementation(() => {}),
        );
      }
      const [firstClient, secondClient] = clients;
      const firstPid = (
        await firstClient.query<{ pid: number }>(
          'SELECT pg_backend_pid() AS pid',
        )
      ).rows[0].pid;
      const secondPid = (
        await secondClient.query<{ pid: number }>(
          'SELECT pg_backend_pid() AS pid',
        )
      ).rows[0].pid;
      const blockerPid = (
        await blocker.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')
      ).rows[0].pid;
      const appleKey = (
        await pool.query<{ key: string }>(
          'SELECT hashtextextended($1, 0)::text AS key',
          [`apple:${subject}`],
        )
      ).rows[0].key;
      checkout = jest
        .spyOn(app.get(DatabaseService), 'getClient')
        .mockResolvedValueOnce(firstClient)
        .mockResolvedValueOnce(secondClient);
      await pool.query(`
        CREATE FUNCTION test_block_apple_identity_insert()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.provider = 'apple' THEN
            PERFORM pg_advisory_xact_lock(${lockKey});
          END IF;
          RETURN NEW;
        END;
        $$;
        CREATE TRIGGER test_block_apple_identity_insert
        BEFORE INSERT ON auth_identities
        FOR EACH ROW EXECUTE FUNCTION test_block_apple_identity_insert();
      `);
      await blocker.query('BEGIN');
      await blocker.query('SELECT pg_advisory_xact_lock($1)', [lockKey]);
      exchangeAuthorizationCode.mockResolvedValue({
        subject,
        refreshToken: `refresh-${subject}`,
        isPrivateEmail: false,
      });

      firstResponse = (
        linkFirst
          ? postAppleLink(registered.accessToken, `first-${subject}`)
          : postApple(`first-${subject}`)
      ).then((response) => response);
      void firstResponse.catch(() => undefined);
      await waitForAdvisoryWait(pool, firstPid, blockerPid, String(lockKey));
      expect(checkout).toHaveBeenCalledTimes(1);
      secondResponse = (
        linkFirst
          ? postApple(`second-${subject}`)
          : postAppleLink(registered.accessToken, `second-${subject}`)
      ).then((response) => response);
      void secondResponse.catch(() => undefined);
      await waitForAdvisoryWait(pool, secondPid, firstPid, appleKey);
      expect(checkout).toHaveBeenCalledTimes(2);
      await blocker.query('COMMIT');
      const [first, second] = await Promise.all([
        firstResponse,
        secondResponse,
      ]);
      const statuses = [first.status, second.status].sort();
      expect(statuses).toEqual(linkFirst ? [200, 204] : [200, 409]);
      if (!linkFirst) {
        expect((second.body as { message?: unknown }).message).toBe(
          'Apple identity cannot be linked',
        );
      }
      const identity = await pool.query<{ user_id: string }>(
        'SELECT user_id FROM auth_identities WHERE provider_subject = $1',
        [subject],
      );
      expect(identity.rows).toHaveLength(1);
      if (linkFirst) {
        expect(identity.rows[0].user_id).toBe(
          accessTokenClaims(registered.accessToken).sub,
        );
      }
      expect(exchangeAuthorizationCode).toHaveBeenCalledTimes(2);
    } catch (error) {
      failed = true;
      throw error;
    } finally {
      const cleanupErrors: unknown[] = [];
      let barrierFailed = false;
      try {
        await blocker.query('ROLLBACK');
      } catch (error) {
        barrierFailed = true;
        cleanupErrors.push(error);
      } finally {
        try {
          blocker.release(barrierFailed);
        } catch (error) {
          cleanupErrors.push(error);
        }
      }
      const settled = await Promise.allSettled([firstResponse, secondResponse]);
      for (const result of settled)
        if (result.status === 'rejected') cleanupErrors.push(result.reason);
      checkout?.mockRestore();
      for (let i = 0; i < clients.length; i++) {
        let broken = false;
        try {
          await clients[i].query('ROLLBACK');
        } catch (error) {
          broken = true;
          cleanupErrors.push(error);
        } finally {
          releaseSpies[i].mockRestore();
          try {
            clients[i].release(broken);
          } catch (error) {
            cleanupErrors.push(error);
          }
        }
      }
      for (const sql of [
        'DROP TRIGGER IF EXISTS test_block_apple_identity_insert ON auth_identities',
        'DROP FUNCTION IF EXISTS test_block_apple_identity_insert()',
      ]) {
        try {
          await pool.query(sql);
        } catch (error) {
          cleanupErrors.push(error);
        }
      }
      if (!failed && cleanupErrors.length) throw cleanupErrors[0];
    }
  });

  it('rolls back all linking changes after a post-update database error', async () => {
    const registered = authBody(
      (
        await request(app.getHttpServer())
          .post('/auth/register')
          .set('X-Forwarded-For', `198.51.100.${nextIp++}`)
          .send({
            email: 'link-rollback@example.com',
            password: 'correct horse',
          })
          .expect(201)
      ).body as unknown,
    );
    exchangeAuthorizationCode.mockResolvedValueOnce({
      subject: 'apple-rollback-subject',
      refreshToken: 'rollback-first',
      email: 'before@example.com',
      isPrivateEmail: true,
    });
    await postAppleLink(registered.accessToken, 'rollback-first').expect(204);
    const userId = accessTokenClaims(registered.accessToken).sub;
    await pool.query(
      `UPDATE auth_identities
       SET revoked_at = TIMESTAMPTZ '2026-01-01 00:00:00+00',
           last_provider_validation_at = TIMESTAMPTZ '2026-01-02 00:00:00+00'
       WHERE provider_subject = $1`,
      ['apple-rollback-subject'],
    );
    const before = await snapshotLinkedState(
      pool,
      'apple-rollback-subject',
      userId,
    );
    expect(before.identity).toHaveLength(1);
    expect(before.identity[0].revoked_at).not.toBeNull();
    expect(before.sessions).toHaveLength(1);
    const client = await pool.connect();
    const releaseSpy = jest
      .spyOn(client, 'release')
      .mockImplementation(() => {});
    let checkout: jest.SpyInstance | undefined;
    let querySpy: jest.SpyInstance | undefined;
    let failed = false;
    const phases: string[] = [];
    let commitError: unknown;
    let transactionState: string | undefined;
    let updatedIdentity: LinkedStateSnapshot['identity'][number] | undefined;
    try {
      const pid = (
        await client.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')
      ).rows[0].pid;
      checkout = jest
        .spyOn(app.get(DatabaseService), 'getClient')
        .mockResolvedValueOnce(client);
      const execute = client.query.bind(client);
      querySpy = jest.spyOn(client, 'query').mockImplementation((async (
        sql: string,
        values?: unknown[],
      ) => {
        const statement = sql.trim();
        if (statement === 'COMMIT') phases.push('commit-start');
        try {
          const result = await execute(sql, values);
          if (statement.startsWith('UPDATE auth_identities')) {
            phases.push('update-completed');
            transactionState = (
              await pool.query<{ state: string }>(
                'SELECT state FROM pg_stat_activity WHERE pid = $1',
                [pid],
              )
            ).rows[0].state;
            updatedIdentity = (
              await execute<LinkedStateSnapshot['identity'][number]>(
                `SELECT *, provider_refresh_token_ciphertext AS ciphertext
               FROM auth_identities WHERE id = $1`,
                [before.identity[0].id],
              )
            ).rows[0];
            phases.push('transaction-observed');
          }
          if (statement === 'ROLLBACK') phases.push('rollback-completed');
          return result;
        } catch (error) {
          if (statement === 'COMMIT') {
            commitError = error;
            phases.push('commit-failed');
          }
          throw error;
        }
      }) as typeof client.query);
      await pool.query(`
        CREATE FUNCTION test_fail_at_apple_identity_commit()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION USING ERRCODE = 'P5505',
            MESSAGE = 'checkpoint5_fixture_commit_failure',
            CONSTRAINT = 'test_fail_at_apple_identity_commit';
        END;
        $$;
        CREATE CONSTRAINT TRIGGER test_fail_at_apple_identity_commit
        AFTER UPDATE ON auth_identities DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW EXECUTE FUNCTION test_fail_at_apple_identity_commit();
      `);
      exchangeAuthorizationCode.mockResolvedValueOnce({
        subject: 'apple-rollback-subject',
        refreshToken: 'rollback-second',
        email: 'after@example.com',
        isPrivateEmail: false,
      });
      const response = await postAppleLink(
        registered.accessToken,
        'rollback-second',
      );
      expect(response.status).toBe(500);
      expect(phases).toEqual([
        'update-completed',
        'transaction-observed',
        'commit-start',
        'commit-failed',
        'rollback-completed',
      ]);
      expect(transactionState).toBe('idle in transaction');
      expect(commitError).toMatchObject({
        code: 'P5505',
        message: 'checkpoint5_fixture_commit_failure',
        constraint: 'test_fail_at_apple_identity_commit',
      });
      expect(updatedIdentity).toMatchObject({
        id: before.identity[0].id,
        provider_email: 'after@example.com',
        is_private_email: false,
        revoked_at: null,
      });
      expect(updatedIdentity!.ciphertext).not.toBe(
        before.identity[0].ciphertext,
      );
      expect(
        updatedIdentity!.last_provider_validation_at!.getTime(),
      ).toBeGreaterThan(
        before.identity[0].last_provider_validation_at!.getTime(),
      );
      expect(exchangeAuthorizationCode).toHaveBeenCalledTimes(2);
      expect(checkout).toHaveBeenCalledTimes(1);
      await expect(
        snapshotLinkedState(pool, 'apple-rollback-subject', userId),
      ).resolves.toEqual(before);
    } catch (error) {
      failed = true;
      throw error;
    } finally {
      const cleanupErrors: unknown[] = [];
      querySpy?.mockRestore();
      checkout?.mockRestore();
      let broken = false;
      try {
        await client.query('ROLLBACK');
      } catch (error) {
        broken = true;
        cleanupErrors.push(error);
      } finally {
        releaseSpy.mockRestore();
        try {
          client.release(broken);
        } catch (error) {
          cleanupErrors.push(error);
        }
      }
      for (const sql of [
        'DROP TRIGGER IF EXISTS test_fail_at_apple_identity_commit ON auth_identities',
        'DROP FUNCTION IF EXISTS test_fail_at_apple_identity_commit()',
      ]) {
        try {
          await pool.query(sql);
        } catch (error) {
          cleanupErrors.push(error);
        }
      }
      if (!failed && cleanupErrors.length) throw cleanupErrors[0];
    }
  });

  it('returns one success and one sanitized conflict for different subjects on one user', async () => {
    const registered = authBody(
      (
        await request(app.getHttpServer())
          .post('/auth/register')
          .set('X-Forwarded-For', `198.51.100.${nextIp++}`)
          .send({
            email: 'link-subject-race@example.com',
            password: 'correct horse',
          })
          .expect(201)
      ).body as unknown,
    );
    exchangeAuthorizationCode.mockImplementation((_identity, code) =>
      Promise.resolve({
        subject: code.includes('one')
          ? 'apple-subject-one'
          : 'apple-subject-two',
        refreshToken: `refresh-${code}`,
        isPrivateEmail: false,
      }),
    );
    const lockKey = 730_404;
    const blocker = await pool.connect();
    const clients: PoolClient[] = [];
    const releaseSpies: jest.SpyInstance[] = [];
    const querySpies: jest.SpyInstance[] = [];
    let checkout: jest.SpyInstance | undefined;
    let failed = false;
    let firstResponse: Promise<request.Response> | undefined;
    let secondResponse: Promise<request.Response> | undefined;
    try {
      for (let i = 0; i < 2; i++) {
        const client = await pool.connect();
        clients.push(client);
        releaseSpies.push(
          jest.spyOn(client, 'release').mockImplementation(() => {}),
        );
      }
      const pids = await Promise.all(
        clients.map(
          async (client) =>
            (
              await client.query<{ pid: number }>(
                'SELECT pg_backend_pid() AS pid',
              )
            ).rows[0].pid,
        ),
      );
      const blockerPid = (
        await blocker.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')
      ).rows[0].pid;
      checkout = jest
        .spyOn(app.get(DatabaseService), 'getClient')
        .mockResolvedValueOnce(clients[0])
        .mockResolvedValueOnce(clients[1]);
      querySpies.push(...clients.map((client) => jest.spyOn(client, 'query')));
      await pool.query(`
        CREATE FUNCTION test_block_different_subject_links()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.provider = 'apple' THEN
            PERFORM pg_advisory_xact_lock_shared(${lockKey});
          END IF;
          RETURN NEW;
        END;
        $$;
        CREATE TRIGGER test_block_different_subject_links
        BEFORE INSERT ON auth_identities
        FOR EACH ROW EXECUTE FUNCTION test_block_different_subject_links();
        CREATE FUNCTION test_hold_subject_winner_at_commit()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          PERFORM pg_advisory_xact_lock(${lockKey + 1});
          RETURN NEW;
        END;
        $$;
        CREATE CONSTRAINT TRIGGER test_hold_subject_winner_at_commit
        AFTER INSERT ON auth_identities DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW EXECUTE FUNCTION test_hold_subject_winner_at_commit();
      `);
      await blocker.query('SELECT pg_advisory_lock($1), pg_advisory_lock($2)', [
        lockKey,
        lockKey + 1,
      ]);
      firstResponse = postAppleLink(registered.accessToken, 'subject-one').then(
        (response) => response,
      );
      void firstResponse.catch(() => undefined);
      await waitForAdvisoryWait(
        pool,
        pids[0],
        blockerPid,
        String(lockKey),
        'ShareLock',
      );
      secondResponse = postAppleLink(
        registered.accessToken,
        'subject-two',
      ).then((response) => response);
      void secondResponse.catch(() => undefined);
      await waitForAdvisoryWait(
        pool,
        pids[1],
        blockerPid,
        String(lockKey),
        'ShareLock',
      );
      expect(checkout).toHaveBeenCalledTimes(2);
      await blocker.query('SELECT pg_advisory_unlock($1)', [lockKey]);
      // One insert is now waiting on the winner's uncommitted unique-index entry.
      let winnerPid: number | undefined;
      const deadline = Date.now() + 5_000;
      do {
        const waiting = await pool.query<{ blocker: number }>(
          `
          SELECT b.pid AS blocker FROM pg_locks w
          JOIN pg_locks b ON b.locktype = w.locktype AND b.transactionid = w.transactionid
          WHERE w.locktype = 'transactionid' AND NOT w.granted AND b.granted
            AND w.pid = ANY($1::int[]) AND b.pid = ANY($1::int[]) AND w.pid <> b.pid
            AND b.pid = ANY(pg_blocking_pids(w.pid))
        `,
          [pids],
        );
        if (waiting.rows.length === 1) {
          winnerPid = waiting.rows[0].blocker;
          break;
        }
        await new Promise<void>((resolve) => setImmediate(resolve));
      } while (Date.now() < deadline);
      expect(winnerPid).toBeDefined();
      await waitForAdvisoryWait(
        pool,
        winnerPid!,
        blockerPid,
        String(lockKey + 1),
      );
      await blocker.query('SELECT pg_advisory_unlock($1)', [lockKey + 1]);
      const responses = await Promise.all([firstResponse, secondResponse]);
      const loserIndex = pids[0] === winnerPid ? 1 : 0;
      expect(responses[loserIndex].status).toBe(409);
      expect(responses[1 - loserIndex].status).toBe(204);
      const insertIndex = querySpies[loserIndex].mock.calls.findIndex(
        ([sql]) =>
          typeof sql === 'string' &&
          sql.trim().startsWith('INSERT INTO auth_identities'),
      );
      expect(insertIndex).toBeGreaterThanOrEqual(0);
      await expect(
        querySpies[loserIndex].mock.results[insertIndex].value,
      ).rejects.toMatchObject({
        code: '23505',
        constraint: 'auth_identities_user_id_provider_key',
      });
      expect(responses[loserIndex].body).toEqual({
        error: 'Conflict',
        statusCode: 409,
        message: 'Apple identity cannot be linked',
      });
      expect(exchangeAuthorizationCode).toHaveBeenCalledTimes(2);
      const identities = await pool.query<{
        provider_subject: string;
        user_id: string;
        id: string;
        ciphertext: string;
      }>(
        `SELECT id, user_id, provider_subject, provider_refresh_token_ciphertext AS ciphertext
         FROM auth_identities WHERE user_id = $1 OR provider_subject = ANY($2::text[])`,
        [
          accessTokenClaims(registered.accessToken).sub,
          ['apple-subject-one', 'apple-subject-two'],
        ],
      );
      expect(identities.rows).toHaveLength(1);
      expect(identities.rows[0]).toMatchObject({
        provider_subject:
          loserIndex === 1 ? 'apple-subject-one' : 'apple-subject-two',
        user_id: accessTokenClaims(registered.accessToken).sub,
      });
      expect(
        decryptProviderToken(
          identities.rows[0].ciphertext,
          identities.rows[0].id,
        ),
      ).toBe(
        loserIndex === 1
          ? 'refresh-code-link-subject-one'
          : 'refresh-code-link-subject-two',
      );
    } catch (error) {
      failed = true;
      throw error;
    } finally {
      const cleanupErrors: unknown[] = [];
      let barrierFailed = false;
      try {
        await blocker.query('SELECT pg_advisory_unlock_all()');
      } catch (error) {
        barrierFailed = true;
        cleanupErrors.push(error);
      } finally {
        try {
          blocker.release(barrierFailed);
        } catch (error) {
          cleanupErrors.push(error);
        }
      }
      const settled = await Promise.allSettled([firstResponse, secondResponse]);
      for (const result of settled)
        if (result.status === 'rejected') cleanupErrors.push(result.reason);
      checkout?.mockRestore();
      for (const spy of querySpies) spy.mockRestore();
      for (let i = 0; i < clients.length; i++) {
        let broken = false;
        try {
          await clients[i].query('ROLLBACK');
        } catch (error) {
          broken = true;
          cleanupErrors.push(error);
        } finally {
          releaseSpies[i].mockRestore();
          try {
            clients[i].release(broken);
          } catch (error) {
            cleanupErrors.push(error);
          }
        }
      }
      for (const sql of [
        'DROP TRIGGER IF EXISTS test_block_different_subject_links ON auth_identities',
        'DROP TRIGGER IF EXISTS test_hold_subject_winner_at_commit ON auth_identities',
        'DROP FUNCTION IF EXISTS test_block_different_subject_links()',
        'DROP FUNCTION IF EXISTS test_hold_subject_winner_at_commit()',
      ]) {
        try {
          await pool.query(sql);
        } catch (error) {
          cleanupErrors.push(error);
        }
      }
      if (!failed && cleanupErrors.length) throw cleanupErrors[0];
    }
  });

  it('rejects malformed input before consuming an authorization code', async () => {
    await request(app.getHttpServer())
      .post('/auth/apple')
      .set('X-Forwarded-For', `198.51.100.${nextIp++}`)
      .send({
        identityToken: 'identity',
        authorizationCode: 'code',
        nonce: 'not-the-required-raw-nonce',
      })
      .expect(400);
    expect(exchangeAuthorizationCode).not.toHaveBeenCalled();
  });

  it('requires explicit linking when a verified Apple email already exists', async () => {
    const registered = authBody(
      (
        await request(app.getHttpServer())
          .post('/auth/register')
          .set('X-Forwarded-For', `198.51.100.${nextIp++}`)
          .send({ email: 'collision@example.com', password: 'correct horse' })
          .expect(201)
      ).body as unknown,
    );
    expect(accessTokenClaims(registered.accessToken).auth_method).toBe(
      'password',
    );
    exchangeAuthorizationCode.mockResolvedValue({
      subject: 'apple-collision-subject',
      refreshToken: 'apple-collision-refresh',
      email: 'collision@example.com',
      isPrivateEmail: false,
    });

    const response = await postApple('collision').expect(409);
    expect(response.body).toMatchObject({ code: 'ACCOUNT_LINK_REQUIRED' });
    const identity = await pool.query(
      'SELECT 1 FROM auth_identities WHERE provider_subject = $1',
      ['apple-collision-subject'],
    );
    expect(identity.rowCount).toBe(0);
  });

  it('maps only sanitized Apple errors to public HTTP responses', async () => {
    exchangeAuthorizationCode.mockRejectedValueOnce(
      new AppleAuthError('INVALID_IDENTITY_TOKEN', 'provider detail'),
    );
    const invalid = await postApple('invalid').expect(401);
    expect(invalid.body).toMatchObject({
      message: 'Invalid Apple authentication',
    });
    expect(JSON.stringify(invalid.body)).not.toContain('provider detail');

    exchangeAuthorizationCode.mockRejectedValueOnce(
      new AppleAuthError('APPLE_TOKEN_API_UNAVAILABLE', 'provider detail'),
    );
    const unavailable = await postApple('unavailable').expect(503);
    expect(unavailable.body).toMatchObject({
      message: 'Apple authentication is temporarily unavailable',
    });
    expect(JSON.stringify(unavailable.body)).not.toContain('provider detail');
  });

  it('lets users.email resolve an Apple signup versus password registration race', async () => {
    const lockKey = 730_401;
    const blocker = await pool.connect();
    let appleResponse: Promise<request.Response> | undefined;

    await pool.query(`
      CREATE FUNCTION test_block_apple_user_insert()
      RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        IF NEW.password_hash IS NULL THEN
          PERFORM pg_advisory_xact_lock(${lockKey});
        END IF;
        RETURN NEW;
      END;
      $$;
      CREATE TRIGGER test_block_apple_user_insert
      BEFORE INSERT ON users
      FOR EACH ROW EXECUTE FUNCTION test_block_apple_user_insert();
    `);

    try {
      await blocker.query('BEGIN');
      await blocker.query('SELECT pg_advisory_xact_lock($1)', [lockKey]);
      exchangeAuthorizationCode.mockResolvedValue({
        subject: 'apple-race-subject',
        refreshToken: 'apple-race-refresh',
        email: 'race@example.com',
        isPrivateEmail: false,
      });

      appleResponse = postApple('race').then((response) => response);
      await waitForBlockedUserInsert(pool);

      const registration = await request(app.getHttpServer())
        .post('/auth/register')
        .set('X-Forwarded-For', `198.51.100.${nextIp++}`)
        .send({ email: 'race@example.com', password: 'correct horse' })
        .expect(201);
      const winningUserId = accessTokenClaims(
        authBody(registration.body as unknown).accessToken,
      ).sub;

      await blocker.query('COMMIT');
      const apple = await appleResponse;
      expect(apple.status).toBe(409);
      expect(apple.body).toMatchObject({ code: 'ACCOUNT_LINK_REQUIRED' });

      const users = await pool.query<{
        id: string;
        password_hash: string | null;
      }>('SELECT id, password_hash FROM users WHERE email = $1', [
        'race@example.com',
      ]);
      expect(users.rows).toHaveLength(1);
      expect(users.rows[0].id).toBe(winningUserId);
      expect(users.rows[0].password_hash).toMatch(/^scrypt\$/);
      const identities = await pool.query(
        `
          SELECT 1 FROM auth_identities
          WHERE provider_subject = $1 OR user_id = $2
        `,
        ['apple-race-subject', winningUserId],
      );
      expect(identities.rowCount).toBe(0);
    } finally {
      await blocker.query('ROLLBACK').catch(() => undefined);
      blocker.release();
      if (appleResponse) await appleResponse.catch(() => undefined);
      await pool.query(`
        DROP TRIGGER IF EXISTS test_block_apple_user_insert ON users;
        DROP FUNCTION IF EXISTS test_block_apple_user_insert();
      `);
    }
  });

  function postApple(label: string): request.Test {
    const ip = `198.51.100.${nextIp++}`;
    return request(app.getHttpServer())
      .post('/auth/apple')
      .set('X-Forwarded-For', ip)
      .send({
        identityToken: `identity-${label}`,
        authorizationCode: `code-${label}`,
        nonce,
      });
  }

  function postAppleLink(accessToken: string, label: string): request.Test {
    const ip = `198.51.100.${nextIp++}`;
    return request(app.getHttpServer())
      .post('/auth/apple/link')
      .set('Authorization', `Bearer ${accessToken}`)
      .set('X-Forwarded-For', ip)
      .send({
        identityToken: `identity-link-${label}`,
        authorizationCode: `code-link-${label}`,
        nonce,
      });
  }
});

interface AuthResponseBody {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: 900;
}

function authBody(value: unknown): AuthResponseBody {
  if (
    !isRecord(value) ||
    typeof value.accessToken !== 'string' ||
    typeof value.refreshToken !== 'string' ||
    value.tokenType !== 'Bearer' ||
    value.expiresIn !== 900
  ) {
    throw new Error('Expected an authentication response');
  }
  return value as unknown as AuthResponseBody;
}

function accessTokenClaims(token: string): Record<string, unknown> {
  const payload = token.split('.')[1];
  const claims = JSON.parse(
    Buffer.from(payload, 'base64url').toString('utf8'),
  ) as unknown;
  if (!isRecord(claims)) throw new Error('Expected JWT claims');
  return claims;
}

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

function decryptProviderToken(ciphertext: string, identityId: string): string {
  const [version, encodedIv, encodedCiphertext, encodedTag] =
    ciphertext.split('.');
  if (version !== 'v1') throw new Error('Unexpected ciphertext version');
  const decipher = createDecipheriv(
    'aes-256-gcm',
    encryptionKey,
    Buffer.from(encodedIv, 'base64url'),
  );
  decipher.setAAD(Buffer.from(`apple-refresh-token:v1:${identityId}`, 'utf8'));
  decipher.setAuthTag(Buffer.from(encodedTag, 'base64url'));
  return Buffer.concat([
    decipher.update(Buffer.from(encodedCiphertext, 'base64url')),
    decipher.final(),
  ]).toString('utf8');
}

// Exact PID relationship plus the bigint advisory-lock tag, never SQL text matching.
async function waitForAdvisoryWait(
  pool: Pool,
  waiterPid: number,
  blockerPid: number,
  key: string,
  waiterMode = 'ExclusiveLock',
): Promise<void> {
  const deadline = Date.now() + 5_000;
  do {
    const result = await pool.query<{ waiting: boolean }>(
      `
      SELECT EXISTS (
        SELECT 1 FROM pg_locks w
        JOIN pg_locks b ON b.locktype = w.locktype
          AND b.database = w.database AND b.classid = w.classid
          AND b.objid = w.objid AND b.objsubid = w.objsubid
        JOIN pg_stat_activity a ON a.pid = w.pid
        WHERE w.pid = $1 AND b.pid = $2
          AND w.locktype = 'advisory' AND w.objsubid = 1
          AND NOT w.granted AND b.granted
          AND w.mode = $4 AND b.mode = 'ExclusiveLock'
          AND ((w.classid::bigint << 32) | w.objid::bigint) = $3::bigint
          AND a.wait_event_type = 'Lock' AND a.wait_event = 'advisory'
          AND $2::int = ANY(pg_blocking_pids($1))
      ) AS waiting
    `,
      [waiterPid, blockerPid, key, waiterMode],
    );
    if (result.rows[0].waiting) return;
    await new Promise<void>((resolve) => setImmediate(resolve));
  } while (Date.now() < deadline);
  throw new Error(
    `Expected advisory lock ${key}: waiter ${waiterPid} -> blocker ${blockerPid}`,
  );
}

async function waitForBlockedUserInsert(pool: Pool): Promise<void> {
  return waitForBlockedQuery(pool, 'INSERT INTO users');
}

async function waitForBlockedQuery(
  pool: Pool,
  queryFragment: string,
  minimum = 1,
): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const blocked = await pool.query<{ count: number }>(
      `
        SELECT COUNT(*)::int AS count
        FROM pg_stat_activity
        WHERE datname = current_database()
          AND pid <> pg_backend_pid()
          AND wait_event_type = 'Lock'
          AND query LIKE $1
      `,
      [`%${queryFragment}%`],
    );
    if (blocked.rows[0].count >= minimum) return;
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  throw new Error(`Timed out waiting for database barrier: ${queryFragment}`);
}

async function snapshotLinkedState(
  pool: Pool,
  subject: string,
  userId: string,
): Promise<LinkedStateSnapshot> {
  const identity = await pool.query(
    `SELECT id::text, user_id::text, provider, provider_subject,
            provider_email, is_private_email,
            provider_refresh_token_ciphertext AS ciphertext,
            last_provider_validation_at, revoked_at::text,
            created_at::text
     FROM auth_identities WHERE provider_subject = $1 AND user_id = $2`,
    [subject, userId],
  );
  const sessions = await pool.query(
    `SELECT id::text, user_id::text, family_id::text, token_hash,
            COALESCE(auth_identity_id::text, '') AS auth_identity_id,
            expires_at::text, COALESCE(revoked_at::text, '') AS revoked_at,
            created_at::text
     FROM refresh_sessions WHERE user_id = $1 ORDER BY id`,
    [userId],
  );
  return { identity: identity.rows, sessions: sessions.rows };
}

interface LinkedStateSnapshot {
  identity: Array<{
    id: string;
    user_id: string;
    provider: string;
    provider_subject: string;
    provider_email: string | null;
    is_private_email: boolean;
    ciphertext: string | null;
    last_provider_validation_at: Date | null;
    revoked_at: string | null;
    created_at: string;
  }>;
  sessions: Array<{
    id: string;
    user_id: string;
    family_id: string;
    token_hash: string;
    auth_identity_id: string;
    expires_at: string;
    revoked_at: string;
    created_at: string;
  }>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
