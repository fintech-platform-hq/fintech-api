import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { createDecipheriv, createHash } from 'crypto';
import { readFileSync } from 'fs';
import { Pool } from 'pg';
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

async function waitForBlockedUserInsert(pool: Pool): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const blocked = await pool.query<{ count: number }>(
      `
        SELECT COUNT(*)::int AS count
        FROM pg_stat_activity
        WHERE datname = current_database()
          AND pid <> pg_backend_pid()
          AND wait_event_type = 'Lock'
          AND query LIKE '%INSERT INTO users%'
      `,
    );
    if (blocked.rows[0].count > 0) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error('Timed out waiting for the Apple user insert barrier');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
