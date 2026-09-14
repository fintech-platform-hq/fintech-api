import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { createHash, randomUUID } from 'crypto';
import { readFileSync } from 'fs';
import { Pool, PoolClient, QueryResultRow } from 'pg';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from '../src/app.module';
import { DatabaseService } from '../src/common/database/database.service';
import { AppleAuthError } from '../src/modules/auth/apple-auth.errors';
import { AppleRefreshTokenCipherService } from '../src/modules/auth/apple-refresh-token-cipher.service';
import {
  AppleAuthorizationExchange,
  AppleTokenService,
} from '../src/modules/auth/apple-token.service';
import { AuthService } from '../src/modules/auth/auth.service';

const databaseUrl = process.env.TEST_DATABASE_URL;
const describeWithDatabase = databaseUrl ? describe : describe.skip;
const hash = (token: string) =>
  createHash('sha256').update(token).digest('hex');
function barrier() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

describeWithDatabase('Apple refresh (PostgreSQL integration)', () => {
  let app: INestApplication<App>;
  let pool: Pool;
  let db: DatabaseService;
  let auth: AuthService;
  let cipher: AppleRefreshTokenCipherService;
  let nextIp = 1;
  const environment = { ...process.env };
  const validateRefreshToken = jest.fn<Promise<void>, [string, string]>();
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
    process.env.APPLE_REFRESH_TOKEN_ENCRYPTION_KEY = Buffer.alloc(
      32,
      17,
    ).toString('base64url');
    pool = new Pool({ connectionString: databaseUrl });
    const database = await pool.query<{ current_database: string }>(
      'SELECT current_database()',
    );
    if (!database.rows[0].current_database.endsWith('_test'))
      throw new Error('Integration tests require a database ending in _test');
    await pool.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public');
    await pool.query(readFileSync('db.sql', 'utf8'));
    const module = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(AppleTokenService)
      .useValue({ validateRefreshToken, exchangeAuthorizationCode })
      .compile();
    app = module.createNestApplication({ logger: false });
    (
      app.getHttpAdapter().getInstance() as {
        set(key: string, value: unknown): void;
      }
    ).set('trust proxy', 1);
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );
    await app.init();
    db = app.get(DatabaseService);
    auth = app.get(AuthService);
    cipher = app.get(AppleRefreshTokenCipherService);
  });
  beforeEach(() => {
    validateRefreshToken.mockReset().mockResolvedValue();
    exchangeAuthorizationCode.mockReset();
    jest
      .spyOn(global, 'fetch')
      .mockRejectedValue(new Error('Live traffic is forbidden'));
  });
  afterEach(() => jest.restoreAllMocks());
  afterAll(async () => {
    await app?.close();
    await pool?.end();
    process.env = environment;
  });

  async function fixture() {
    const userId = randomUUID(),
      identityId = randomUUID(),
      subject = randomUUID();
    await pool.query(
      'INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)',
      [userId, `${userId}@example.test`, 'fixture-password-hash'],
    );
    await pool.query(
      `INSERT INTO auth_identities (id, user_id, provider, provider_subject, provider_refresh_token_ciphertext, last_provider_validation_at)
      VALUES ($1, $2, 'apple', $3, $4, clock_timestamp() - interval '25 hours')`,
      [
        identityId,
        userId,
        subject,
        cipher.encrypt('provider-token-sentinel', identityId),
      ],
    );
    return {
      userId,
      identityId,
      subject,
      token: await session(userId, identityId),
    };
  }
  async function session(
    userId: string,
    identityId: string | null,
    familyId = randomUUID(),
  ) {
    const token = randomUUID();
    await pool.query(
      `INSERT INTO refresh_sessions (id, user_id, auth_identity_id, family_id, token_hash, expires_at)
      VALUES ($1, $2, $3, $4, $5, clock_timestamp() + interval '30 days')`,
      [randomUUID(), userId, identityId, familyId, hash(token)],
    );
    return token;
  }
  function refresh(token: string) {
    return request(app.getHttpServer())
      .post('/auth/refresh')
      .set('X-Forwarded-For', `10.33.0.${nextIp++}`)
      .send({ refreshToken: token });
  }
  async function identityState(id: string) {
    return (
      await pool.query<{
        revoked_at: Date | null;
        last_provider_validation_at: Date | null;
      }>(
        'SELECT revoked_at, last_provider_validation_at FROM auth_identities WHERE id = $1',
        [id],
      )
    ).rows[0];
  }
  async function sessions(userId: string) {
    return (
      await pool.query<{
        token_hash: string;
        revoked_at: Date | null;
        family_id: string;
        auth_identity_id: string | null;
      }>(
        'SELECT token_hash, revoked_at, family_id, auth_identity_id FROM refresh_sessions WHERE user_id = $1 ORDER BY id',
        [userId],
      )
    ).rows;
  }
  async function financialSnapshot() {
    const snapshots: unknown[] = [];
    for (const table of ['users', 'accounts', 'categories', 'transactions']) {
      snapshots.push(
        (
          await pool.query<{ row: unknown }>(
            `SELECT to_jsonb(t) AS row FROM ${table} t ORDER BY id`,
          )
        ).rows,
      );
    }
    return snapshots;
  }
  async function trackedClient() {
    const client = await pool.connect();
    const pid = (
      await client.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')
    ).rows[0].pid;
    const statements: string[] = [];
    const release = jest.fn(() => client.release());
    const wrapped = {
      query: <T extends QueryResultRow>(sql: string, values?: unknown[]) => {
        statements.push(sql);
        return client.query<T>(sql, values);
      },
      release,
    } as unknown as PoolClient;
    return { client, wrapped, pid, statements, release };
  }
  async function waitForBlock(waiter: number, blocker: number) {
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline) {
      const result = await pool.query<{ blocked: boolean }>(
        'SELECT $2::int = ANY(pg_blocking_pids($1)) AS blocked',
        [waiter, blocker],
      );
      if (result.rows[0].blocked) return;
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    throw new Error('Expected PostgreSQL lock dependency was not observed');
  }

  it('commits selective revocation, preserves financial data and unrelated usable sessions, and reactivation does not revive old sessions', async () => {
    const f = await fixture(),
      other = await fixture();
    const secondApple = await session(f.userId, f.identityId),
      password = await session(f.userId, null);
    const accountId = randomUUID(),
      categoryId = randomUUID();
    await pool.query(
      "INSERT INTO accounts (id, user_id, name, currency) VALUES ($1, $2, 'fixture', 'BRL')",
      [accountId, f.userId],
    );
    await pool.query(
      "INSERT INTO categories (id, user_id, name) VALUES ($1, $2, 'fixture')",
      [categoryId, f.userId],
    );
    await pool.query(
      `INSERT INTO transactions (id, user_id, account_id, category_id, type, amount_minor, currency, occurred_at)
      VALUES ($1, $2, $3, $4, 'expense', 100, 'BRL', clock_timestamp())`,
      [randomUUID(), f.userId, accountId, categoryId],
    );
    const before = await financialSnapshot(),
      identityBefore = await identityState(f.identityId),
      otherBefore = await sessions(other.userId);
    validateRefreshToken.mockRejectedValueOnce(
      new AppleAuthError('APPLE_REFRESH_TOKEN_REJECTED', 'provider-secret'),
    );
    expect((await refresh(f.token).expect(401)).body).toEqual({
      statusCode: 401,
      message: 'Invalid refresh token',
      error: 'Unauthorized',
    });
    const revoked = await identityState(f.identityId);
    expect(revoked.revoked_at).toBeInstanceOf(Date);
    expect(revoked.last_provider_validation_at).toEqual(
      identityBefore.last_provider_validation_at,
    );
    const rows = await sessions(f.userId);
    expect(
      rows.filter((row) => row.auth_identity_id === f.identityId),
    ).toHaveLength(2);
    expect(
      rows
        .filter((row) => row.auth_identity_id === f.identityId)
        .every((row) => row.revoked_at !== null),
    ).toBe(true);
    expect(
      rows.find((row) => row.auth_identity_id === null)?.revoked_at,
    ).toBeNull();
    expect(await sessions(other.userId)).toEqual(otherBefore);
    expect((await identityState(other.identityId)).revoked_at).toBeNull();
    expect(await financialSnapshot()).toEqual(before);
    await refresh(password).expect(200);
    await refresh(other.token).expect(200);
    exchangeAuthorizationCode.mockResolvedValue({
      subject: f.subject,
      refreshToken: 'new-provider-token',
      isPrivateEmail: false,
    });
    const login = await request(app.getHttpServer())
      .post('/auth/apple')
      .send({
        identityToken: 'identity',
        authorizationCode: 'code',
        nonce: 'n'.repeat(43),
      })
      .expect(200);
    expect((await identityState(f.identityId)).revoked_at).toBeNull();
    expect(
      (await sessions(f.userId))
        .filter((row) =>
          [hash(f.token), hash(secondApple)].includes(row.token_hash),
        )
        .every((row) => row.revoked_at !== null),
    ).toBe(true);
    await refresh(secondApple).expect(401);
    await refresh((login.body as { refreshToken: string }).refreshToken).expect(
      200,
    );
  });

  it.each(['fresh', 'boundary', 'null'] as const)(
    'uses PostgreSQL for the 24h decision (%s) and records success after validation',
    async (state) => {
      const f = await fixture();
      await pool.query(
        `UPDATE auth_identities SET last_provider_validation_at = CASE $2::text
      WHEN 'fresh' THEN clock_timestamp() - interval '23 hours 59 minutes'
      WHEN 'boundary' THEN clock_timestamp() - interval '24 hours' ELSE NULL END WHERE id = $1`,
        [f.identityId, state],
      );
      const before = await identityState(f.identityId);
      let validationFinishedAt: string | undefined;
      validateRefreshToken.mockImplementation(async () => {
        validationFinishedAt = (
          await pool.query<{ at: string }>(
            'SELECT clock_timestamp()::text AS at',
          )
        ).rows[0].at;
      });
      await refresh(f.token).expect(200);
      const after = await identityState(f.identityId);
      expect(validateRefreshToken).toHaveBeenCalledTimes(
        state === 'fresh' ? 0 : 1,
      );
      if (state === 'fresh') expect(after).toEqual(before);
      else {
        const persisted = await pool.query<{ after_validation: boolean }>(
          'SELECT last_provider_validation_at >= $2::timestamptz AS after_validation FROM auth_identities WHERE id = $1',
          [f.identityId, validationFinishedAt],
        );
        expect(persisted.rows[0].after_validation).toBe(true);
        if (before.last_provider_validation_at)
          expect(after.last_provider_validation_at!.getTime()).toBeGreaterThan(
            before.last_provider_validation_at.getTime(),
          );
      }
    },
  );

  it('keeps the same original refresh usable after 503 and retries only after backoff expires', async () => {
    const f = await fixture(),
      before = await sessions(f.userId),
      identityBefore = await identityState(f.identityId);
    const clock = jest.spyOn(Date, 'now').mockReturnValue(Date.now());
    validateRefreshToken.mockRejectedValueOnce(
      new AppleAuthError(
        'APPLE_TOKEN_API_UNAVAILABLE',
        'secret-network-detail',
      ),
    );
    const response = await refresh(f.token).expect(503);
    expect(JSON.stringify(response.body)).not.toMatch(
      /secret|provider-token|ciphertext/,
    );
    expect(await sessions(f.userId)).toEqual(before);
    expect(await identityState(f.identityId)).toEqual(identityBefore);
    await refresh(f.token).expect(503);
    expect(validateRefreshToken).toHaveBeenCalledTimes(1);
    clock.mockReturnValue(Date.now() + 60000);
    await refresh(f.token).expect(200);
    expect(validateRefreshToken).toHaveBeenCalledTimes(2);
    expect(
      (await sessions(f.userId)).filter((row) => row.revoked_at === null),
    ).toHaveLength(1);
  });

  it.each([false, true])(
    'serializes two sessions of the same identity, including temporary failure backoff (failure=%s)',
    async (failure) => {
      const f = await fixture(),
        secondToken = await session(f.userId, f.identityId);
      const first = await trackedClient(),
        second = await trackedClient();
      const entered = barrier(),
        resume = barrier();
      jest
        .spyOn(db, 'getClient')
        .mockResolvedValueOnce(first.wrapped)
        .mockResolvedValueOnce(second.wrapped);
      validateRefreshToken.mockImplementation(async () => {
        entered.resolve();
        await resume.promise;
        if (failure)
          throw new AppleAuthError(
            'APPLE_TOKEN_API_UNAVAILABLE',
            'unavailable',
          );
      });
      const pending: Promise<unknown>[] = [];
      try {
        pending.push(auth.refresh(f.token).catch((error: unknown) => error));
        await entered.promise;
        pending.push(
          auth.refresh(secondToken).catch((error: unknown) => error),
        );
        await waitForBlock(second.pid, first.pid);
        expect(validateRefreshToken).toHaveBeenCalledTimes(1);
        resume.resolve();
        const results = await Promise.all(pending);
        for (const result of results)
          expect(result).toMatchObject(
            failure ? { status: 503 } : { expiresIn: 900 },
          );
        expect(validateRefreshToken).toHaveBeenCalledTimes(1);
        expect(
          (await sessions(f.userId)).filter((row) => row.revoked_at === null),
        ).toHaveLength(2);
      } finally {
        resume.resolve();
        await Promise.allSettled(pending);
        if (!first.release.mock.calls.length) first.client.release();
        if (!second.release.mock.calls.length) second.client.release();
      }
    },
  );

  it('rolls back validation timestamp and rotation if successor insertion fails', async () => {
    const f = await fixture(),
      before = await sessions(f.userId),
      identityBefore = await identityState(f.identityId);
    await pool.query(`CREATE FUNCTION cp6_fail_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'postgres-secret-detail'; END $$;
      CREATE TRIGGER cp6_fail_insert BEFORE INSERT ON refresh_sessions FOR EACH ROW EXECUTE FUNCTION cp6_fail_insert()`);
    try {
      expect((await refresh(f.token).expect(500)).body).toEqual({
        statusCode: 500,
        message: 'Internal Server Error',
      });
      expect(await sessions(f.userId)).toEqual(before);
      expect(await identityState(f.identityId)).toEqual(identityBefore);
    } finally {
      await pool.query(
        'DROP TRIGGER cp6_fail_insert ON refresh_sessions; DROP FUNCTION cp6_fail_insert()',
      );
    }
    await refresh(f.token).expect(200);
    expect(validateRefreshToken).toHaveBeenCalledTimes(2);
  });

  it('rolls back a real deferred COMMIT failure during invalid_grant and releases a clean connection without a false 401', async () => {
    const f = await fixture(),
      before = await sessions(f.userId),
      identityBefore = await identityState(f.identityId);
    const tracked = await trackedClient();
    jest.spyOn(db, 'getClient').mockResolvedValueOnce(tracked.wrapped);
    validateRefreshToken.mockRejectedValueOnce(
      new AppleAuthError('APPLE_REFRESH_TOKEN_REJECTED', 'invalid_grant'),
    );
    await pool.query(`CREATE FUNCTION cp6_fail_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'postgres-secret-commit-detail'; END $$;
      CREATE CONSTRAINT TRIGGER cp6_fail_commit AFTER UPDATE ON auth_identities DEFERRABLE INITIALLY DEFERRED
      FOR EACH ROW EXECUTE FUNCTION cp6_fail_commit()`);
    try {
      expect((await refresh(f.token).expect(500)).body).toEqual({
        statusCode: 500,
        message: 'Internal Server Error',
      });
      expect(tracked.statements.slice(-2)).toEqual(['COMMIT', 'ROLLBACK']);
      expect(tracked.release).toHaveBeenCalledTimes(1);
      const activity = await db.query<{
        state: string;
        xact_start: Date | null;
      }>('SELECT state, xact_start FROM pg_stat_activity WHERE pid = $1', [
        tracked.pid,
      ]);
      expect(activity.rows[0]).toEqual({ state: 'idle', xact_start: null });
      expect(await sessions(f.userId)).toEqual(before);
      expect(await identityState(f.identityId)).toEqual(identityBefore);
    } finally {
      await pool.query(
        'DROP TRIGGER cp6_fail_commit ON auth_identities; DROP FUNCTION cp6_fail_commit()',
      );
      if (!tracked.release.mock.calls.length) tracked.client.release();
    }
    await refresh(f.token).expect(200);
  });

  it('preserves reuse-family revocation when reuse races with an Apple successor rotation', async () => {
    const f = await fixture();
    const rotated = await auth.refresh(f.token);
    await pool.query(
      "UPDATE auth_identities SET last_provider_validation_at = clock_timestamp() - interval '25 hours' WHERE id = $1",
      [f.identityId],
    );
    const first = await trackedClient(),
      second = await trackedClient(),
      entered = barrier(),
      resume = barrier();
    jest
      .spyOn(db, 'getClient')
      .mockResolvedValueOnce(first.wrapped)
      .mockResolvedValueOnce(second.wrapped);
    validateRefreshToken.mockImplementation(async () => {
      entered.resolve();
      await resume.promise;
    });
    const pending: Promise<unknown>[] = [];
    try {
      pending.push(
        auth.refresh(rotated.refreshToken).catch((error: unknown) => error),
      );
      await entered.promise;
      pending.push(auth.refresh(f.token).catch((error: unknown) => error));
      await waitForBlock(second.pid, first.pid);
      resume.resolve();
      const [success, reused] = await Promise.all(pending);
      expect(success).toMatchObject({ expiresIn: 900 });
      expect(reused).toMatchObject({ status: 401 });
      expect(
        (await sessions(f.userId)).every((row) => row.revoked_at !== null),
      ).toBe(true);
      expect((await identityState(f.identityId)).revoked_at).toBeNull();
      expect(validateRefreshToken).toHaveBeenCalledTimes(2);
    } finally {
      resume.resolve();
      await Promise.allSettled(pending);
      if (!first.release.mock.calls.length) first.client.release();
      if (!second.release.mock.calls.length) second.client.release();
    }
  });
});
