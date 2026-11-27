import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { createHash, createHmac, randomUUID } from 'crypto';
import { readFileSync } from 'fs';
import type { NextFunction, Request, Response } from 'express';
import { Pool } from 'pg';
import request from 'supertest';
import type { App } from 'supertest/types';
import { AppModule } from '../src/app.module';
import { AppleTokenService } from '../src/modules/auth/apple-token.service';
import { AppleAuthError } from '../src/modules/auth/apple-auth.errors';
import { IdentityEmailDelivery } from '../src/modules/auth/identity-email-delivery';
import type { EmailPurpose } from '../src/modules/auth/identity-email-delivery';
import type { AuthResponse } from '../src/modules/auth/auth.types';

const databaseUrl = process.env.TEST_DATABASE_URL;
const describeDatabase = databaseUrl ? describe : describe.skip;
const secret = 'identity-v1-integration-synthetic-secret';
const originalPassword = 'synthetic original password';
const newPassword = 'synthetic replacement password';
const appleBody = (subject: string) => ({
  identityToken: subject,
  authorizationCode: 'synthetic-code',
  nonce: 'A'.repeat(43),
});

describeDatabase('Identity V1 HTTP and PostgreSQL', () => {
  let app: INestApplication<App>;
  let pool: Pool;
  const inbox = new Map<string, string>();
  let ip = 0;
  const deliver = jest.fn(
    (email: string, purpose: EmailPurpose, code: string) => {
      inbox.set(`${email}:${purpose}`, code);
    },
  );
  const exchange = jest.fn((subject: string) => ({
    subject,
    refreshToken: 'synthetic-apple-refresh',
    isPrivateEmail: false,
  }));
  const validate = jest.fn();

  beforeAll(async () => {
    process.env.DATABASE_URL = databaseUrl;
    process.env.JWT_ACCESS_SECRET = secret;
    process.env.JWT_ISSUER = 'identity-v1-test';
    process.env.JWT_AUDIENCE = 'identity-v1-test';
    process.env.APPLE_REFRESH_TOKEN_ENCRYPTION_KEY = Buffer.alloc(
      32,
      42,
    ).toString('base64url');
    pool = new Pool({ connectionString: databaseUrl });
    const db = await pool.query<{ name: string }>(
      'SELECT current_database() AS name',
    );
    if (!db.rows[0].name.endsWith('_test'))
      throw new Error('Expected disposable _test database');
    await pool.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public');
    await pool.query(readFileSync('db.sql', 'utf8'));
    const module = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(IdentityEmailDelivery)
      .useValue({ assertAvailable: () => undefined, deliver })
      .overrideProvider(AppleTokenService)
      .useValue({
        exchangeAuthorizationCode: exchange,
        validateRefreshToken: validate,
      })
      .compile();
    app = module.createNestApplication({ logger: false });
    (
      app.getHttpAdapter().getInstance() as {
        set(key: string, value: number): void;
      }
    ).set('trust proxy', 1);
    app.use((req: Request, res: Response<unknown>, next: NextFunction) => {
      if (req.get('X-Lenver-Test-Discard-Response') === '1') {
        const send = res.send.bind(res) as typeof res.send;
        res.send = (body?: unknown) => {
          if (res.statusCode === 204) return res.destroy();
          return send(body);
        };
      }
      next();
    });
    app.useGlobalPipes(
      new ValidationPipe({
        transform: true,
        whitelist: true,
        forbidNonWhitelisted: true,
      }),
    );
    await app.init();
  });

  afterAll(async () => {
    await app?.close();
    await pool?.end();
  });

  function post(path: string, body: object, access?: string) {
    const http = request(app.getHttpServer())
      .post(path)
      .set('X-Forwarded-For', `192.0.2.${++ip}`);
    if (access) http.set('Authorization', `Bearer ${access}`);
    return http.send(body);
  }

  function get(path: string, access: string) {
    return request(app.getHttpServer())
      .get(path)
      .set('Authorization', `Bearer ${access}`);
  }

  function claims(token: string) {
    return JSON.parse(
      Buffer.from(token.split('.')[1], 'base64url').toString('utf8'),
    ) as {
      sub: string;
      sid: string;
      iat: number;
      exp: number;
    };
  }

  async function register(verified = false) {
    const email = `${randomUUID()}@example.test`;
    const body = (
      await post('/v1/auth/register', {
        email,
        password: originalPassword,
      }).expect(201)
    ).body as AuthResponse;
    const { sub, sid } = claims(body.accessToken);
    if (verified) await verify(email, body.accessToken);
    return { ...body, email, sub, sid };
  }

  async function verify(email: string, access: string) {
    await post('/v1/auth/verification', {}, access).expect(202);
    await post(
      '/v1/auth/verification/confirm',
      { code: code(email, 'verify') },
      access,
    ).expect(204);
  }

  function code(email: string, purpose: EmailPurpose) {
    const value = inbox.get(`${email}:${purpose}`);
    if (!value) throw new Error('Synthetic delivery missing');
    return value;
  }

  function account(access: string) {
    return post(
      '/accounts',
      { name: 'Synthetic account', currency: 'BRL' },
      access,
    );
  }

  async function accounts(userId: string) {
    return (
      await pool.query<{ id: string }>(
        'SELECT id FROM accounts WHERE user_id = $1 ORDER BY id',
        [userId],
      )
    ).rows;
  }

  type FinancialSnapshot = {
    accounts: number;
    transactions: number;
    idempotencyKeys: number;
    mvpAccounts: number;
    mvpAccountsState: {
      accountId: string;
      revision: string;
      baseMinor: string;
      coverageStart: string;
      referenceZone: string;
      baseSuspended: boolean;
    }[];
    balanceChecks: number;
    recoveries: number;
    movementVersions: number;
    checkReplacements: number;
    baseVersions: number;
  };
  type FinancialTable =
    | 'accounts'
    | 'transactions'
    | 'mvp_balance_checks'
    | 'mvp_expense_recoveries'
    | 'mvp_movement_versions'
    | 'mvp_base_versions';
  type FinancialCount = Exclude<keyof FinancialSnapshot, 'mvpAccountsState'>;
  type FinancialWriter = {
    barrierTable: FinancialTable;
    effects: FinancialCount[];
    run: () => Promise<number>;
  };
  type WriterFactory = [
    string,
    (accessToken: string) => Promise<FinancialWriter>,
  ];

  async function financialSnapshot(userId: string): Promise<FinancialSnapshot> {
    const { rows } = await pool.query<FinancialSnapshot>(
      `SELECT
        (SELECT count(*)::int FROM accounts WHERE user_id = $1) AS accounts,
        (SELECT count(*)::int FROM transactions WHERE user_id = $1) AS transactions,
        (SELECT count(*)::int FROM idempotency_keys WHERE user_id = $1) AS "idempotencyKeys",
        (SELECT count(*)::int FROM mvp_accounts WHERE user_id = $1) AS "mvpAccounts",
        COALESCE((
          SELECT jsonb_agg(jsonb_build_object(
            'accountId', account_id::text,
            'revision', revision::text,
            'baseMinor', base_minor::text,
            'coverageStart', coverage_start::text,
            'referenceZone', reference_zone,
            'baseSuspended', base_suspended
          ) ORDER BY account_id)
          FROM mvp_accounts WHERE user_id = $1
        ), '[]'::jsonb) AS "mvpAccountsState",
        (SELECT count(*)::int FROM mvp_balance_checks WHERE user_id = $1) AS "balanceChecks",
        (SELECT count(*)::int FROM mvp_expense_recoveries WHERE user_id = $1) AS recoveries,
        (SELECT count(*)::int FROM mvp_movement_versions WHERE user_id = $1) AS "movementVersions",
        (SELECT count(*)::int FROM mvp_check_replacements WHERE user_id = $1) AS "checkReplacements",
        (SELECT count(*)::int FROM mvp_base_versions WHERE user_id = $1) AS "baseVersions"`,
      [userId],
    );
    return rows[0];
  }

  async function createMvpAccount(accessToken: string) {
    const response = await post(
      '/mvp/account',
      {
        baseMinor: '90000',
        coverageStart: '2026-11-14T12:00:00Z',
        referenceZone: 'America/Sao_Paulo',
      },
      accessToken,
    )
      .set('Idempotency-Key', randomUUID())
      .expect(201);
    return (response.body as { account: { id: string } }).account.id;
  }

  async function createMvpMovement(
    accessToken: string,
    accountId: string,
    expectedRevision: string,
    amountMinor: number,
    occurredAt: string,
  ) {
    const response = await post(
      '/mvp/transactions',
      {
        accountId,
        type: 'expense',
        amountMinor,
        currency: 'BRL',
        occurredAt,
        clientMutationId: randomUUID(),
        expectedRevision,
      },
      accessToken,
    )
      .set('Idempotency-Key', randomUUID())
      .expect(201);
    return response.body as { id: string };
  }

  async function createMvpCheck(
    accessToken: string,
    accountId: string,
    expectedRevision: string,
    observedMinor: string,
    referenceAt: string,
  ) {
    const response = await post(
      '/mvp/checks',
      { accountId, expectedRevision, observedMinor, referenceAt },
      accessToken,
    )
      .set('Idempotency-Key', randomUUID())
      .expect(201);
    return response.body as { id: string };
  }

  async function recoveryFixture(accessToken: string) {
    const accountId = await createMvpAccount(accessToken);
    const original = await createMvpMovement(
      accessToken,
      accountId,
      '1',
      5500,
      '2026-11-14T12:00:00Z',
    );
    const check = await createMvpCheck(
      accessToken,
      accountId,
      '2',
      '80000',
      '2026-11-18T12:00:00Z',
    );
    await createMvpMovement(
      accessToken,
      accountId,
      '3',
      1800,
      '2026-11-18T12:10:00Z',
    );
    return { accountId, originalId: original.id, checkId: check.id };
  }

  async function auditConfirmation(accessToken: string, input: object) {
    const response = await post(
      '/mvp/audit-previews',
      input,
      accessToken,
    ).expect(200);
    const preview = response.body as {
      revision: string;
      previewToken: string;
    };
    return {
      ...input,
      expectedRevision: preview.revision,
      previewToken: preview.previewToken,
      confirmed: true,
    };
  }

  const writerFactories: WriterFactory[] = [
    [
      'legacy account creation',
      (accessToken) =>
        Promise.resolve({
          barrierTable: 'accounts',
          effects: ['accounts'],
          run: () => account(accessToken).then(({ status }) => status),
        }),
    ],
    [
      'legacy transaction creation',
      async (accessToken) => {
        const accountId = (
          (await account(accessToken).expect(201)).body as { id: string }
        ).id;
        const key = randomUUID();
        return {
          barrierTable: 'transactions',
          effects: ['transactions', 'idempotencyKeys'],
          run: () =>
            post(
              '/transactions',
              {
                accountId,
                type: 'expense',
                amountMinor: 20,
                currency: 'BRL',
                occurredAt: '2026-11-26T10:00:00Z',
                clientMutationId: randomUUID(),
              },
              accessToken,
            )
              .set('Idempotency-Key', key)
              .then(({ status }) => status),
        };
      },
    ],
    [
      'MVP account opening',
      (accessToken) => {
        const key = randomUUID();
        return Promise.resolve({
          barrierTable: 'accounts',
          effects: [
            'accounts',
            'mvpAccounts',
            'idempotencyKeys',
            'baseVersions',
          ],
          run: () =>
            post(
              '/mvp/account',
              {
                baseMinor: '90000',
                coverageStart: '2026-11-14T12:00:00Z',
                referenceZone: 'America/Sao_Paulo',
              },
              accessToken,
            )
              .set('Idempotency-Key', key)
              .then(({ status }) => status),
        });
      },
    ],
    [
      'MVP movement registration',
      async (accessToken) => {
        const accountId = await createMvpAccount(accessToken);
        const key = randomUUID();
        return {
          barrierTable: 'transactions',
          effects: ['transactions', 'idempotencyKeys'],
          run: () =>
            post(
              '/mvp/transactions',
              {
                accountId,
                type: 'expense',
                amountMinor: 20,
                currency: 'BRL',
                occurredAt: '2026-11-15T10:00:00Z',
                clientMutationId: randomUUID(),
                expectedRevision: '1',
              },
              accessToken,
            )
              .set('Idempotency-Key', key)
              .then(({ status }) => status),
        };
      },
    ],
    [
      'balance check confirmation',
      async (accessToken) => {
        const accountId = await createMvpAccount(accessToken);
        const key = randomUUID();
        return {
          barrierTable: 'mvp_balance_checks',
          effects: ['balanceChecks', 'idempotencyKeys'],
          run: () =>
            post(
              '/mvp/checks',
              {
                accountId,
                observedMinor: '90000',
                referenceAt: '2026-11-14T13:00:00Z',
                expectedRevision: '1',
              },
              accessToken,
            )
              .set('Idempotency-Key', key)
              .then(({ status }) => status),
        };
      },
    ],
    [
      'forgotten expense recovery',
      async (accessToken) => {
        const { accountId, checkId } = await recoveryFixture(accessToken);
        const key = randomUUID();
        return {
          barrierTable: 'mvp_expense_recoveries',
          effects: ['transactions', 'recoveries', 'idempotencyKeys'],
          run: () =>
            post(
              '/mvp/recoveries',
              {
                accountId,
                checkId,
                amountMinor: '2500',
                day: '2026-11-15',
                occurredAt: '2026-11-15T15:00:00Z',
                description: 'Synthetic forgotten expense',
                expectedRevision: '4',
                action: 'create',
                evidence: 'Synthetic evidence',
              },
              accessToken,
            )
              .set('Idempotency-Key', key)
              .then(({ status }) => status),
        };
      },
    ],
    [
      'audited movement correction',
      async (accessToken) => {
        const accountId = await createMvpAccount(accessToken);
        const movement = await createMvpMovement(
          accessToken,
          accountId,
          '1',
          5500,
          '2026-11-15T12:00:00Z',
        );
        const input = await auditConfirmation(accessToken, {
          accountId,
          targetId: movement.id,
          action: 'correct',
          reason: 'Synthetic correction',
          amountMinor: '5400',
        });
        const key = randomUUID();
        return {
          barrierTable: 'mvp_movement_versions',
          effects: ['movementVersions', 'idempotencyKeys'],
          run: () =>
            post('/mvp/audited-changes', input, accessToken)
              .set('Idempotency-Key', key)
              .then(({ status }) => status),
        };
      },
    ],
  ];

  async function waitForHolderLocks(expected = 1) {
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline) {
      const result = await pool.query<{ waiting: string }>(
        `SELECT count(*)::text AS waiting FROM pg_stat_activity
         WHERE datname = current_database() AND wait_event_type = 'Lock'
           AND query LIKE 'SELECT id FROM users WHERE id = %FOR UPDATE'`,
      );
      if (Number(result.rows[0].waiting) >= expected) return;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    throw new Error(`Expected ${expected} requests to wait for the holder`);
  }

  async function waitForFinancialInsert(table: string) {
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline) {
      const result = await pool.query<{ waiting: boolean }>(
        `SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname = current_database()
           AND wait_event = 'advisory' AND query ILIKE $1) AS waiting`,
        [`%INSERT INTO ${table}%`],
      );
      if (result.rows[0].waiting) return;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    throw new Error(`Financial writer did not reach the ${table} barrier`);
  }

  async function installFinancialBarrier(table: FinancialTable) {
    await pool.query(`
      CREATE FUNCTION identity_fixture_pause_financial_write() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN PERFORM pg_advisory_xact_lock(10101); RETURN NEW; END $$;
      CREATE TRIGGER identity_fixture_pause_financial_write BEFORE INSERT ON ${table}
      FOR EACH ROW EXECUTE FUNCTION identity_fixture_pause_financial_write()
    `);
  }

  async function removeFinancialBarrier(table: FinancialTable) {
    await pool.query(`
      DROP TRIGGER IF EXISTS identity_fixture_pause_financial_write ON ${table};
      DROP FUNCTION IF EXISTS identity_fixture_pause_financial_write()
    `);
  }

  it('restricts both financial API generations, verifies once, and preserves owner isolation', async () => {
    const a = await register();
    const b = await register();
    await get('/v1/auth/session', a.accessToken)
      .expect(200)
      .expect(({ body }) => {
        expect(body).toMatchObject({
          financialAccess: false,
          passwordVerified: false,
        });
      });
    await get('/accounts', a.accessToken).expect(403);
    await get('/mvp/account', a.accessToken).expect(403);
    await account(a.accessToken).expect(403);
    await post('/transactions', {}, a.accessToken).expect(403);
    expect(await accounts(a.sub)).toEqual([]);
    await post('/v1/auth/verification', {}, a.accessToken).expect(202);
    const value = code(a.email, 'verify');
    await post(
      '/v1/auth/verification/confirm',
      { code: value },
      b.accessToken,
    ).expect(400);
    const races = await Promise.all(
      [1, 2].map(() =>
        post('/v1/auth/verification/confirm', { code: value }, a.accessToken),
      ),
    );
    expect(races.map(({ status }) => status).sort()).toEqual([204, 400]);
    await account(a.accessToken).expect(201);
    await verify(b.email, b.accessToken);
    await get('/accounts', b.accessToken).expect(200, []);
    expect(await accounts(a.sub)).toHaveLength(1);
  });

  it('expires and caps verification attempts across resends', async () => {
    const a = await register();
    await post('/v1/auth/verification', {}, a.accessToken).expect(202);
    const value = code(a.email, 'verify');
    const wrong = value === '000000' ? '111111' : '000000';
    for (let i = 0; i < 5; i++) {
      await post(
        '/v1/auth/verification/confirm',
        { code: wrong },
        a.accessToken,
      ).expect(400);
    }
    await post(
      '/v1/auth/verification/confirm',
      { code: value },
      a.accessToken,
    ).expect(400);
    await pool.query(
      "UPDATE identity_email_proofs SET expires_at = now() - interval '1 minute' WHERE user_id = $1",
      [a.sub],
    );
    await post(
      '/v1/auth/verification/confirm',
      { code: value },
      a.accessToken,
    ).expect(400);
    await verify(a.email, a.accessToken);
  });

  it('invalidates an issued proof when the pending address changes', async () => {
    const a = await register();
    await post('/v1/auth/verification', {}, a.accessToken).expect(202);
    const first = code(a.email, 'verify');
    const anotherEmail = `${randomUUID()}@example.test`;
    await post(
      '/v1/auth/verification/email',
      { email: anotherEmail, password: originalPassword },
      a.accessToken,
    ).expect(204);
    await post(
      '/v1/auth/verification/email',
      { email: a.email, password: originalPassword },
      a.accessToken,
    ).expect(204);
    await post(
      '/v1/auth/verification/confirm',
      { code: first },
      a.accessToken,
    ).expect(400);
    await get('/accounts', a.accessToken).expect(403);
  });

  it('recovers only verified passwords, with neutral responses and single-use proof', async () => {
    const a = await register(true);
    const pending = await register();
    const missing = 'unknown@example.test';
    for (const email of [a.email, pending.email, missing]) {
      await post('/v1/auth/recovery', { email }).expect(202).expect('');
    }
    expect(inbox.has(`${missing}:recover`)).toBe(false);
    expect(inbox.has(`${pending.email}:recover`)).toBe(false);
    const payload = {
      email: a.email,
      code: code(a.email, 'recover'),
      newPassword,
    };
    await post('/v1/auth/recovery/confirm', payload).expect(204);
    await post('/v1/auth/recovery/confirm', payload).expect(400);
    await get('/accounts', a.accessToken).expect(401);
    await post('/v1/auth/login', {
      email: a.email,
      password: originalPassword,
    }).expect(401);
    const login = (
      await post('/v1/auth/login', {
        email: a.email,
        password: newPassword,
      }).expect(200)
    ).body as AuthResponse;
    expect(claims(login.accessToken).sub).toBe(a.sub);
  });

  it('binds password change proof and pure outcome to act and family', async () => {
    const a = await register(true);
    const otherFamily = (
      await post('/v1/auth/login', {
        email: a.email,
        password: originalPassword,
      }).expect(200)
    ).body as AuthResponse;
    const operationId = randomUUID();
    const { proof } = (
      await post(
        '/v1/auth/password/change/proof',
        { password: originalPassword, operationId },
        a.accessToken,
      ).expect(200)
    ).body as { proof: string };
    const outcome = `/v1/auth/password/change/${operationId}`;
    await get(outcome, a.accessToken).expect(200, { status: 'unknown' });
    await post(
      '/v1/auth/password/change',
      { proof, operationId: randomUUID(), newPassword },
      a.accessToken,
    ).expect(400);
    await post(
      '/v1/auth/password/change',
      { proof, operationId, newPassword },
      otherFamily.accessToken,
    ).expect(400);
    await post(
      '/v1/auth/password/change',
      { proof, operationId, newPassword },
      a.accessToken,
    ).expect(204);
    const before = await pool.query(
      'SELECT * FROM identity_password_changes WHERE user_id = $1',
      [a.sub],
    );
    await get(outcome, a.accessToken).expect(200, { status: 'committed' });
    await get(outcome, a.accessToken).expect(200, { status: 'committed' });
    expect(
      (
        await pool.query(
          'SELECT * FROM identity_password_changes WHERE user_id = $1',
          [a.sub],
        )
      ).rows,
    ).toEqual(before.rows);
    await post(
      '/v1/auth/password/change',
      { proof, operationId, newPassword },
      a.accessToken,
    ).expect(400);
    await get(outcome, otherFamily.accessToken).expect(401);
    await get('/accounts', a.accessToken).expect(200);
  });

  it('keeps the original family ceiling, rejects idle and legacy sessions, and logs out rotated families', async () => {
    const a = await register(true);
    const interval = claims(a.accessToken);
    expect(interval.exp - interval.iat).toBe(900);
    const current = async () =>
      (
        await pool.query<{ family_expires_at: Date }>(
          'SELECT family_expires_at FROM refresh_sessions WHERE family_id = $1 AND revoked_at IS NULL',
          [a.sid],
        )
      ).rows[0]?.family_expires_at;
    const ceiling = await current();
    const rotated = (
      await post('/v1/auth/refresh', { refreshToken: a.refreshToken }).expect(
        200,
      )
    ).body as AuthResponse;
    expect(await current()).toEqual(ceiling);
    expect(claims(rotated.accessToken).sid).toBe(a.sid);
    await post('/v1/auth/logout', { refreshToken: a.refreshToken }).expect(204);
    await get('/accounts', rotated.accessToken).expect(401);
    await post('/v1/auth/refresh', {
      refreshToken: rotated.refreshToken,
    }).expect(401);

    const issue = async () =>
      (
        await post('/v1/auth/login', {
          email: a.email,
          password: originalPassword,
        }).expect(200)
      ).body as AuthResponse;
    const idle = await issue();
    await pool.query(
      "UPDATE refresh_sessions SET expires_at = clock_timestamp() - interval '1 second' WHERE family_id = $1",
      [claims(idle.accessToken).sid],
    );
    await get('/accounts', idle.accessToken).expect(401);
    await post('/v1/auth/refresh', { refreshToken: idle.refreshToken }).expect(
      401,
    );
    const absolute = await issue();
    await pool.query(
      "UPDATE refresh_sessions SET family_expires_at = clock_timestamp() - interval '1 second' WHERE family_id = $1",
      [claims(absolute.accessToken).sid],
    );
    await get('/accounts', absolute.accessToken).expect(401);
    await post('/v1/auth/refresh', {
      refreshToken: absolute.refreshToken,
    }).expect(401);
    const legacy = await issue();
    await pool.query(
      'UPDATE refresh_sessions SET family_expires_at = NULL WHERE family_id = $1',
      [claims(legacy.accessToken).sid],
    );
    await post('/v1/auth/refresh', {
      refreshToken: legacy.refreshToken,
    }).expect(401);
    const [header, payload] = legacy.accessToken.split('.');
    const oldClaims = JSON.parse(
      Buffer.from(payload, 'base64url').toString(),
    ) as { sid?: string };
    delete oldClaims.sid;
    const unsigned = `${header}.${Buffer.from(JSON.stringify(oldClaims)).toString('base64url')}`;
    const signature = createHmac('sha256', secret)
      .update(unsigned)
      .digest('base64url');
    await get('/accounts', `${unsigned}.${signature}`).expect(401);
  });

  it('revalidates after waiting for the holder and leaves no financial effects', async () => {
    const a = await register(true);
    const b = await register(true);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [
        a.sub,
      ]);
      const operation = account(a.accessToken).then(({ status }) => status);
      await waitForHolderLocks();
      await account(b.accessToken).expect(201);
      await client.query(
        'UPDATE refresh_sessions SET revoked_at = clock_timestamp() WHERE family_id = $1',
        [a.sid],
      );
      await client.query('COMMIT');
      expect(await operation).toBe(401);
      expect(await accounts(a.sub)).toEqual([]);
      expect(await accounts(b.sub)).toHaveLength(1);
    } finally {
      await client.query('ROLLBACK');
      client.release();
    }
  });

  it.each(writerFactories)(
    '%s leaves no financial changes when logout wins the holder lock',
    async (_writerName, makeWriter) => {
      const a = await register(true);
      const writer = await makeWriter(a.accessToken);
      const before = await financialSnapshot(a.sub);
      const blocker = await pool.connect();
      let logout: Promise<number> | undefined;
      let operation: Promise<number> | undefined;
      try {
        await blocker.query('BEGIN');
        await blocker.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [
          a.sub,
        ]);
        logout = post('/v1/auth/logout', {
          refreshToken: a.refreshToken,
        }).then(({ status }) => status);
        await waitForHolderLocks();
        operation = writer.run();
        await waitForHolderLocks(2);
        await blocker.query('COMMIT');
        const [logoutStatus, operationStatus] = await Promise.all([
          logout,
          operation,
        ]);
        expect(logoutStatus).toBe(204);
        expect(operationStatus).toBe(401);
        expect(await financialSnapshot(a.sub)).toEqual(before);
        await get('/accounts', a.accessToken).expect(401);
      } finally {
        await blocker.query('ROLLBACK').catch(() => undefined);
        blocker.release();
        await Promise.allSettled(
          [logout, operation].filter(
            (pending): pending is Promise<number> => pending !== undefined,
          ),
        );
      }
    },
  );

  it.each(writerFactories)(
    '%s commits before logout when it wins the holder lock',
    async (_writerName, makeWriter) => {
      const a = await register(true);
      const writer = await makeWriter(a.accessToken);
      const before = await financialSnapshot(a.sub);
      const blocker = await pool.connect();
      let operation: Promise<number> | undefined;
      let logout: Promise<number> | undefined;
      try {
        await installFinancialBarrier(writer.barrierTable);
        await blocker.query('BEGIN');
        await blocker.query('SELECT pg_advisory_xact_lock(10101)');
        operation = writer.run();
        await waitForFinancialInsert(writer.barrierTable);
        logout = post('/v1/auth/logout', {
          refreshToken: a.refreshToken,
        }).then(({ status }) => status);
        await waitForHolderLocks();
        await blocker.query('COMMIT');
        const [operationStatus, logoutStatus] = await Promise.all([
          operation,
          logout,
        ]);
        expect(operationStatus).toBe(201);
        expect(logoutStatus).toBe(204);
        const after = await financialSnapshot(a.sub);
        for (const effect of writer.effects) {
          expect(after[effect]).toBe(before[effect] + 1);
        }
        await get('/accounts', a.accessToken).expect(401);
      } finally {
        await blocker.query('ROLLBACK').catch(() => undefined);
        blocker.release();
        await Promise.allSettled(
          [operation, logout].filter(
            (pending): pending is Promise<number> => pending !== undefined,
          ),
        );
        await removeFinancialBarrier(writer.barrierTable);
      }
    },
  );

  it('allows Apple on the same hybrid holder while the password email is pending', async () => {
    const a = await register(true);
    const subject = randomUUID();
    await post(
      '/v1/auth/apple/link',
      { ...appleBody(subject), password: originalPassword, consent: true },
      a.accessToken,
    ).expect(204);
    await pool.query(
      'UPDATE users SET email_verified_at = NULL WHERE id = $1',
      [a.sub],
    );
    await get('/accounts', a.accessToken).expect(403);
    const apple = (await post('/v1/auth/apple', appleBody(subject)).expect(200))
      .body as AuthResponse;
    expect(claims(apple.accessToken).sub).toBe(a.sub);
    await get('/accounts', apple.accessToken).expect(200, []);
  });

  it('reconciles a discarded Apple-link response, and an earlier unlink cannot replay its effect', async () => {
    const a = await register(true);
    const b = await register(true);
    const secondFamily = (
      await post('/v1/auth/login', {
        email: a.email,
        password: originalPassword,
      }).expect(200)
    ).body as AuthResponse;
    const linkId = randomUUID();
    const unlinkId = randomUUID();
    const receiptPath = (id: string) => `/v1/auth/method-operations/${id}`;
    const subject = randomUUID();
    const link = {
      ...appleBody(subject),
      password: originalPassword,
      consent: true,
    };
    const unlink = { password: originalPassword };
    const linkPath = '/v1/auth/apple/link';
    const unlinkPath = '/v1/auth/apple/unlink';

    await get(receiptPath(linkId), a.accessToken).expect(200, {
      status: 'unknown',
    });
    await post(linkPath, link, a.accessToken)
      .set('Idempotency-Key', 'invalid')
      .expect(400);
    const blocker = await pool.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [
        a.sub,
      ]);
      const commit = post(linkPath, link, a.accessToken)
        .set('Idempotency-Key', linkId)
        .set('X-Lenver-Test-Discard-Response', '1')
        .then(
          ({ status }) => status,
          (error: unknown) => error,
        );
      try {
        await waitForHolderLocks();
        await get(receiptPath(linkId), a.accessToken).expect(200, {
          status: 'unknown',
        });
        await blocker.query('COMMIT');
      } finally {
        await blocker.query('ROLLBACK');
        expect(await commit).toMatchObject({ code: 'ECONNRESET' });
      }
    } finally {
      blocker.release();
    }

    const exchangeCount = exchange.mock.calls.length;
    await get(receiptPath(linkId), a.accessToken)
      .expect('Cache-Control', 'no-store')
      .expect(200, { status: 'committed', action: 'apple_link' });
    for (const token of [b.accessToken, secondFamily.accessToken]) {
      await get(receiptPath(linkId), token).expect(200, { status: 'unknown' });
    }
    await get(receiptPath('invalid'), a.accessToken).expect(400);
    await post(linkPath, link, a.accessToken)
      .set('Idempotency-Key', linkId)
      .expect(204);
    expect(exchange).toHaveBeenCalledTimes(exchangeCount);
    await post(unlinkPath, unlink, a.accessToken)
      .set('Idempotency-Key', linkId)
      .expect(409);
    const apple = (await post('/v1/auth/apple', appleBody(subject)).expect(200))
      .body as AuthResponse;
    await post(unlinkPath, unlink, apple.accessToken)
      .set('Idempotency-Key', unlinkId)
      .expect(403);

    await Promise.all(
      [1, 2].map(() =>
        post(unlinkPath, unlink, a.accessToken)
          .set('Idempotency-Key', unlinkId)
          .expect(204),
      ),
    );
    await get(receiptPath(unlinkId), a.accessToken).expect(200, {
      status: 'committed',
      action: 'apple_unlink',
    });
    await get(receiptPath(linkId), apple.accessToken).expect(401);
    await get('/accounts', a.accessToken).expect(200);
    await post(linkPath, link, a.accessToken).expect(204);
    await post(unlinkPath, unlink, a.accessToken)
      .set('Idempotency-Key', unlinkId)
      .expect(204);
    expect(
      (await get('/v1/auth/session', a.accessToken).expect(200)).body,
    ).toMatchObject({ hasApple: true });

    const count = await pool.query(
      'SELECT count(*)::int AS total FROM identity_method_receipts WHERE user_id = $1',
      [a.sub],
    );
    expect(count.rows).toEqual([{ total: 2 }]);
    await post('/v1/auth/logout', { refreshToken: a.refreshToken }).expect(204);
    await get(receiptPath(linkId), a.accessToken).expect(401);
  });

  it('records only a valid password link and reconciles password unlink without repeating Apple proof', async () => {
    const subject = randomUUID();
    const apple = (await post('/v1/auth/apple', appleBody(subject)).expect(200))
      .body as AuthResponse;
    const email = `${randomUUID()}@example.test`;
    const linkId = randomUUID();
    const unlinkId = randomUUID();
    const link = '/v1/auth/password/link/confirm';
    const unlink = '/v1/auth/password/unlink';
    const receiptPath = (id: string) => `/v1/auth/method-operations/${id}`;

    await post(
      '/v1/auth/password/link',
      { ...appleBody(subject), email, consent: true },
      apple.accessToken,
    ).expect(202);
    const emailCode = code(email, 'add_password');
    const invalidCode = emailCode === '000000' ? '000001' : '000000';
    await post(
      link,
      { email, code: invalidCode, newPassword },
      apple.accessToken,
    )
      .set('Idempotency-Key', linkId)
      .expect(400);
    await get(receiptPath(linkId), apple.accessToken).expect(200, {
      status: 'unknown',
    });
    await Promise.all(
      [1, 2].map(() =>
        post(link, { email, code: emailCode, newPassword }, apple.accessToken)
          .set('Idempotency-Key', linkId)
          .expect(204),
      ),
    );
    await get(receiptPath(linkId), apple.accessToken).expect(200, {
      status: 'committed',
      action: 'password_link',
    });
    const password = (
      await post('/v1/auth/login', { email, password: newPassword }).expect(200)
    ).body as AuthResponse;
    await post(unlink, appleBody(subject), apple.accessToken)
      .set('Idempotency-Key', unlinkId)
      .expect(204);
    const exchangeCount = exchange.mock.calls.length;
    await get(receiptPath(unlinkId), apple.accessToken).expect(200, {
      status: 'committed',
      action: 'password_unlink',
    });
    await post(unlink, appleBody(subject), apple.accessToken)
      .set('Idempotency-Key', unlinkId)
      .expect(204);
    expect(exchange).toHaveBeenCalledTimes(exchangeCount);
    await get('/accounts', password.accessToken).expect(401);
    await get('/accounts', apple.accessToken).expect(200);
  });

  it('keeps Apple continuity and prevents concurrent removals from leaving no method', async () => {
    const a = await register(true);
    const subject = randomUUID();
    await post(
      '/v1/auth/apple/link',
      { ...appleBody(subject), password: originalPassword, consent: true },
      a.accessToken,
    ).expect(204);
    const apple = (await post('/v1/auth/apple', appleBody(subject)).expect(200))
      .body as AuthResponse;
    expect(claims(apple.accessToken).sub).toBe(a.sub);
    const removals = await Promise.all([
      post(
        '/v1/auth/apple/unlink',
        { password: originalPassword },
        a.accessToken,
      ),
      post('/v1/auth/password/unlink', appleBody(subject), apple.accessToken),
    ]);
    expect(removals.filter(({ status }) => status === 204)).toHaveLength(1);
    const available = await Promise.all([
      get('/accounts', a.accessToken),
      get('/accounts', apple.accessToken),
    ]);
    expect(available.map(({ status }) => status).sort()).toEqual([200, 401]);
  });

  it('links a password from Apple only after email proof by the same family', async () => {
    const subject = randomUUID();
    const apple = (await post('/v1/auth/apple', appleBody(subject)).expect(200))
      .body as AuthResponse;
    const other = (await post('/v1/auth/apple', appleBody(subject)).expect(200))
      .body as AuthResponse;
    const email = `${randomUUID()}@example.test`;
    await post(
      '/v1/auth/password/link',
      { ...appleBody(subject), email, consent: true },
      apple.accessToken,
    ).expect(202);
    const payload = { email, code: code(email, 'add_password'), newPassword };
    await post(
      '/v1/auth/password/link/confirm',
      payload,
      other.accessToken,
    ).expect(400);
    await post(
      '/v1/auth/password/link/confirm',
      payload,
      apple.accessToken,
    ).expect(204);
    const login = (
      await post('/v1/auth/login', { email, password: newPassword }).expect(200)
    ).body as AuthResponse;
    expect(claims(login.accessToken).sub).toBe(claims(apple.accessToken).sub);
    await get('/accounts', login.accessToken).expect(200, []);
  });

  it('preserves Apple-only holders when the provider revokes their last method', async () => {
    const apple = (
      await post('/v1/auth/apple', appleBody(randomUUID())).expect(200)
    ).body as AuthResponse;
    const userId = claims(apple.accessToken).sub;
    await pool.query(
      "UPDATE auth_identities SET last_provider_validation_at = now() - interval '25 hours' WHERE user_id = $1",
      [userId],
    );
    validate.mockRejectedValueOnce(
      new AppleAuthError('APPLE_REFRESH_TOKEN_REJECTED', 'synthetic'),
    );
    await post('/v1/auth/refresh', { refreshToken: apple.refreshToken }).expect(
      401,
    );
    await get('/accounts', apple.accessToken).expect(401);
    const user = await pool.query('SELECT id FROM users WHERE id = $1', [
      userId,
    ]);
    expect(user.rowCount).toBe(1);
    const session = await pool.query<{ revoked_at: Date | null }>(
      'SELECT revoked_at FROM refresh_sessions WHERE token_hash = $1',
      [createHash('sha256').update(apple.refreshToken).digest('hex')],
    );
    expect(session.rows[0].revoked_at).toBeInstanceOf(Date);
  });
});
