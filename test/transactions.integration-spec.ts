import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { readFileSync } from 'fs';
import { createHash, createHmac, randomUUID } from 'crypto';
import { Pool, PoolClient } from 'pg';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from '../src/app.module';

const databaseUrl = process.env.TEST_DATABASE_URL;
const describeWithDatabase = databaseUrl ? describe : describe.skip;

describeWithDatabase(
  'Authenticated transactions (PostgreSQL integration)',
  () => {
    const firstAccountId = '10000000-0000-4000-8000-000000000001';
    const secondAccountId = '20000000-0000-4000-8000-000000000001';
    const firstCategoryId = '10000000-0000-4000-8000-000000000002';
    const secondCategoryId = '20000000-0000-4000-8000-000000000002';
    const transactionBody = {
      accountId: firstAccountId,
      categoryId: firstCategoryId,
      type: 'expense',
      amountMinor: 1250,
      currency: 'BRL',
      description: 'Lunch',
      occurredAt: '2026-09-10T15:00:00.000Z',
      clientMutationId: '10000000-0000-4000-8000-000000000003',
    };

    let app: INestApplication<App>;
    let pool: Pool;
    let firstUserId: string;
    let secondUserId: string;
    let firstAccessToken: string;
    let secondAccessToken: string;
    let firstRefreshToken: string;

    beforeAll(async () => {
      if (!databaseUrl) return;

      process.env.DATABASE_URL = databaseUrl;
      process.env.JWT_ACCESS_SECRET =
        'integration-test-secret-with-at-least-32-bytes';
      process.env.JWT_ISSUER = 'fintech-api-integration';
      process.env.JWT_AUDIENCE = 'fintech-clients-integration';

      pool = new Pool({ connectionString: databaseUrl });
      const database = await pool.query<{ current_database: string }>(
        'SELECT current_database()',
      );
      if (!database.rows[0].current_database.endsWith('_test')) {
        throw new Error('Integration tests require a database ending in _test');
      }

      await pool.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public');
      await pool.query(readFileSync('db.sql', 'utf8'));

      const module = await Test.createTestingModule({
        imports: [AppModule],
      }).compile();
      app = module.createNestApplication();
      app.useGlobalPipes(
        new ValidationPipe({
          whitelist: true,
          forbidNonWhitelisted: true,
          transform: true,
          validationError: { target: false, value: false },
        }),
      );
      await app.init();

      const first = await request(app.getHttpServer())
        .post('/auth/register')
        .send({ email: '  FIRST@Example.com ', password: 'correct horse' })
        .expect(201);
      const second = await request(app.getHttpServer())
        .post('/auth/register')
        .send({ email: 'second@example.com', password: 'correct horse' })
        .expect(201);

      const firstAuth = authBody(first.body as unknown);
      const secondAuth = authBody(second.body as unknown);
      firstAccessToken = firstAuth.accessToken;
      secondAccessToken = secondAuth.accessToken;
      firstRefreshToken = firstAuth.refreshToken;
      firstUserId = accessTokenSubject(firstAccessToken);
      secondUserId = accessTokenSubject(secondAccessToken);

      await pool.query(
        `
        INSERT INTO accounts (id, user_id, name, currency)
        VALUES ($1, $2, 'Main', 'BRL'), ($3, $4, 'Other', 'BRL')
      `,
        [firstAccountId, firstUserId, secondAccountId, secondUserId],
      );
      await pool.query(
        `
        INSERT INTO categories (id, user_id, name)
        VALUES ($1, $2, 'Food'), ($3, $4, 'Other')
      `,
        [firstCategoryId, firstUserId, secondCategoryId, secondUserId],
      );
    });

    it('normalizes email and keeps auth response contract stable', async () => {
      const stored = await pool.query<{
        email: string;
        password_hash: string;
      }>('SELECT email, password_hash FROM users WHERE id = $1', [firstUserId]);
      expect(stored.rows[0].email).toBe('first@example.com');
      expect(stored.rows[0].password_hash).toMatch(/^scrypt\$/);
      expect(stored.rows[0].password_hash).not.toContain('correct horse');
      const refresh = await pool.query<{ token_hash: string }>(
        'SELECT token_hash FROM refresh_sessions WHERE user_id = $1',
        [firstUserId],
      );
      expect(refresh.rows[0].token_hash).toMatch(/^[0-9a-f]{64}$/);
      expect(refresh.rows[0].token_hash).not.toBe(firstRefreshToken);
      expect(firstAccessToken.split('.')).toHaveLength(3);
      expect(firstRefreshToken).toEqual(expect.any(String));
    });

    it('rejects duplicate registration and invalid credentials', async () => {
      await request(app.getHttpServer())
        .post('/auth/register')
        .send({ email: 'FIRST@example.com', password: 'correct horse' })
        .expect(409);
      await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: 'first@example.com', password: 'wrong password' })
        .expect(401);
    });

    it('logs in, rotates refresh tokens, revokes a reused family, and logs out', async () => {
      const login = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: 'FIRST@example.com', password: 'correct horse' })
        .expect(200);
      const loginAuth = authBody(login.body as unknown);
      expect(loginAuth).toMatchObject({ tokenType: 'Bearer', expiresIn: 900 });

      const rotated = await request(app.getHttpServer())
        .post('/auth/refresh')
        .send({ refreshToken: loginAuth.refreshToken })
        .expect(200);
      const rotatedAuth = authBody(rotated.body as unknown);
      expect(rotatedAuth.refreshToken).not.toBe(loginAuth.refreshToken);

      await request(app.getHttpServer())
        .post('/auth/refresh')
        .send({ refreshToken: loginAuth.refreshToken })
        .expect(401);
      await request(app.getHttpServer())
        .post('/auth/refresh')
        .send({ refreshToken: rotatedAuth.refreshToken })
        .expect(401);

      const freshLogin = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: 'first@example.com', password: 'correct horse' })
        .expect(200);
      const freshLoginAuth = authBody(freshLogin.body as unknown);
      await request(app.getHttpServer())
        .post('/auth/logout')
        .send({ refreshToken: freshLoginAuth.refreshToken })
        .expect(204)
        .expect('');
      await request(app.getHttpServer())
        .post('/auth/refresh')
        .send({ refreshToken: freshLoginAuth.refreshToken })
        .expect(401);
    });

    it('revokes descendants when reuse races with successor rotation', async () => {
      const login = authBody(
        (
          await request(app.getHttpServer())
            .post('/auth/login')
            .send({
              email: 'first@example.com',
              password: 'correct horse',
            })
            .expect(200)
        ).body as unknown,
      );
      const firstRotation = authBody(
        (
          await request(app.getHttpServer())
            .post('/auth/refresh')
            .send({ refreshToken: login.refreshToken })
            .expect(200)
        ).body as unknown,
      );
      const blocker = await pool.connect();

      try {
        await blocker.query('BEGIN');
        await blocker.query(
          `SELECT 1 FROM refresh_sessions WHERE token_hash = $1 FOR UPDATE`,
          [hashRefreshToken(firstRotation.refreshToken)],
        );

        const successorRotation = request(app.getHttpServer())
          .post('/auth/refresh')
          .send({ refreshToken: firstRotation.refreshToken })
          .then((response) => response);
        await waitForBlockedAuthOperations(pool, 1);

        const reuse = request(app.getHttpServer())
          .post('/auth/refresh')
          .send({ refreshToken: login.refreshToken })
          .then((response) => response);
        await waitForBlockedAuthOperations(pool, 2);

        await blocker.query('COMMIT');
        const [rotationResponse, reuseResponse] = await Promise.all([
          successorRotation,
          reuse,
        ]);
        expect(rotationResponse.status).toBe(200);
        expect(reuseResponse.status).toBe(401);

        const descendant = authBody(rotationResponse.body as unknown);
        await request(app.getHttpServer())
          .post('/auth/refresh')
          .send({ refreshToken: descendant.refreshToken })
          .expect(401);
      } finally {
        await rollbackAndRelease(blocker);
      }
    });

    it('returns 201 for a valid owned account and category', async () => {
      const response = await postTransaction(
        firstAccessToken,
        '10000000-0000-4000-8000-000000000004',
        transactionBody,
      ).expect(201);
      expect(response.body).toMatchObject(transactionBodyWithoutMutationId());
    });

    it('returns 400 for invalid or incomplete payloads', async () => {
      await postTransaction(
        firstAccessToken,
        '10000000-0000-4000-8000-000000000005',
        { accountId: firstAccountId },
      ).expect(400);
    });

    it.each([
      [
        'missing account',
        '30000000-0000-4000-8000-000000000001',
        firstCategoryId,
      ],
      ['foreign account', secondAccountId, firstCategoryId],
    ])(
      'returns indistinguishable 404 for %s',
      async (_case, accountId, categoryId) => {
        const response = await postTransaction(firstAccessToken, randomKey(), {
          ...transactionBody,
          accountId,
          categoryId,
        }).expect(404);
        expect((response.body as { message: unknown }).message).toBe(
          'Account not found',
        );
      },
    );

    it.each([
      ['missing category', '30000000-0000-4000-8000-000000000002'],
      ['foreign category', secondCategoryId],
    ])('returns indistinguishable 404 for %s', async (_case, categoryId) => {
      const response = await postTransaction(firstAccessToken, randomKey(), {
        ...transactionBody,
        categoryId,
      }).expect(404);
      expect((response.body as { message: unknown }).message).toBe(
        'Category not found',
      );
    });

    it('rejects inconsistent account and category ownership', async () => {
      await postTransaction(secondAccessToken, randomKey(), {
        ...transactionBody,
        accountId: secondAccountId,
        categoryId: firstCategoryId,
      }).expect(404);
    });

    it('requires transaction currency to equal account currency', async () => {
      await postTransaction(firstAccessToken, randomKey(), {
        ...transactionBody,
        currency: 'USD',
      }).expect(400);
    });

    it('scopes idempotency keys by authenticated user', async () => {
      const key = randomKey();
      await postTransaction(firstAccessToken, key, {
        ...transactionBody,
        categoryId: undefined,
      }).expect(201);
      await postTransaction(secondAccessToken, key, {
        ...transactionBody,
        accountId: secondAccountId,
        categoryId: secondCategoryId,
      }).expect(201);
    });

    it('enforces ownership and currency invariants in PostgreSQL', async () => {
      await expect(
        pool.query(
          `
            INSERT INTO transactions (
              id, user_id, account_id, category_id, type,
              amount_minor, currency, occurred_at
            ) VALUES ($1, $2, $3, $4, 'expense', 100, 'BRL', now())
          `,
          [randomUUID(), firstUserId, firstAccountId, secondCategoryId],
        ),
      ).rejects.toMatchObject({ code: '23503' });

      await expect(
        pool.query(
          `
            INSERT INTO transactions (
              id, user_id, account_id, category_id, type,
              amount_minor, currency, occurred_at
            ) VALUES ($1, $2, $3, NULL, 'expense', 100, 'USD', now())
          `,
          [randomUUID(), firstUserId, firstAccountId],
        ),
      ).rejects.toMatchObject({ code: '23503' });
    });

    it('does not accept identity from payload and requires a bearer token', async () => {
      await postTransaction('', randomKey(), transactionBody).expect(401);
      await postTransaction(firstAccessToken, randomKey(), {
        ...transactionBody,
        userId: secondUserId,
      }).expect(400);
    });

    it.each([
      ['unexpected algorithm', { alg: 'none' }, {}],
      ['wrong issuer', {}, { iss: 'other-issuer' }],
      ['wrong audience', {}, { aud: 'other-audience' }],
      ['expired token', {}, { exp: 1 }],
      ['invalid subject', {}, { sub: 'not-a-uuid' }],
    ])('rejects JWT with %s', async (_case, header, payload) => {
      await postTransaction(
        signedAccessToken(firstUserId, header, payload),
        randomKey(),
        transactionBody,
      ).expect(401);
    });

    it('rate limits registration separately at five requests per window', async () => {
      for (let attempt = 0; attempt < 2; attempt += 1) {
        await request(app.getHttpServer())
          .post('/auth/register')
          .send({ email: 'invalid', password: 'short' })
          .expect(400);
      }

      const limited = await request(app.getHttpServer())
        .post('/auth/register')
        .send({ email: 'invalid', password: 'short' })
        .expect(429);
      expect(limited.headers['retry-after']).toEqual(expect.any(String));
    });

    afterAll(async () => {
      if (app) await app.close();
      if (pool) await pool.end();
    });

    function postTransaction(
      token: string,
      key: string,
      body: object,
    ): request.Test {
      const test = request(app.getHttpServer())
        .post('/transactions')
        .set('Idempotency-Key', key);
      if (token) test.set('Authorization', `Bearer ${token}`);
      return test.send(body);
    }

    function transactionBodyWithoutMutationId(): Record<string, unknown> {
      return {
        accountId: transactionBody.accountId,
        categoryId: transactionBody.categoryId,
        type: transactionBody.type,
        amountMinor: transactionBody.amountMinor,
        currency: transactionBody.currency,
        description: transactionBody.description,
        occurredAt: transactionBody.occurredAt,
      };
    }

    function randomKey(): string {
      return randomUUID();
    }
  },
);

function accessTokenSubject(token: string): string {
  const payload = JSON.parse(
    Buffer.from(token.split('.')[1], 'base64url').toString('utf8'),
  ) as { sub: string };
  return payload.sub;
}

function authBody(value: unknown): {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: 900;
} {
  if (
    typeof value !== 'object' ||
    value === null ||
    !('accessToken' in value) ||
    typeof value.accessToken !== 'string' ||
    !('refreshToken' in value) ||
    typeof value.refreshToken !== 'string' ||
    !('tokenType' in value) ||
    value.tokenType !== 'Bearer' ||
    !('expiresIn' in value) ||
    value.expiresIn !== 900
  ) {
    throw new Error('Expected authentication response');
  }

  return value as {
    accessToken: string;
    refreshToken: string;
    tokenType: 'Bearer';
    expiresIn: 900;
  };
}

function signedAccessToken(
  userId: string,
  headerOverrides: Record<string, unknown>,
  payloadOverrides: Record<string, unknown>,
): string {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(
    JSON.stringify({ alg: 'HS256', typ: 'JWT', ...headerOverrides }),
  ).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      sub: userId,
      iss: 'fintech-api-integration',
      aud: 'fintech-clients-integration',
      iat: now,
      exp: now + 900,
      jti: randomUUID(),
      ...payloadOverrides,
    }),
  ).toString('base64url');
  const signature = createHmac(
    'sha256',
    'integration-test-secret-with-at-least-32-bytes',
  )
    .update(`${header}.${payload}`)
    .digest('base64url');
  return `${header}.${payload}.${signature}`;
}

function hashRefreshToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

async function waitForBlockedAuthOperations(
  pool: Pool,
  expected: number,
): Promise<void> {
  const deadline = Date.now() + 5_000;

  while (Date.now() < deadline) {
    const result = await pool.query<{ count: string }>(
      `
        SELECT count(*)::text AS count
        FROM pg_stat_activity
        WHERE datname = current_database()
          AND wait_event_type = 'Lock'
          AND (
            query LIKE '%refresh_sessions%'
            OR query LIKE '%pg_advisory_xact_lock%'
          )
      `,
    );
    if (Number(result.rows[0].count) >= expected) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }

  throw new Error(`Expected ${expected} blocked authentication operations`);
}

async function rollbackAndRelease(client: PoolClient): Promise<void> {
  try {
    await client.query('ROLLBACK');
  } finally {
    client.release();
  }
}
