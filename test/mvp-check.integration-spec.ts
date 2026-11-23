import { INestApplication, ValidationPipe } from '@nestjs/common';
import { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Pool } from 'pg';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from '../src/app.module';

const url = process.env.TEST_DATABASE_URL;
const describeWithDatabase = url ? describe : describe.skip;
const baseAt = '2026-01-01T12:00:00.000001Z';
const checkAt = '2026-01-02T11:00:00.123456Z';
const afterCheck = '2026-01-02T12:00:00.123456Z';

describeWithDatabase('I2 balance checks (HTTP and PostgreSQL)', () => {
  let app: INestApplication<App>;
  let pool: Pool;
  let fixtureIP = 0;
  const http = () => request(app.getHttpServer());

  beforeAll(async () => {
    process.env.DATABASE_URL = url;
    process.env.JWT_ACCESS_SECRET = 'disposable-i2-test-secret-long-enough';
    process.env.JWT_ISSUER = 'fintech-integration';
    process.env.JWT_AUDIENCE = 'fintech-integration';
    pool = new Pool({ connectionString: url });
    const {
      rows: [db],
    } = await pool.query<{ current_database: string }>(
      'SELECT current_database()',
    );
    if (!db.current_database.endsWith('_test')) {
      throw new Error(
        'Integration tests require a disposable database ending in _test',
      );
    }
    await pool.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public');
    await pool.query(readFileSync('db.sql', 'utf8'));
    const module = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();
    app = module.createNestApplication<NestExpressApplication>({
      logger: false,
    });
    (app as NestExpressApplication).set('trust proxy', 1);
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

  afterAll(async () => {
    await app?.close();
    await pool?.end();
  });

  async function open(baseMinor = '90000') {
    const auth = await http()
      .post('/auth/register')
      .set('X-Forwarded-For', `192.0.2.${++fixtureIP}`)
      .send({
        email: `i2-${randomUUID()}@example.test`,
        password: 'fictional i2 password',
      })
      .expect(201);
    const authorization = `Bearer ${(auth.body as { accessToken: string }).accessToken}`;
    const response = await http()
      .post('/mvp/account')
      .set('Authorization', authorization)
      .set('Idempotency-Key', randomUUID())
      .send({
        baseMinor,
        coverageStart: baseAt,
        referenceZone: 'America/Sao_Paulo',
      })
      .expect(201);
    const { account, principalId } = response.body as {
      account: { id: string };
      principalId: string;
    };
    const input = {
      accountId: account.id,
      observedMinor: '80000',
      referenceAt: checkAt,
    };
    return {
      id: account.id,
      principalId,
      authorization,
      preview: (changes = {}) =>
        http()
          .post('/mvp/check-previews')
          .set('Authorization', authorization)
          .send({ ...input, ...changes }),
      confirm: (expectedRevision: string, key = randomUUID(), changes = {}) =>
        http()
          .post('/mvp/checks')
          .set('Authorization', authorization)
          .set('Idempotency-Key', key)
          .send({ ...input, expectedRevision, ...changes }),
      list: (query = {}) =>
        http()
          .get(`/mvp/account/${account.id}/checks`)
          .set('Authorization', authorization)
          .query(query),
      move: (
        expectedRevision: string,
        amountMinor: number,
        occurredAt: string,
        key = randomUUID(),
      ) =>
        http()
          .post('/mvp/transactions')
          .set('Authorization', authorization)
          .set('Idempotency-Key', key)
          .send({
            accountId: account.id,
            type: 'expense',
            currency: 'BRL',
            amountMinor,
            occurredAt,
            clientMutationId: randomUUID(),
            expectedRevision,
          }),
    };
  }

  async function counts(id: string) {
    const { rows } = await pool.query(
      `SELECT (SELECT count(*)::int FROM transactions WHERE account_id = $1) AS movements,
              (SELECT count(*)::int FROM mvp_balance_checks WHERE account_id = $1) AS checks,
              (SELECT count(*)::int FROM idempotency_keys
               WHERE response->>'accountId' = $1::uuid::text AND response ? 'observedMinor') AS receipts,
              (SELECT revision::text FROM mvp_accounts WHERE account_id = $1) AS revision`,
      [id],
    );
    return rows[0] as {
      movements: number;
      checks: number;
      receipts: number;
      revision: string;
    };
  }

  it('preserves S02 originals, includes the exact cut and keeps prior checks independently', async () => {
    const a = await open();
    await a.move('1', 5500, baseAt).expect(201);
    await a
      .preview()
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          referenceAt: checkAt,
          calculatedMinor: '84500',
          differenceMinor: '4500',
          revision: '2',
        }),
      );
    expect(await counts(a.id)).toEqual({
      movements: 1,
      checks: 0,
      receipts: 0,
      revision: '2',
    });
    const key = randomUUID();
    const first = await a.confirm('2', key).expect(201);
    const original = first.body as { id: string; baseConfirmedAt: string };
    expect(first.body).toMatchObject({
      authorId: a.principalId,
      observedMinor: '80000',
      originalCalculatedMinor: '84500',
      originalDifferenceMinor: '4500',
      revision: '3',
      referenceAt: checkAt,
    });
    expect(Date.parse(original.baseConfirmedAt)).not.toBeNaN();
    expect(await counts(a.id)).toEqual({
      movements: 1,
      checks: 1,
      receipts: 1,
      revision: '3',
    });

    await a.move('3', 1800, afterCheck).expect(201);
    await a
      .list({ view: 'pending' })
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          summary: { balanceMinor: '82700', revision: '4' },
          entries: [
            {
              ...original,
              calculatedAtReferenceMinor: '84500',
              remainingDifferenceMinor: '4500',
              status: 'open',
            },
          ],
        }),
      );
    await a
      .confirm('2', key.toUpperCase())
      .expect(201)
      .expect(({ body }) => expect(body).toEqual(first.body));
    await a
      .confirm('2', key, { observedMinor: '79999' })
      .expect(409)
      .expect(({ body }) =>
        expect(body).toMatchObject({ code: 'IDEMPOTENCY_CONFLICT' }),
      );
    await a.move('4', 100, checkAt).expect(201);
    await a
      .confirm('5', randomUUID(), {
        referenceAt: afterCheck,
        observedMinor: '82600',
      })
      .expect(201);
    await a
      .list()
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          summary: { balanceMinor: '82600', revision: '6' },
          entries: [
            { status: 'coincident', remainingDifferenceMinor: '0' },
            {
              id: original.id,
              originalDifferenceMinor: '4500',
              calculatedAtReferenceMinor: '84400',
              remainingDifferenceMinor: '4400',
              status: 'open',
            },
          ],
        }),
      );
    await a
      .list({ view: 'pending' })
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          entries: [{ id: original.id, status: 'open' }],
        }),
      );
    expect(await counts(a.id)).toEqual({
      movements: 3,
      checks: 2,
      receipts: 2,
      revision: '6',
    });
  });

  it('enforces coverage and signed exact totals outside Int64, with no effects on rejection', async () => {
    const a = await open('9223372036854775807');
    const observedMinor = '-9223372036854775808';
    for (const referenceAt of [
      '2026-01-01T12:00:00.000000Z',
      '9999-12-31T00:00:00Z',
    ]) {
      await a.preview({ referenceAt }).expect(400);
      await a.confirm('1', randomUUID(), { referenceAt }).expect(400);
    }
    await a.preview({ observedMinor: '9223372036854775808' }).expect(400);
    await a.preview({ observedMinor: '-0' }).expect(400);
    await a.preview({ observedMinor: '0', referenceAt: baseAt }).expect(200);
    await a
      .preview({ observedMinor, referenceAt: baseAt })
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          calculatedMinor: '9223372036854775807',
          differenceMinor: '18446744073709551615',
        }),
      );
    expect(await counts(a.id)).toEqual({
      movements: 0,
      checks: 0,
      receipts: 0,
      revision: '1',
    });
    await a
      .confirm('1', randomUUID(), { observedMinor, referenceAt: baseAt })
      .expect(201)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          originalDifferenceMinor: '18446744073709551615',
        }),
      );
    const negative = await open('-1');
    await negative
      .confirm('1', randomUUID(), { observedMinor: '99', referenceAt: baseAt })
      .expect(201)
      .expect(({ body }) =>
        expect(body).toMatchObject({ originalDifferenceMinor: '-100' }),
      );
  });

  it('serializes check against expense and concurrent replay, including the shared key namespace', async () => {
    const a = await open();
    const key = randomUUID();
    const [check, move] = await Promise.all([
      a.confirm('1', key),
      a.move('1', 1800, checkAt),
    ]);
    expect([check.status, move.status].sort()).toEqual([201, 409]);
    expect((check.status === 409 ? check : move).body).toMatchObject({
      code: 'STALE_REVISION',
    });
    const nextKey = randomUUID();
    const [one, two] = await Promise.all([
      a.confirm('2', nextKey).expect(201),
      a.confirm('2', nextKey).expect(201),
    ]);
    expect(one.body).toEqual(two.body);
    expect(one.body).toMatchObject({
      originalCalculatedMinor: move.status === 201 ? '88200' : '90000',
    });
    await a
      .move('3', 1, checkAt, nextKey)
      .expect(409)
      .expect(({ body }) =>
        expect(body).toMatchObject({ code: 'IDEMPOTENCY_CONFLICT' }),
      );
    expect(await counts(a.id)).toEqual({
      movements: Number(move.status === 201),
      checks: 1 + Number(check.status === 201),
      receipts: 1 + Number(check.status === 201),
      revision: '3',
    });
  });

  it('rolls back the observation and revision when the receipt fails, and rejects mutation', async () => {
    const a = await open();
    const key = randomUUID();
    await pool.query(`
      CREATE FUNCTION fail_i2_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN IF NEW.idempotency_key = '${key}' THEN RAISE EXCEPTION 'fixture failure'; END IF; RETURN NEW; END; $$;
      CREATE TRIGGER fail_i2_receipt BEFORE INSERT ON idempotency_keys
      FOR EACH ROW EXECUTE FUNCTION fail_i2_receipt();
    `);
    try {
      await a.confirm('1', key).expect(503);
      expect(await counts(a.id)).toEqual({
        movements: 0,
        checks: 0,
        receipts: 0,
        revision: '1',
      });
    } finally {
      await pool.query(
        'DROP TRIGGER fail_i2_receipt ON idempotency_keys; DROP FUNCTION fail_i2_receipt()',
      );
    }
    await a.confirm('1', key).expect(201);
    await expect(
      pool.query(
        'UPDATE mvp_balance_checks SET observed_minor = 0 WHERE account_id = $1',
        [a.id],
      ),
    ).rejects.toMatchObject({ constraint: 'mvp_check_immutable' });
    await expect(
      pool.query('DELETE FROM mvp_balance_checks WHERE account_id = $1', [
        a.id,
      ]),
    ).rejects.toMatchObject({ constraint: 'mvp_check_immutable' });
  });

  it('keeps reads at one confirmed revision and rejects an insert with no receipt at commit', async () => {
    const a = await open();
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        `INSERT INTO mvp_balance_checks
        (id, user_id, account_id, observed_minor, reference_at, mvp_revision, mvp_write_key)
        VALUES ($1, $2, $3, 80000, $4, 2, $5)`,
        [randomUUID(), a.principalId, a.id, checkAt, randomUUID()],
      );
      await a
        .list()
        .expect(200)
        .expect(({ body }) =>
          expect(body).toMatchObject({
            summary: { revision: '1', balanceMinor: '90000' },
            entries: [],
          }),
        );
      await expect(client.query('COMMIT')).rejects.toMatchObject({
        code: '23503',
      });
    } finally {
      await client.query('ROLLBACK');
      client.release();
    }
    await a.confirm('1').expect(201);
    await a
      .list()
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          summary: { revision: '2', balanceMinor: '90000' },
          entries: [{ revision: '2', remainingDifferenceMinor: '10000' }],
        }),
      );
  });

  it('does not reveal checks or pagination anchors across principals', async () => {
    const a = await open();
    const b = await open();
    const own = await a.confirm('1').expect(201);
    await b.preview({ accountId: a.id }).expect(404);
    await b.confirm('1', randomUUID(), { accountId: a.id }).expect(404);
    await http()
      .get(`/mvp/account/${a.id}/checks`)
      .set('Authorization', b.authorization)
      .expect(404);
    await b
      .list({ revision: '1', after: (own.body as { id: string }).id })
      .expect(400);
    await b
      .list()
      .expect(200)
      .expect(({ body }) => expect(body).toMatchObject({ entries: [] }));
  });

  it('requires a confirmed base even for an account owned by the principal', async () => {
    const a = await open();
    const legacy = await http()
      .post('/accounts')
      .set('Authorization', a.authorization)
      .send({ name: 'Legacy fixture', currency: 'BRL' })
      .expect(201);
    const accountId = (legacy.body as { id: string }).id;
    const requests = [
      () => a.preview({ accountId }),
      () => a.confirm('1', randomUUID(), { accountId }),
      () =>
        http()
          .get(`/mvp/account/${accountId}/checks`)
          .set('Authorization', a.authorization),
    ];
    for (const request of requests) {
      await request()
        .expect(409)
        .expect(({ body }) =>
          expect(body).toMatchObject({ code: 'BASE_REQUIRED' }),
        );
    }
  });

  it('pages in deterministic order and invalidates a cursor after another write', async () => {
    const a = await open();
    // Seed through the same trigger and commit each check with its own receipt.
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (let revision = 2; revision <= 52; revision++) {
        const id = randomUUID();
        const key = randomUUID();
        await client.query(
          `INSERT INTO mvp_balance_checks
          (id, user_id, account_id, observed_minor, reference_at, mvp_revision, mvp_write_key)
          VALUES ($1, $2, $3, 80000, $4, $5, $6)`,
          [id, a.principalId, a.id, checkAt, revision, key],
        );
        await client.query(
          `INSERT INTO idempotency_keys (id, user_id, idempotency_key, request_hash, response)
          VALUES ($1, $2, $3, 'fixture', $4)`,
          [
            randomUUID(),
            a.principalId,
            key,
            JSON.stringify({ id, accountId: a.id, revision: String(revision) }),
          ],
        );
      }
      await client.query('COMMIT');
    } finally {
      await client.query('ROLLBACK');
      client.release();
    }
    const first = await a.list({ view: 'pending' }).expect(200);
    const { entries, nextAfter } = first.body as {
      entries: Array<{ id: string }>;
      nextAfter: string;
    };
    expect(entries).toHaveLength(50);
    expect(nextAfter).toBe(entries.at(-1)?.id);
    const last = await a
      .list({ view: 'pending', after: nextAfter, revision: '52' })
      .expect(200);
    const tail = last.body as {
      entries: Array<{ id: string }>;
      nextAfter: string | null;
    };
    expect(tail.entries).toHaveLength(1);
    expect(entries.some(({ id }) => id === tail.entries[0].id)).toBe(false);
    expect(tail.nextAfter).toBeNull();
    await a.move('52', 10, afterCheck).expect(201);
    await a
      .list({ after: nextAfter, revision: '52' })
      .expect(409)
      .expect(({ body }) =>
        expect(body).toMatchObject({ code: 'STALE_REVISION' }),
      );
  });
});
