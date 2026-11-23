import { INestApplication, ValidationPipe } from '@nestjs/common';
import { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Pool } from 'pg';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from '../src/app.module';

const databaseUrl = process.env.TEST_DATABASE_URL;
const describeWithDatabase = databaseUrl ? describe : describe.skip;
const coverageStart = '2026-01-01T12:00:00.000001Z';
const opening = { coverageStart, referenceZone: 'America/Sao_Paulo' };

describeWithDatabase('I1-A account (HTTP and PostgreSQL)', () => {
  let pool: Pool;
  let app: INestApplication<App>;
  let legacyAuth: string;
  let legacyId: string;
  let legacyMove: Record<string, unknown>;
  let legacyReceipt: unknown;
  let legacyRows: unknown;
  const legacyKey = randomUUID();
  let fixtureIP = 0;

  beforeAll(async () => {
    process.env.DATABASE_URL = databaseUrl;
    process.env.JWT_ACCESS_SECRET = 'disposable-i1a-test-secret-long-enough';
    process.env.JWT_ISSUER = 'fintech-integration';
    process.env.JWT_AUDIENCE = 'fintech-integration';
    pool = new Pool({ connectionString: databaseUrl });
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
    const bootstrap = readFileSync('db.sql', 'utf8');
    const mvpStart = bootstrap.indexOf('CREATE TABLE mvp_accounts');
    expect(mvpStart).toBeGreaterThan(0);
    await pool.query(bootstrap.slice(0, mvpStart));

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
      }),
    );
    await app.init();

    legacyAuth = await register();
    const legacy = await http()
      .post('/accounts')
      .set('Authorization', legacyAuth)
      .send({ name: 'Fictícia anterior', currency: 'BRL' })
      .expect(201);
    legacyId = (legacy.body as { id: string }).id;
    legacyMove = {
      accountId: legacyId,
      type: 'expense',
      amountMinor: 5500,
      currency: 'BRL',
      occurredAt: coverageStart,
      clientMutationId: randomUUID(),
    };
    const posted = await postMove(legacyAuth, legacyKey, legacyMove).expect(
      201,
    );
    legacyReceipt = posted.body;
    legacyRows = await readLegacyRows();
    await pool.query(
      readFileSync('migrations/20261123_add_mvp_account_base.sql', 'utf8'),
    );
    await pool.query(
      readFileSync(
        'migrations/20261123_enable_mvp_transaction_registration.sql',
        'utf8',
      ),
    );
    await pool.query(
      readFileSync('migrations/20261123_record_mvp_balance_checks.sql', 'utf8'),
    );
    await pool.query(
      readFileSync('migrations/20261123_recover_mvp_expenses.sql', 'utf8'),
    );
  });

  afterAll(async () => {
    await app?.close();
    await pool?.end();
  });

  it.each([
    '0',
    '90000',
    '-5500',
    '9223372036854775807',
    '-9223372036854775808',
  ])(
    'opens and reads a confirmed exact balance of %s minor units',
    async (baseMinor) => {
      const auth = await register();
      await http()
        .get('/mvp/account')
        .set('Authorization', auth)
        .expect(200)
        .expect(({ body }) =>
          expect(body).toMatchObject({
            status: 'no_account',
            balanceMinor: null,
          }),
        );
      const terms = { ...opening, baseMinor };
      const reviewed = await http()
        .post('/mvp/account-previews')
        .set('Authorization', auth)
        .send(terms)
        .expect(200);
      expect(reviewed.body).toEqual(terms);
      await http().get('/accounts').set('Authorization', auth).expect(200, []);

      const response = await open(auth, randomUUID(), terms).expect(201);
      expect(response.body).toMatchObject({
        status: 'available',
        balanceMinor: baseMinor,
        revision: '1',
        base: terms,
      });
      await http()
        .get('/mvp/account')
        .set('Authorization', auth)
        .expect(200)
        .expect((read) =>
          expect(read.body).toMatchObject({
            account: (response.body as { account: unknown }).account,
            balanceMinor: baseMinor,
            revision: '1',
          }),
        );
    },
  );

  it('serializes different intents and replays the winner using the canonical receipt', async () => {
    const auth = await register();
    const commands = [
      { key: randomUUID(), baseMinor: '100' },
      { key: randomUUID(), baseMinor: '200' },
    ];
    const replies = await Promise.all(
      commands.map(({ key, baseMinor }) =>
        open(auth, key, { ...opening, baseMinor }),
      ),
    );
    expect(replies.map(({ status }) => status).sort()).toEqual([201, 409]);
    const winner = replies.findIndex(({ status }) => status === 201);
    expect(replies[1 - winner].body).toMatchObject({
      code: 'MVP_ACCOUNT_EXISTS',
    });
    const command = commands[winner];
    const terms = { ...opening, baseMinor: command.baseMinor };
    const replay = await open(auth, command.key.toUpperCase(), terms).expect(
      201,
    );
    expect(replay.body).toEqual(replies[winner].body);
    await open(auth, command.key, { ...terms, baseMinor: '1' })
      .expect(409)
      .expect(({ body }) =>
        expect(body).toMatchObject({ code: 'IDEMPOTENCY_CONFLICT' }),
      );
    await http()
      .get('/accounts')
      .set('Authorization', auth)
      .expect(200)
      .expect(({ body }) => expect(body).toHaveLength(1));
  });

  it('commits a concurrent first submission for the same key once', async () => {
    const auth = await register();
    const key = randomUUID();
    const terms = { ...opening, baseMinor: '0' };
    const [first, second] = await Promise.all([
      open(auth, key, terms).expect(201),
      open(auth, key, terms).expect(201),
    ]);
    expect(first.body).toEqual(second.body);
    const {
      rows: [count],
    } = await pool.query<{ count: number }>(
      'SELECT count(*)::int AS count FROM idempotency_keys WHERE idempotency_key = $1',
      [key],
    );
    expect(count.count).toBe(1);
  });

  it('preserves pre-upgrade accounts, movements and receipts, and blocks legacy adoption', async () => {
    expect(await readLegacyRows()).toEqual(legacyRows);
    const { rows: precision } = await pool.query(
      `SELECT occurrence_day, occurrence_zone, latest_occurrence_at, mvp_recovery_id
       FROM transactions WHERE account_id = $1`,
      [legacyId],
    );
    expect(precision).toEqual([
      {
        occurrence_day: null,
        occurrence_zone: null,
        latest_occurrence_at: null,
        mvp_recovery_id: null,
      },
    ]);
    await postMove(legacyAuth, legacyKey, legacyMove)
      .expect(201)
      .expect(({ body }) => expect(body).toEqual(legacyReceipt));
    await http()
      .get('/mvp/account')
      .set('Authorization', legacyAuth)
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          account: null,
          legacyAccounts: [{ id: legacyId }],
          balanceMinor: null,
        }),
      );
    await http()
      .get(`/mvp/account/${legacyId}`)
      .set('Authorization', legacyAuth)
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          status: 'base_required',
          base: null,
          balanceMinor: null,
          revision: null,
        }),
      );
    const adopt = { ...opening, baseMinor: '0', accountId: legacyId };
    await http()
      .post('/mvp/account-previews')
      .set('Authorization', legacyAuth)
      .send(adopt)
      .expect(409)
      .expect(({ body }) =>
        expect(body).toMatchObject({ code: 'LEGACY_ADOPTION_BLOCKED' }),
      );
    await open(legacyAuth, randomUUID(), adopt).expect(409);
    await open(legacyAuth, legacyKey, adopt)
      .expect(409)
      .expect(({ body }) =>
        expect(body).toMatchObject({ code: 'IDEMPOTENCY_CONFLICT' }),
      );
    expect(await readLegacyRows()).toEqual(legacyRows);
  });

  it('enforces ownership on activation and reads, and blocks old writers on the active account', async () => {
    const authA = await register();
    const authB = await register();
    const response = await open(authA, randomUUID(), {
      ...opening,
      baseMinor: '1',
    }).expect(201);
    const { account } = response.body as { account: { id: string } };
    await http().get('/mvp/account').expect(401);
    await http()
      .get(`/mvp/account/${account.id}`)
      .set('Authorization', authB)
      .expect(404);
    await open(authB, randomUUID(), {
      ...opening,
      baseMinor: '0',
      accountId: account.id,
    }).expect(404);
    await postMove(authB, randomUUID(), {
      ...legacyMove,
      accountId: account.id,
    }).expect(404);
    await postMove(authA, randomUUID(), {
      ...legacyMove,
      accountId: account.id,
    }).expect(400);
    await http()
      .get('/mvp/account')
      .set('Authorization', authB)
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          status: 'no_account',
          legacyAccounts: [],
        }),
      );
    await http()
      .get('/mvp/account')
      .set('Authorization', authA)
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({ balanceMinor: '1', revision: '1' }),
      );
  });

  it('rolls back a future base and lets a valid intent open the account', async () => {
    const auth = await register();
    const key = randomUUID();
    await open(auth, key, {
      ...opening,
      baseMinor: '9223372036854775808',
    }).expect(400);
    await open(auth, key, {
      ...opening,
      baseMinor: '0',
      coverageStart: '2099-01-01T00:00:00Z',
    }).expect(400);
    await http().get('/accounts').set('Authorization', auth).expect(200, []);
    await open(auth, key, { ...opening, baseMinor: '0' }).expect(201);
  });

  it('reads inclusive microsecond coverage and one committed revision in exact cents', async () => {
    // A SQL-only fixture creates qualifying movements before marking the account active.
    // The public account flow never adopts an account with movements.
    const auth = await register();
    const response = await http()
      .get('/mvp/account')
      .set('Authorization', auth)
      .expect(200);
    const { principalId } = response.body as { principalId: string };
    const accountId = randomUUID();
    await pool.query(
      "INSERT INTO accounts (id,user_id,name,currency) VALUES ($1,$2,'Fixture','BRL')",
      [accountId, principalId],
    );
    const atBase = randomUUID();
    await pool.query(
      `
      INSERT INTO transactions (id,user_id,account_id,type,amount_minor,currency,occurred_at)
      VALUES ($1,$4,$5,'income',333,'BRL','2026-01-01T12:00:00Z'),
             ($2,$4,$5,'expense',5500,'BRL',$6),
             ($3,$4,$5,'income',666,'BRL','2099-01-01T00:00:00Z')`,
      [
        randomUUID(),
        atBase,
        randomUUID(),
        principalId,
        accountId,
        coverageStart,
      ],
    );
    await pool.query(
      `INSERT INTO mvp_accounts (user_id,account_id,base_minor,coverage_start,reference_zone)
      VALUES ($1,$2,9007199254800000,$3,$4)`,
      [principalId, accountId, coverageStart, opening.referenceZone],
    );
    await expect(
      pool.query('DELETE FROM transactions WHERE id = $1', [atBase]),
    ).rejects.toMatchObject({ constraint: 'mvp_transaction_writes_disabled' });
    await expect(
      pool.query('UPDATE transactions SET amount_minor = 1 WHERE id = $1', [
        atBase,
      ]),
    ).rejects.toMatchObject({ constraint: 'mvp_transaction_writes_disabled' });
    const writer = await pool.connect();
    try {
      await writer.query('BEGIN');
      await writer.query(
        'UPDATE mvp_accounts SET revision = 2, base_minor = base_minor + 1 WHERE user_id = $1',
        [principalId],
      );
      await expectBalance('9007199254794500', '1');
      await writer.query('COMMIT');
      await expectBalance('9007199254794501', '2');
    } finally {
      await writer.query('ROLLBACK');
      writer.release();
    }

    async function expectBalance(balanceMinor: string, revision: string) {
      await http()
        .get('/mvp/account')
        .set('Authorization', auth)
        .expect(200)
        .expect(({ body }) =>
          expect(body).toMatchObject({
            status: 'available',
            balanceMinor,
            revision,
          }),
        );
    }
  });

  it('registers at T0, rejects invalid dates and values, and reads an exact coherent history', async () => {
    const auth = await register();
    const other = await register();
    const opened = await open(auth, randomUUID(), {
      ...opening,
      baseMinor: '90000',
    }).expect(201);
    const accountId = (opened.body as { account: { id: string } }).account.id;
    const move = {
      ...legacyMove,
      accountId,
      expectedRevision: '1',
      description: 'Fictícia no corte',
    };
    const path = `/mvp/account/${accountId}/history`;
    await http().get(path).expect(401);
    await http().get(path).set('Authorization', other).expect(404);
    await postMvp(other, randomUUID(), move).expect(404);
    await postMvp(legacyAuth, randomUUID(), { ...move, accountId: legacyId })
      .expect(409)
      .expect(({ body }) =>
        expect(body).toMatchObject({ code: 'BASE_REQUIRED' }),
      );

    for (const invalid of [
      { occurredAt: '2026-01-01T12:00:00.000000Z' },
      { occurredAt: '2099-01-01T12:00:00.000000Z' },
      { occurredAt: '2026-01-01T12:00:00.0000001Z' },
      { currency: 'USD' },
      { amountMinor: 0 },
      { amountMinor: 1.1 },
      { amountMinor: 1_000_000_000 },
    ]) {
      await postMvp(auth, randomUUID(), { ...move, ...invalid }).expect(400);
    }
    await http()
      .get(path)
      .set('Authorization', auth)
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          summary: { balanceMinor: '90000', revision: '1' },
          entries: [],
        }),
      );
    const key = randomUUID();
    const posted = await postMvp(auth, key, move).expect(201);
    expect(posted.body).toMatchObject({
      occurredAt: coverageStart,
      amountMinor: '5500',
      revision: '2',
    });
    await postMvp(auth, randomUUID(), {
      ...move,
      expectedRevision: '2',
      type: 'income',
      amountMinor: 2500,
      clientMutationId: randomUUID(),
    }).expect(201);
    await postMvp(auth, key, move).expect(201, posted.body);
    const first = await http().get(path).set('Authorization', auth).expect(200);
    const second = await http()
      .get(path)
      .set('Authorization', auth)
      .expect(200);
    expect(first.body).toMatchObject({
      summary: { balanceMinor: '87000', revision: '3' },
      entries: [{ coverage: 'covered' }, { coverage: 'covered' }],
    });
    const entries = (first.body as { entries: Array<{ id: string }> }).entries;
    expect(entries.map(({ id }) => id)).toEqual(
      entries
        .map(({ id }) => id)
        .sort()
        .reverse(),
    );
    expect(second.body).toMatchObject({
      entries,
      summary: { balanceMinor: '87000', revision: '3' },
    });
    await http()
      .get(`/mvp/account/${legacyId}/history`)
      .set('Authorization', legacyAuth)
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          summary: {
            status: 'base_required',
            balanceMinor: null,
            revision: null,
          },
          entries: [{ coverage: 'no_base', amountMinor: '5500' }],
        }),
      );
  });

  it('serializes same-key replay and rejects an obsolete revision under contention', async () => {
    const auth = await register();
    const opened = await open(auth, randomUUID(), {
      ...opening,
      baseMinor: '0',
    }).expect(201);
    const accountId = (opened.body as { account: { id: string } }).account.id;
    const move = { ...legacyMove, accountId, expectedRevision: '1' };
    const key = randomUUID();
    const [a, replay, competitor] = await Promise.all([
      postMvp(auth, key, move),
      postMvp(auth, key.toUpperCase(), move),
      postMvp(auth, randomUUID(), { ...move, clientMutationId: randomUUID() }),
    ]);
    expect([a.status, competitor.status].sort()).toEqual([201, 409]);
    expect(replay.status).toBe(a.status);
    expect(replay.body).toEqual(a.body);
    expect((a.status === 409 ? a : competitor).body).toMatchObject({
      code: 'STALE_REVISION',
    });
    const winningKey = randomUUID();
    const next = { ...move, expectedRevision: '2' };
    await postMvp(auth, winningKey, next).expect(201);
    await postMvp(auth, winningKey, { ...next, description: 'Mudança' })
      .expect(409)
      .expect(({ body }) =>
        expect(body).toMatchObject({ code: 'IDEMPOTENCY_CONFLICT' }),
      );
    await postMove(auth, winningKey, { ...legacyMove, accountId }).expect(409);
    await http()
      .get(`/mvp/account/${accountId}/history`)
      .set('Authorization', auth)
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          summary: { revision: '3', balanceMinor: '-11000' },
          entries: [{}, {}],
        }),
      );
  });

  it('rolls back the movement and revision if creating the receipt fails', async () => {
    const auth = await register();
    const opened = await open(auth, randomUUID(), {
      ...opening,
      baseMinor: '90000',
    }).expect(201);
    const {
      account: { id: accountId },
      principalId,
    } = opened.body as {
      account: { id: string };
      principalId: string;
    };
    const move = { ...legacyMove, accountId, expectedRevision: '1' };
    const key = randomUUID();
    // A marked direct insert is insufficient: COMMIT requires its matching receipt.
    await expect(
      pool.query(
        `INSERT INTO transactions (id,user_id,account_id,type,amount_minor,currency,occurred_at,mvp_write_key,mvp_revision)
       VALUES ($1,$2,$3,'expense',5500,'BRL',$4,$5,2)`,
        [randomUUID(), principalId, accountId, coverageStart, key],
      ),
    ).rejects.toThrow(
      /requires its own receipt|violates foreign key constraint/,
    );
    await pool.query(`
      CREATE FUNCTION test_fail_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'injected receipt failure'; END; $$;
      CREATE TRIGGER test_fail_receipt BEFORE INSERT ON idempotency_keys
      FOR EACH ROW WHEN (NEW.response ? 'occurredAt') EXECUTE FUNCTION test_fail_receipt();
    `);
    try {
      await postMvp(auth, key, move).expect(503);
    } finally {
      await pool.query(
        'DROP TRIGGER test_fail_receipt ON idempotency_keys; DROP FUNCTION test_fail_receipt()',
      );
    }
    await http()
      .get(`/mvp/account/${accountId}/history`)
      .set('Authorization', auth)
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          summary: { balanceMinor: '90000', revision: '1' },
          entries: [],
        }),
      );
    expect(
      (
        await pool.query(
          'SELECT 1 FROM idempotency_keys WHERE idempotency_key = $1',
          [key],
        )
      ).rowCount,
    ).toBe(0);
    const retry = await postMvp(auth, key, move).expect(201);
    await postMvp(auth, key, move).expect(201, retry.body);
  });

  it.each([true, false])(
    'pages tied timestamps and invalidates a changed snapshot (MVP active: %s)',
    async (active) => {
      const auth = await register();
      const identity = await http()
        .get('/mvp/account')
        .set('Authorization', auth)
        .expect(200);
      const { principalId } = identity.body as { principalId: string };
      const accountId = randomUUID();
      const client = await pool.connect();
      try {
        // Use the legacy SQL fixture to test pagination over earlier data.
        await client.query('BEGIN');
        await client.query(
          "INSERT INTO accounts (id,user_id,name,currency) VALUES ($1,$2,'Fictícia','BRL')",
          [accountId, principalId],
        );
        await client.query(
          `
        INSERT INTO transactions (id,user_id,account_id,type,amount_minor,currency,occurred_at)
        SELECT gen_random_uuid(),$1,$2,'expense',1,'BRL',$3 FROM generate_series(1,51)
      `,
          [principalId, accountId, coverageStart],
        );
        if (active) {
          await client.query(
            `INSERT INTO mvp_accounts (user_id,account_id,base_minor,coverage_start,reference_zone)
           VALUES ($1,$2,90000,$3,$4)`,
            [principalId, accountId, coverageStart, opening.referenceZone],
          );
        }
        await client.query('COMMIT');
      } finally {
        client.release();
      }
      const getPage = () =>
        http()
          .get(`/mvp/account/${accountId}/history`)
          .set('Authorization', auth);
      type Page = {
        summary: { asOf: string };
        entries: Array<{ id: string }>;
        nextCursor: string;
      };
      const first = (await getPage().expect(200)).body as Page;
      expect(first.entries).toHaveLength(50);
      const next = (
        await getPage().query({ cursor: first.nextCursor }).expect(200)
      ).body as Page;
      expect(next.entries).toHaveLength(1);
      expect(next.entries[0].id).not.toBe(first.entries[49].id);
      expect(next.entries[0].id < first.entries[49].id).toBe(true);
      expect(next.summary.asOf).toBe(first.summary.asOf);
      if (active) {
        await postMvp(auth, randomUUID(), {
          ...legacyMove,
          accountId,
          expectedRevision: '1',
        }).expect(201);
      } else {
        await postMove(auth, randomUUID(), { ...legacyMove, accountId }).expect(
          201,
        );
      }
      await getPage()
        .query({ cursor: first.nextCursor })
        .expect(409)
        .expect(({ body }) =>
          expect(body).toMatchObject({ code: 'STALE_REVISION' }),
        );
    },
  );

  async function readLegacyRows() {
    const { rows } = await pool.query<Record<string, unknown>>(
      `
      SELECT to_jsonb(a) AS account, to_jsonb(t) - ARRAY['mvp_write_key', 'mvp_revision', 'occurrence_day', 'occurrence_zone',
        'latest_occurrence_at', 'mvp_recovery_id'] AS movement, to_jsonb(i) AS receipt
      FROM accounts a
      JOIN transactions t ON t.user_id = a.user_id AND t.account_id = a.id
      JOIN idempotency_keys i ON i.user_id = a.user_id AND i.idempotency_key = $2
      WHERE a.id = $1`,
      [legacyId, legacyKey],
    );
    return rows;
  }

  function http() {
    return request(app.getHttpServer());
  }

  async function register() {
    const response = await http()
      .post('/auth/register')
      .set('X-Forwarded-For', `192.0.2.${++fixtureIP}`)
      .send({
        email: `${randomUUID()}@example.test`,
        password: 'disposable fake password',
      })
      .expect(201);
    return `Bearer ${(response.body as { accessToken: string }).accessToken}`;
  }

  function open(auth: string, key: string, terms: Record<string, unknown>) {
    return http()
      .post('/mvp/account')
      .set('Authorization', auth)
      .set('Idempotency-Key', key)
      .send(terms);
  }

  function postMove(auth: string, key: string, terms: Record<string, unknown>) {
    return http()
      .post('/transactions')
      .set('Authorization', auth)
      .set('Idempotency-Key', key)
      .send(terms);
  }

  function postMvp(auth: string, key: string, terms: Record<string, unknown>) {
    return http()
      .post('/mvp/transactions')
      .set('Authorization', auth)
      .set('Idempotency-Key', key)
      .send(terms);
  }
});
