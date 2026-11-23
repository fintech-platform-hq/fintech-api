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

  async function readLegacyRows() {
    const { rows } = await pool.query<Record<string, unknown>>(
      `
      SELECT to_jsonb(a) AS account, to_jsonb(t) AS movement, to_jsonb(i) AS receipt
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
});
