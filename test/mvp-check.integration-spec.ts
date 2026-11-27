import { INestApplication, ValidationPipe } from '@nestjs/common';
import { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Pool } from 'pg';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from '../src/app.module';
import type { MvpAccountSummary } from '../src/modules/accounts/mvp-account.service';
import type {
  AuditReceipt,
  MvpAuditService,
} from '../src/modules/accounts/mvp-audit.service';
import type {
  MvpCheckEntry,
  MvpCheckReceipt,
} from '../src/modules/accounts/mvp-check.service';
import type { RecoveryReceipt } from '../src/modules/accounts/mvp-recovery.service';
import type { MvpTransactionReceipt } from '../src/modules/transactions/dto/mvp-transaction.dto';

type AuditPreview = Awaited<ReturnType<MvpAuditService['preview']>>;
type CheckPage = { summary: MvpAccountSummary; entries: MvpCheckEntry[] };

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

  async function open(
    baseMinor = '90000',
    coverageStart = baseAt,
    referenceZone = 'America/Sao_Paulo',
  ) {
    const email = `i2-${randomUUID()}@example.test`;
    const auth = await http()
      .post('/auth/register')
      .set('X-Forwarded-For', `192.0.2.${++fixtureIP}`)
      .send({
        email,
        password: 'fictional i2 password',
      })
      .expect(201);
    await pool.query(
      'UPDATE users SET email_verified_at = now() WHERE email = $1',
      [email],
    );
    const authorization = `Bearer ${(auth.body as { accessToken: string }).accessToken}`;
    const response = await http()
      .post('/mvp/account')
      .set('Authorization', authorization)
      .set('Idempotency-Key', randomUUID())
      .send({
        baseMinor,
        coverageStart,
        referenceZone,
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

  function baseAudit(a: Awaited<ReturnType<typeof open>>) {
    return {
      input: (action: string, fields = {}) => ({
        accountId: a.id,
        targetId: a.id,
        action,
        reason: 'Fictitious base review',
        ...fields,
      }),
      preview: (input: object) =>
        http()
          .post('/mvp/audit-previews')
          .set('Authorization', a.authorization)
          .send(input),
      confirm: (
        input: object,
        preview: AuditPreview,
        key = randomUUID(),
        confirmed = true,
      ) =>
        http()
          .post('/mvp/audited-changes')
          .set('Authorization', a.authorization)
          .set('Idempotency-Key', key)
          .send({
            ...input,
            expectedRevision: preview.revision,
            previewToken: preview.previewToken,
            confirmed,
          }),
      versions: () =>
        http()
          .get(`/mvp/account/${a.id}/base-versions`)
          .set('Authorization', a.authorization),
      history: () =>
        http()
          .get(`/mvp/account/${a.id}/history`)
          .set('Authorization', a.authorization),
    };
  }

  it('I5 S10 suspends, corrects, replays and preserves original values and ownership', async () => {
    const a = await open();
    const b = await open();
    const audit = baseAudit(a);
    await a.move('1', 5500, baseAt).expect(201);
    const original = (await a.confirm('2').expect(201)).body as MvpCheckReceipt;
    await a.move('3', 1800, afterCheck).expect(201);

    const suspend = audit.input('suspend_base');
    const suspension = (await audit.preview(suspend).expect(200))
      .body as AuditPreview;
    expect(suspension).toMatchObject({
      revision: '4',
      balanceMinor: '82700',
      projectedBalanceMinor: null,
    });
    await audit.confirm(suspend, suspension, randomUUID(), false).expect(400);
    const suspensionKey = randomUUID();
    const suspendedReceipt = (
      await audit.confirm(suspend, suspension, suspensionKey).expect(201)
    ).body as AuditReceipt;
    await a
      .preview()
      .expect(409)
      .expect(({ body }) =>
        expect((body as { code: string }).code).toBe('BASE_SUSPENDED'),
      );
    await a
      .move('5', 1, baseAt)
      .expect(409)
      .expect(({ body }) =>
        expect((body as { code: string }).code).toBe('BASE_SUSPENDED'),
      );
    await a
      .list()
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          summary: {
            status: 'unavailable',
            baseSuspended: true,
            balanceMinor: null,
          },
          entries: [
            {
              originalCalculatedMinor: '84500',
              originalDifferenceMinor: '4500',
              remainingDifferenceMinor: null,
              resolutionStatus: 'unavailable',
            },
          ],
        }),
      );
    await a
      .list({ view: 'pending' })
      .expect(200)
      .expect(({ body }) => expect((body as CheckPage).entries).toEqual([]));

    const change = audit.input('correct_base', { baseMinor: '91000' });
    const preview = (await audit.preview(change).expect(200))
      .body as AuditPreview;
    expect(preview).toMatchObject({
      revision: '5',
      balanceMinor: null,
      projectedBalanceMinor: '83700',
      previousCoverageStart: baseAt,
      proposedCoverageStart: baseAt,
      coverageChanges: [],
      checks: [
        {
          id: original.id,
          originalDifferenceMinor: '4500',
          beforeMinor: null,
          afterMinor: '5500',
        },
      ],
    });
    const foreign = baseAudit(b);
    await foreign.preview(change).expect(404);
    await foreign.confirm(change, preview).expect(404);
    await http()
      .get(`/mvp/account/${a.id}/base-versions`)
      .set('Authorization', b.authorization)
      .expect(404);
    const key = randomUUID();
    const [first, replay] = await Promise.all([
      audit.confirm(change, preview, key).expect(201),
      audit.confirm(change, preview, key).expect(201),
    ]);
    expect(replay.body).toEqual(first.body);
    await audit
      .confirm(suspend, suspension, suspensionKey)
      .expect(201, suspendedReceipt);
    await audit
      .confirm({ ...change, baseMinor: '92000' }, preview, key)
      .expect(409)
      .expect(({ body }) =>
        expect((body as { code: string }).code).toBe('IDEMPOTENCY_CONFLICT'),
      );
    await audit
      .confirm(change, preview)
      .expect(409)
      .expect(({ body }) =>
        expect((body as { code: string }).code).toBe('STALE_REVISION'),
      );
    await a
      .list()
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          summary: { revision: '6', balanceMinor: '83700' },
          entries: [
            {
              ...original,
              calculatedAtReferenceMinor: '85500',
              remainingDifferenceMinor: '5500',
            },
          ],
        }),
      );
    await audit
      .versions()
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject([
          {
            ...(first.body as AuditReceipt),
            baseMinor: '91000',
            authorId: a.principalId,
          },
          { ...suspendedReceipt, baseMinor: '90000' },
          {
            action: 'original',
            revision: '1',
            baseMinor: '90000',
            reason: null,
          },
        ]),
      );

    for (const revision of ['6', '7', '8']) {
      await a.move(revision, 1, afterCheck).expect(201);
    }
    const secondChange = audit.input('correct_base', { baseMinor: '92000' });
    const secondPreview = (await audit.preview(secondChange).expect(200))
      .body as AuditPreview;
    await audit.confirm(secondChange, secondPreview).expect(201);
    await audit
      .versions()
      .expect(200)
      .expect(({ body }) => {
        const versions = body as { revision: string }[];
        expect(versions.map(({ revision }) => revision)).toEqual([
          '10',
          '6',
          '5',
          '1',
        ]);
      });
  });

  it('I5 requires a known instant when T0 crosses a day, then reclassifies coverage inclusively', async () => {
    const a = await open();
    const audit = baseAudit(a);
    const first = (await a.move('1', 5500, baseAt).expect(201))
      .body as MvpTransactionReceipt;
    const old = (await a.confirm('2').expect(201)).body as MvpCheckReceipt;
    const lateCut = '2026-01-04T12:00:00.000001Z';
    const later = (
      await a.confirm('3', randomUUID(), { referenceAt: lateCut }).expect(201)
    ).body as MvpCheckReceipt;
    const dateOnly = (
      await http()
        .post('/mvp/recoveries')
        .set('Authorization', a.authorization)
        .set('Idempotency-Key', randomUUID())
        .send({
          accountId: a.id,
          checkId: later.id,
          action: 'create',
          expectedRevision: '4',
          amountMinor: '1000',
          day: '2026-01-03',
          evidence: 'Fictitious receipt',
        })
        .expect(201)
    ).body as RecoveryReceipt;
    const newStart = '2026-01-03T12:00:00.000001Z';
    const change = audit.input('correct_base', {
      baseMinor: '84500',
      coverageStart: newStart,
    });
    const suspended = audit.input('suspend_base');
    const suspension = (await audit.preview(suspended).expect(200))
      .body as AuditPreview;
    await audit.confirm(suspended, suspension).expect(201);
    const blocked = (await audit.preview(change).expect(200))
      .body as AuditPreview;
    expect(blocked).toMatchObject({
      previewToken: null,
      projectedBalanceMinor: null,
      ambiguousMovementIds: [dateOnly.transactionId],
      coverageChanges: [
        { id: first.id, after: 'before_base' },
        { id: dateOnly.transactionId, after: 'ambiguous' },
      ],
    });
    const refinement = audit.input('refine_occurrence', {
      targetId: dateOnly.transactionId,
      occurredAt: newStart,
    });
    await audit.preview({ ...refinement, occurredAt: lateCut }).expect(400);
    const reviewed = (await audit.preview(refinement).expect(200))
      .body as AuditPreview;
    await audit.confirm(refinement, reviewed).expect(201);
    const preview = (await audit.preview(change).expect(200))
      .body as AuditPreview;
    expect(preview).toMatchObject({
      projectedBalanceMinor: '83500',
      ambiguousMovementIds: [],
      coverageChanges: [{ id: first.id, after: 'before_base' }],
    });
    await audit.confirm(change, preview).expect(201);
    await audit
      .history()
      .expect(200)
      .expect(({ body }) =>
        expect((body as CheckPage).entries).toMatchObject([
          {
            id: dateOnly.transactionId,
            coverage: 'covered',
            occurrenceDay: null,
            occurredAt: newStart,
          },
          { id: first.id, coverage: 'before_base' },
        ]),
      );
    const checks = ((await a.list().expect(200)).body as CheckPage).entries;
    expect(checks).toMatchObject([
      { id: later.id, remainingDifferenceMinor: '3500' },
      {
        id: old.id,
        originalDifferenceMinor: '4500',
        calculatedAtReferenceMinor: null,
        remainingDifferenceMinor: null,
        status: 'unavailable',
        resolutionStatus: 'unavailable',
      },
    ]);
  });

  it('I5 rolls back a version when its receipt fails and serializes across check and base writers', async () => {
    const a = await open();
    const audit = baseAudit(a);
    const change = audit.input('correct_base', {
      baseMinor: '-9223372036854775808',
    });
    await a.move('1', 1, baseAt).expect(201);
    const preview = (await audit.preview(change).expect(200))
      .body as AuditPreview;
    expect(preview.projectedBalanceMinor).toBe('-9223372036854775809');

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const key = randomUUID();
      await client.query(
        `INSERT INTO mvp_base_versions
        (id,user_id,account_id,revision,action,base_minor,coverage_start,reason,write_key)
        VALUES ($1,$2,$3,3,'correct_base',-1,$4,'Fictitious rollback',$5)`,
        [randomUUID(), a.principalId, a.id, baseAt, key],
      );
      await client.query(
        "INSERT INTO idempotency_keys (id,user_id,idempotency_key,request_hash,response) VALUES ($1,$2,$3,'fixture','{}')",
        [randomUUID(), a.principalId, key],
      );
      await audit
        .history()
        .expect(200)
        .expect(({ body }) =>
          expect((body as CheckPage).summary).toMatchObject({
            balanceMinor: '89999',
            revision: '2',
          }),
        );
      await expect(client.query('COMMIT')).rejects.toMatchObject({
        code: '23514',
      });
    } finally {
      await client.query('ROLLBACK');
      client.release();
    }
    await audit
      .versions()
      .expect(200)
      .expect(({ body }) => expect(body).toHaveLength(1));
    const concurrent = await Promise.all([
      a.confirm('2'),
      audit.confirm(change, preview),
    ]);
    expect(concurrent.map((result) => result.status).sort()).toEqual([
      201, 409,
    ]);
    await audit
      .history()
      .expect(200)
      .expect(({ body }) =>
        expect((body as CheckPage).summary.revision).toBe('3'),
      );
  });

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
  async function recoveryFixture() {
    const a = await open('90000', '2026-11-14T12:00:00Z');
    await a.move('1', 5500, '2026-11-14T12:00:00Z').expect(201);
    const referenceAt = '2026-11-18T12:00:00Z';
    const check = await a
      .confirm('2', randomUUID(), { referenceAt })
      .expect(201);
    await a.move('3', 1800, '2026-11-18T12:10:00Z').expect(201);
    const input = {
      accountId: a.id,
      checkId: (check.body as { id: string }).id,
      amountMinor: '2500',
      day: '2026-11-15',
      occurredAt: '2026-11-15T15:00:00Z',
      description: 'Padaria',
    };
    const preview = (changes = {}) =>
      http()
        .post('/mvp/recovery-previews')
        .set('Authorization', a.authorization)
        .send({ ...input, ...changes });
    const recover = (changes = {}, key = randomUUID()) =>
      http()
        .post('/mvp/recoveries')
        .set('Authorization', a.authorization)
        .set('Idempotency-Key', key)
        .send({
          ...input,
          expectedRevision: '4',
          evidence: 'Compra identificada no comprovante',
          action: 'create',
          ...changes,
        });
    const ledger = () =>
      pool
        .query<{
          movements: number;
          recoveries: number;
          receipts: number;
          revision: string;
        }>(
          `SELECT (SELECT count(*)::int FROM transactions WHERE account_id = $1) AS movements,
          (SELECT count(*)::int FROM mvp_expense_recoveries WHERE account_id = $1) AS recoveries,
          (SELECT count(*)::int FROM idempotency_keys WHERE response->>'accountId' = $1::uuid::text
            AND response ? 'transactionId') AS receipts,
          (SELECT revision::text FROM mvp_accounts WHERE account_id = $1) AS revision`,
          [a.id],
        )
        .then(({ rows }) => rows[0]);
    return { a, input, preview, recover, ledger };
  }

  it('S03 keeps the original and resolves only the identified R$25 and R$20 expenses', async () => {
    const { a, input, preview, recover, ledger } = await recoveryFixture();
    await a
      .list()
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          summary: { balanceMinor: '82700' },
          entries: [
            { remainingDifferenceMinor: '4500', resolutionStatus: 'open' },
          ],
        }),
      );
    await preview()
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          revision: '4',
          dateStatus: 'eligible',
          candidates: [],
        }),
      );
    const first = await recover().expect(201);
    await a
      .list()
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          summary: { balanceMinor: '80200', revision: '5' },
          entries: [
            {
              originalCalculatedMinor: '84500',
              observedMinor: '80000',
              originalDifferenceMinor: '4500',
              calculatedAtReferenceMinor: '82000',
              remainingDifferenceMinor: '2000',
              resolutionStatus: 'partially_explained',
            },
          ],
        }),
      );
    await recover({
      expectedRevision: '5',
      amountMinor: '2000',
      day: '2026-11-16',
      occurredAt: '2026-11-16T15:00:00Z',
      description: 'Segunda despesa',
    }).expect(201);
    await a
      .list()
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          summary: { balanceMinor: '78200', revision: '6' },
          entries: [
            {
              originalCalculatedMinor: '84500',
              observedMinor: '80000',
              originalDifferenceMinor: '4500',
              remainingDifferenceMinor: '0',
              calculatedAtReferenceMinor: '80000',
              status: 'coincident',
              resolutionStatus: 'resolved',
            },
          ],
        }),
      );
    await a
      .list({ view: 'pending' })
      .expect(200)
      .expect(({ body }) => expect(body).toMatchObject({ entries: [] }));
    const audit = await pool.query<{
      user_id: string;
      transaction_id: string;
      declaration: unknown;
      evidence: string;
    }>(
      'SELECT user_id, transaction_id, declaration, evidence FROM mvp_expense_recoveries WHERE check_id = $1 ORDER BY mvp_revision',
      [input.checkId],
    );
    expect(audit.rows[0]).toMatchObject({
      user_id: a.principalId,
      transaction_id: (first.body as { transactionId: string }).transactionId,
      evidence: 'Compra identificada no comprovante',
      declaration: {
        amountMinor: '2500',
        day: '2026-11-15',
        occurredAt: '2026-11-15T15:00:00.000000Z',
      },
    });
    expect(await ledger()).toEqual({
      movements: 4,
      recoveries: 2,
      receipts: 2,
      revision: '6',
    });
  });

  it('assigns zero delta to a linked movement included in the original check', async () => {
    const { a, recover, ledger } = await recoveryFixture();
    const {
      rows: [original],
    } = await pool.query<{ id: string }>(
      'SELECT id FROM transactions WHERE account_id = $1 AND amount_minor = 5500',
      [a.id],
    );
    await recover({
      action: 'link',
      transactionId: original.id,
      amountMinor: '5500',
      day: '2026-11-14',
      occurredAt: '2026-11-14T12:00:00Z',
    }).expect(201);
    await a
      .list()
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          summary: { balanceMinor: '82700' },
          entries: [
            { remainingDifferenceMinor: '4500', resolutionStatus: 'open' },
          ],
        }),
      );
    expect(await ledger()).toEqual({
      movements: 2,
      recoveries: 1,
      receipts: 1,
      revision: '5',
    });
  });

  it('S04 preserves an inverted residue and distinguishes unlinked numeric coincidence', async () => {
    const inverted = await recoveryFixture();
    await inverted.recover({ amountMinor: '5000' }).expect(201);
    await inverted.a
      .list({ view: 'pending' })
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          summary: { balanceMinor: '77700' },
          entries: [
            { remainingDifferenceMinor: '-500', resolutionStatus: 'open' },
          ],
        }),
      );
    const coincident = await recoveryFixture();
    await coincident.a.move('4', 4500, coincident.input.occurredAt).expect(201);
    await coincident.a
      .list()
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          entries: [
            {
              remainingDifferenceMinor: '0',
              resolutionStatus: 'coincident',
              originalDifferenceMinor: '4500',
            },
          ],
        }),
      );
  });

  it('S05 preview and deferral have no effects; history link and distinct purchase require explicit confirmation', async () => {
    const { a, input, preview, recover, ledger } = await recoveryFixture();
    const same = await a.move('4', 2500, input.occurredAt).expect(201);
    const sameID = (same.body as { id: string }).id;
    const similar = await a.move('5', 2500, '2026-11-15T17:00:00Z').expect(201);
    const similarID = (similar.body as { id: string }).id;
    await preview()
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          revision: '6',
          candidates: [{ id: similarID }, { id: sameID }],
        }),
      );
    expect(await ledger()).toEqual({
      movements: 4,
      recoveries: 0,
      receipts: 0,
      revision: '6',
    });
    await recover({ action: undefined, expectedRevision: '6' }).expect(400);
    await recover({ action: 'link', expectedRevision: '6' }).expect(400);
    await recover({
      action: 'link',
      transactionId: sameID,
      expectedRevision: '6',
      amountMinor: '2400',
    }).expect(201);
    await a
      .list()
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          summary: { balanceMinor: '77700', revision: '7' },
          entries: [{ remainingDifferenceMinor: '-500' }],
        }),
      );
    await recover({
      action: 'link',
      transactionId: sameID,
      expectedRevision: '7',
    })
      .expect(409)
      .expect(({ body }) =>
        expect(body).toMatchObject({ code: 'MOVEMENT_ALREADY_LINKED' }),
      );

    const separate = await recoveryFixture();
    await separate.a.move('4', 2500, separate.input.occurredAt).expect(201);
    await separate
      .preview()
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          revision: '5',
          candidates: [expect.objectContaining({ amountMinor: '2500' })],
        }),
      );
    expect(await separate.ledger()).toEqual({
      movements: 3,
      recoveries: 0,
      receipts: 0,
      revision: '5',
    });
    await separate.recover({ expectedRevision: '5' }).expect(201);
    await separate.a
      .list()
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          summary: { balanceMinor: '77700' },
          entries: [{ remainingDifferenceMinor: '-500' }],
        }),
      );
  });

  it('S05/S07 serializes stable reference replays and rejects incompatible targets and stale unreferenced previews', async () => {
    const { a, input, recover, ledger, preview } = await recoveryFixture();
    const reference = {
      externalSource: 'bank-a',
      externalReference: 'genuine-reference-1',
    };
    await recover({ externalSource: 'bank-a' }).expect(400);
    const key = randomUUID();
    const [a1, a2, b1] = await Promise.all([
      recover(reference, key).expect(201),
      recover(reference, key).expect(201),
      recover(reference).expect(201),
    ]);
    expect(a1.body).toEqual(a2.body);
    expect(a1.body).toEqual(b1.body);
    expect(await ledger()).toEqual({
      movements: 3,
      recoveries: 1,
      receipts: 2,
      revision: '5',
    });
    await preview(reference)
      .expect(200)
      .expect(({ body }) =>
        expect(
          (body as { existingRecovery: unknown }).existingRecovery,
        ).toEqual(a1.body),
      );
    await recover({ ...reference, amountMinor: '2000' })
      .expect(409)
      .expect(({ body }) =>
        expect(body).toMatchObject({ code: 'EXTERNAL_REFERENCE_CONFLICT' }),
      );
    await recover({ ...reference, amountMinor: '2000' }, key)
      .expect(409)
      .expect(({ body }) =>
        expect(body).toMatchObject({ code: 'IDEMPOTENCY_CONFLICT' }),
      );
    await recover()
      .expect(409)
      .expect(({ body }) =>
        expect(body).toMatchObject({ code: 'STALE_REVISION' }),
      );
    const other = await a.move('5', 2500, input.occurredAt).expect(201);
    await recover({
      ...reference,
      action: 'link',
      transactionId: (other.body as { id: string }).id,
      expectedRevision: '6',
    })
      .expect(409)
      .expect(({ body }) =>
        expect(body).toMatchObject({ code: 'EXTERNAL_REFERENCE_CONFLICT' }),
      );
    await recover({
      ...reference,
      action: 'link',
      transactionId: (a1.body as { transactionId: string }).transactionId,
      expectedRevision: '6',
    })
      .expect(201)
      .expect(({ body }) => expect(body).toEqual(a1.body));
  });

  it('allows one winner when clients race to use the same reference for incompatible expenses', async () => {
    const { recover, ledger } = await recoveryFixture();
    const reference = {
      externalSource: 'bank-a',
      externalReference: 'racing-provider-id',
    };
    const replies = await Promise.all([
      recover(reference),
      recover({ ...reference, amountMinor: '2600' }),
    ]);
    expect(replies.map(({ status }) => status).sort()).toEqual([201, 409]);
    expect(replies.find(({ status }) => status === 409)?.body).toMatchObject({
      code: 'EXTERNAL_REFERENCE_CONFLICT',
    });
    expect(await ledger()).toEqual({
      movements: 3,
      recoveries: 1,
      receipts: 1,
      revision: '5',
    });
  });

  it('S09 rolls back before the recovery link, then serializes a retry against another confirmation', async () => {
    const { recover, ledger, a } = await recoveryFixture();
    const old = await ledger();
    await pool.query(`CREATE FUNCTION i3_fail_link() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'injected link failure'; END $$;
      CREATE TRIGGER i3_fail_link BEFORE INSERT ON mvp_expense_recoveries
      FOR EACH ROW EXECUTE FUNCTION i3_fail_link();`);
    const key = randomUUID();
    try {
      await recover({}, key).expect(503);
      expect(await ledger()).toEqual(old);
    } finally {
      await pool.query(
        'DROP TRIGGER i3_fail_link ON mvp_expense_recoveries; DROP FUNCTION i3_fail_link()',
      );
    }
    const [first, concurrent] = await Promise.all([
      recover({}, key),
      a.confirm('4', randomUUID(), { referenceAt: '2026-11-19T12:00:00Z' }),
    ]);
    expect([first.status, concurrent.status].sort()).toEqual([201, 409]);
    if (first.status === 201) {
      await recover({}, key)
        .expect(201)
        .expect(({ body }) => expect(body).toEqual(first.body));
    } else {
      await recover({ expectedRevision: '5' }).expect(201);
    }
    expect((await ledger()).recoveries).toBe(1);
  });

  it('isolates candidates, selected transaction IDs, checks and external references between holders', async () => {
    const a = await recoveryFixture();
    const b = await recoveryFixture();
    const reference = {
      externalSource: 'bank-a',
      externalReference: 'same-provider-id',
    };
    const first = await a.recover(reference).expect(201);
    await b
      .preview({ ...reference, accountId: a.a.id, checkId: a.input.checkId })
      .expect(404);
    await b.preview({ checkId: a.input.checkId }).expect(404);
    await b
      .recover({
        action: 'link',
        transactionId: (first.body as { transactionId: string }).transactionId,
      })
      .expect(404);
    await b
      .preview(reference)
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          candidates: [],
          existingRecovery: null,
        }),
      );
    await b.recover(reference).expect(201);
    await http().post('/mvp/recovery-previews').send(a.input).expect(401);
  });

  it('S11 freezes day precision and rejects cuts whose inclusion depends on an unknown time', async () => {
    const { a, preview, recover, ledger } = await recoveryFixture();
    await preview({ day: '2026-11-14', occurredAt: null })
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({ dateStatus: 'time_required' }),
      );
    await preview({ day: '2026-11-18', occurredAt: null })
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          dateStatus: 'time_required',
          ambiguousCheckIds: [expect.any(String)],
        }),
      );
    await recover({ day: '2026-11-18', occurredAt: null })
      .expect(409)
      .expect(({ body }) =>
        expect(body).toMatchObject({ code: 'OCCURRENCE_TIME_REQUIRED' }),
      );
    await preview({ day: '2026-11-13', occurredAt: null })
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({ dateStatus: 'outside_coverage' }),
      );
    await preview({
      day: '2026-11-18',
      occurredAt: '2026-11-18T12:00:00.000001Z',
    })
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({ dateStatus: 'after_check' }),
      );
    await preview({
      day: '2026-11-18',
      occurredAt: '2026-11-18T12:00:00.000000Z',
    })
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({ dateStatus: 'eligible' }),
      );
    const noTime = await recover({
      occurredAt: null,
      amountMinor: '1000',
    }).expect(201);
    const { transactionId } = noTime.body as { transactionId: string };
    await http()
      .get(`/mvp/account/${a.id}/history`)
      .set('Authorization', a.authorization)
      .expect(200)
      .expect(({ body }) => {
        const history = body as {
          entries: {
            id: string;
            occurrenceDay?: string;
            occurrenceZone?: string;
          }[];
        };
        expect(
          history.entries.find((entry) => entry.id === transactionId),
        ).toMatchObject({
          occurrenceDay: '2026-11-15',
          occurrenceZone: 'America/Sao_Paulo',
        });
      });
    const inDay = { referenceAt: '2026-11-15T15:00:00Z' };
    await a
      .preview(inDay)
      .expect(409)
      .expect(({ body }) =>
        expect(body).toMatchObject({ code: 'OCCURRENCE_TIME_REQUIRED' }),
      );
    await a.confirm('5', randomUUID(), inDay).expect(409);
    await a.preview({ referenceAt: '2026-11-16T02:59:59.999998Z' }).expect(409);
    await a.preview({ referenceAt: '2026-11-16T02:59:59.999999Z' }).expect(200);
    await a.preview({ referenceAt: '2026-11-15T02:59:59.999999Z' }).expect(200);
    expect((await ledger()).revision).toBe('5');
    await a
      .list()
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          entries: [
            {
              remainingDifferenceMinor: '3500',
              resolutionStatus: 'partially_explained',
            },
          ],
        }),
      );
  });

  it('freezes civil days across 23-hour and 25-hour transitions and an offset change at midnight', async () => {
    const { rows } = await pool.query<{ hours: number; start: string }>(
      `SELECT extract(epoch FROM mvp_civil_day_start(day + 1, zone) - mvp_civil_day_start(day, zone))::int / 3600 AS hours,
         to_char(mvp_civil_day_start(day, zone) AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI') AS start
       FROM (VALUES ('2026-03-08'::date, 'America/New_York'), ('2026-11-01', 'America/New_York'),
         ('2026-11-01', 'America/Havana'), ('2018-11-04', 'America/Sao_Paulo')) AS days(day, zone)`,
    );
    expect(rows).toEqual([
      { hours: 23, start: '2026-03-08 05:00' },
      { hours: 25, start: '2026-11-01 04:00' },
      { hours: 25, start: '2026-11-01 04:00' },
      { hours: 23, start: '2018-11-04 03:00' },
    ]);
  });
  async function auditedFixture() {
    const { a, recover, input } = await recoveryFixture();
    const bakery = (await recover().expect(201)).body as {
      transactionId: string;
    };
    const other = (
      await recover({
        amountMinor: '2000',
        day: '2026-11-16',
        occurredAt: '2026-11-16T15:00:00Z',
        expectedRevision: '5',
      }).expect(201)
    ).body as { transactionId: string };
    const change = {
      accountId: a.id,
      targetId: bakery.transactionId,
      action: 'correct',
      amountMinor: '2400',
      reason: 'Valor conferido no recibo',
    };
    const preview = (body: object) =>
      http()
        .post('/mvp/audit-previews')
        .set('Authorization', a.authorization)
        .send(body);
    const review = async (body: object) => {
      const result = await preview(body).expect(200);
      const terms = result.body as { revision: string; previewToken: string };
      return {
        ...body,
        expectedRevision: terms.revision,
        previewToken: terms.previewToken,
      };
    };
    const confirm = (body: object, key = randomUUID()) =>
      http()
        .post('/mvp/audited-changes')
        .set('Authorization', a.authorization)
        .set('Idempotency-Key', key)
        .send(body);
    const versions = (auth = a.authorization) =>
      http()
        .get(`/mvp/account/${a.id}/history/${bakery.transactionId}/versions`)
        .set('Authorization', auth);
    return {
      a,
      bakery,
      other,
      change,
      preview,
      review,
      confirm,
      versions,
      checkId: input.checkId,
    };
  }

  it('I4 S03/S09 serializes corrections and checks, preserves originals and replays the winner', async () => {
    const { a, change, preview, review, confirm, versions, checkId } =
      await auditedFixture();
    await preview(change)
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          balanceMinor: '78200',
          projectedBalanceMinor: '78300',
          revision: '6',
          checks: [
            {
              id: checkId,
              originalDifferenceMinor: '4500',
              beforeMinor: '0',
              afterMinor: '100',
            },
          ],
        }),
      );
    const winner = await review(change);
    const loser = await review({ ...change, amountMinor: '2300' });
    await confirm({ ...winner, previewToken: '0'.repeat(64) })
      .expect(409)
      .expect(({ body }) =>
        expect(body).toMatchObject({ code: 'AUDIT_PREVIEW_REQUIRED' }),
      );

    const gate = await pool.connect();
    const key = randomUUID();
    await pool.query(`CREATE FUNCTION i4_wait_version() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN IF NEW.amount_minor = 2400 THEN PERFORM pg_advisory_xact_lock(94124); END IF; RETURN NEW; END $$;
      CREATE TRIGGER i4_wait_version AFTER INSERT ON mvp_movement_versions
      FOR EACH ROW EXECUTE FUNCTION i4_wait_version();`);
    let result: object;
    try {
      await gate.query('SELECT pg_advisory_lock(94124)');
      const first = confirm(winner, key)
        .expect(201)
        .then(({ body }) => body as object);
      let waiting = false;
      for (let attempt = 0; attempt < 100 && !waiting; attempt++) {
        const { rowCount } = await pool.query(
          "SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND objid = 94124 AND NOT granted",
        );
        waiting = Boolean(rowCount);
        if (!waiting) await new Promise((resolve) => setTimeout(resolve, 15));
      }
      await a
        .list()
        .expect(200)
        .expect(({ body }) =>
          expect(body).toMatchObject({
            summary: { revision: '6', balanceMinor: '78200' },
            entries: [{ remainingDifferenceMinor: '0' }],
          }),
        );
      const second = confirm(loser)
        .expect(409)
        .expect(({ body }) =>
          expect(body).toMatchObject({ code: 'STALE_REVISION' }),
        )
        .then(() => undefined);
      const anotherCheck = a
        .confirm('6')
        .expect(409)
        .then(() => undefined);
      await gate.query('SELECT pg_advisory_unlock(94124)');
      [result] = await Promise.all([first, second, anotherCheck]);
      expect(waiting).toBe(true);
    } finally {
      await gate.query('SELECT pg_advisory_unlock_all()');
      gate.release();
      await pool.query(
        'DROP TRIGGER i4_wait_version ON mvp_movement_versions; DROP FUNCTION i4_wait_version()',
      );
    }
    await confirm(winner, key)
      .expect(201)
      .expect(({ body }) => expect(body).toEqual(result));
    await confirm(loser, key)
      .expect(409)
      .expect(({ body }) =>
        expect(body).toMatchObject({ code: 'IDEMPOTENCY_CONFLICT' }),
      );
    await a
      .list({ view: 'pending' })
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          summary: { revision: '7', balanceMinor: '78300' },
          entries: [
            {
              id: checkId,
              originalCalculatedMinor: '84500',
              observedMinor: '80000',
              originalDifferenceMinor: '4500',
              remainingDifferenceMinor: '100',
              resolutionStatus: 'partially_explained',
            },
          ],
        }),
      );
    await versions()
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject([
          { action: 'original', amountMinor: '2500', description: 'Padaria' },
          {
            action: 'correct',
            amountMinor: '2400',
            authorId: a.principalId,
            reason: change.reason,
          },
        ]),
      );
    const outsider = await open();
    await versions(outsider.authorization).expect(404);
    await http()
      .post('/mvp/audit-previews')
      .set('Authorization', outsider.authorization)
      .send(change)
      .expect(404);
    await http()
      .post('/mvp/audited-changes')
      .set('Authorization', outsider.authorization)
      .set('Idempotency-Key', key)
      .send(winner)
      .expect(404);
  });

  it.each([
    ['invalidate', '80200', '2000'],
    ['correct', '78200', '2500'],
  ] as const)(
    'I4 S04 %s recalculates the historical cut and link attribution',
    async (action, balance, difference) => {
      const { a, other, bakery, checkId, review, confirm } =
        await auditedFixture();
      const targetId =
        action === 'invalidate' ? other.transactionId : bakery.transactionId;
      const terms = await review({
        accountId: a.id,
        targetId,
        action,
        reason: 'Conferência do comprovante',
        ...(action === 'correct'
          ? { occurredAt: '2026-11-18T12:10:00.123456Z' }
          : {}),
      });
      await confirm(terms).expect(201);
      await a
        .list()
        .expect(200)
        .expect(({ body }) =>
          expect(body).toMatchObject({
            summary: { balanceMinor: balance },
            entries: [
              {
                id: checkId,
                originalDifferenceMinor: '4500',
                remainingDifferenceMinor: difference,
              },
            ],
          }),
        );
      await http()
        .get(`/mvp/account/${a.id}/history`)
        .set('Authorization', a.authorization)
        .expect(200)
        .expect(({ body }) =>
          expect(body).toMatchObject({
            entries: expect.arrayContaining([
              expect.objectContaining({
                id: targetId,
                auditAction: action,
                ...(action === 'correct'
                  ? { occurredAt: '2026-11-18T12:10:00.123456Z' }
                  : {}),
              }),
            ]) as object,
          }),
        );
    },
  );

  it('I4 keeps the exact inclusive cut and retains each edited description and occurrence', async () => {
    const { a, change, review, confirm, versions, checkId } =
      await auditedFixture();
    const exactCut = '2026-11-18T12:00:00.000000Z';
    const justAfterCut = '2026-11-18T12:00:00.000001Z';
    await confirm(
      await review({ ...change, occurredAt: exactCut, description: '' }),
    ).expect(201);
    await a
      .list()
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          entries: [{ id: checkId, remainingDifferenceMinor: '100' }],
        }),
      );
    await confirm(
      await review({
        ...change,
        occurredAt: justAfterCut,
        description: 'Nota revisada',
      }),
    ).expect(201);
    await a
      .list()
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          summary: { balanceMinor: '78300' },
          entries: [{ id: checkId, remainingDifferenceMinor: '2500' }],
        }),
      );
    await versions()
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject([
          { action: 'original', description: 'Padaria', amountMinor: '2500' },
          {
            action: 'correct',
            description: null,
            occurredAt: exactCut,
            amountMinor: '2400',
          },
          {
            action: 'correct',
            description: 'Nota revisada',
            occurredAt: justAfterCut,
            amountMinor: '2400',
          },
        ]),
      );
  });

  it('I4 S03 supersedes only the selected observation and preserves its audit and exact cut', async () => {
    const { a, change, review, confirm, checkId } = await auditedFixture();
    await confirm(await review(change)).expect(201);
    const referenceAt = '2026-11-18T14:00:00.000001Z';
    const previous = (
      await a
        .confirm('7', randomUUID(), { observedMinor: '78300', referenceAt })
        .expect(201)
    ).body as { id: string };
    const terms = await review({
      accountId: a.id,
      targetId: previous.id,
      action: 'replace_check',
      reason: 'Erro de digitação',
      referenceAt,
      observedMinor: '78200',
    });
    const key = randomUUID();
    const created = (await confirm(terms, key).expect(201)).body as {
      id: string;
    };
    expect(created).toMatchObject({
      replacesCheckId: previous.id,
      authorId: a.principalId,
      reason: 'Erro de digitação',
      referenceAt,
      originalDifferenceMinor: '100',
    });
    await confirm(terms, key)
      .expect(201)
      .expect(({ body }) => expect(body).toEqual(created));
    await a
      .list()
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          entries: [
            {
              id: created.id,
              replacesCheckId: previous.id,
              remainingDifferenceMinor: '100',
            },
            {
              id: previous.id,
              observedMinor: '78300',
              originalDifferenceMinor: '0',
              supersededBy: created.id,
            },
            { id: checkId, remainingDifferenceMinor: '100' },
          ],
        }),
      );
    await a
      .list({ view: 'pending' })
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({
          entries: [{ id: created.id }, { id: checkId }],
        }),
      );
    const second = await review({
      accountId: a.id,
      targetId: created.id,
      action: 'replace_check',
      reason: 'Nova conferência da digitação',
      referenceAt,
      observedMinor: '78300',
    });
    await confirm(second).expect(201);
    await a
      .list({ view: 'pending' })
      .expect(200)
      .expect(({ body }) =>
        expect(body).toMatchObject({ entries: [{ id: checkId }] }),
      );
  });

  it('I4 rolls back revision, audit and receipt together for movement and observation failures', async () => {
    const { a, change, review, confirm, versions, checkId } =
      await auditedFixture();
    const movement = await review(change);
    const observation = await review({
      accountId: a.id,
      targetId: checkId,
      action: 'replace_check',
      reason: 'Erro de digitação',
      referenceAt: '2026-11-18T12:00:00Z',
      observedMinor: '80100',
    });
    await pool.query(`CREATE FUNCTION i4_fail_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN IF NEW.response->>'action' IN ('correct', 'replace_check') THEN
        RAISE EXCEPTION 'injected receipt failure'; END IF; RETURN NEW; END $$;
      CREATE TRIGGER i4_fail_receipt BEFORE INSERT ON idempotency_keys
      FOR EACH ROW EXECUTE FUNCTION i4_fail_receipt();`);
    const keys = [randomUUID(), randomUUID()];
    const before = await counts(a.id);
    try {
      await confirm(movement, keys[0]).expect(503);
      await confirm(observation, keys[1]).expect(503);
      expect(await counts(a.id)).toEqual(before);
      await versions()
        .expect(200)
        .expect(({ body }) => expect(body).toHaveLength(1));
      const { rows } = await pool.query(
        'SELECT 1 FROM idempotency_keys WHERE idempotency_key = ANY($1::uuid[])',
        [keys],
      );
      expect(rows).toEqual([]);
      const links = await pool.query(
        'SELECT 1 FROM mvp_check_replacements WHERE account_id = $1',
        [a.id],
      );
      expect(links.rowCount).toBe(0);
    } finally {
      await pool.query(
        'DROP TRIGGER i4_fail_receipt ON idempotency_keys; DROP FUNCTION i4_fail_receipt()',
      );
    }
    await confirm(movement, keys[0]).expect(201);
  });
});
