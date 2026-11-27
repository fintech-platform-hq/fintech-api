import { createHmac } from 'crypto';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from '../src/app.module';
import { DatabaseService } from '../src/common/database/database.service';

describe('Accounts API (e2e)', () => {
  const userId = '10000000-0000-4000-8000-000000000010';
  const accessToken = makeAccessToken(userId);
  const account = {
    id: '10000000-0000-4000-8000-000000000001',
    name: 'Main',
    currency: 'BRL',
    created_at: new Date('2026-09-10T15:00:00.000Z'),
  };

  let app: INestApplication<App>;
  const query = jest.fn((text: string, parameters?: unknown[]) => {
    if (text.includes('FROM refresh_sessions s'))
      return Promise.resolve({ rows: [{ financialAccess: true }] });
    if (text.includes('INSERT INTO accounts')) {
      return Promise.resolve({
        rows: [
          {
            ...account,
            id: parameters?.[0],
            name: parameters?.[2],
            currency: parameters?.[3],
          },
        ],
      });
    }

    return Promise.resolve({ rows: [] });
  });

  beforeAll(async () => {
    process.env.JWT_ACCESS_SECRET = '01234567890123456789012345678901';
    process.env.JWT_ISSUER = 'fintech-api-test';
    process.env.JWT_AUDIENCE = 'fintech-clients-test';

    const module = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(DatabaseService)
      .useValue({
        query,
        getClient: jest.fn().mockResolvedValue({ query, release: jest.fn() }),
      })
      .compile();

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
  });

  beforeEach(() => query.mockClear());

  it('returns 401 without authentication', async () => {
    await request(app.getHttpServer()).get('/accounts').expect(401);
  });

  it('guards recovery previews and rejects an unconfirmed or malformed recovery', async () => {
    const input = {
      accountId: account.id,
      checkId: account.id,
      amountMinor: '2500',
      day: '2026-11-15',
    };
    await request(app.getHttpServer())
      .post('/mvp/recovery-previews')
      .send(input)
      .expect(401);
    await request(app.getHttpServer())
      .post('/mvp/recovery-previews')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ ...input, day: '2026-02-29' })
      .expect(400);
    await request(app.getHttpServer())
      .post('/mvp/recoveries')
      .set('Authorization', `Bearer ${accessToken}`)
      .set('Idempotency-Key', account.id)
      .send({ ...input, expectedRevision: '4', action: 'create' })
      .expect(400);
    expect(
      query.mock.calls.filter(
        ([sql]) => !sql.includes('FROM refresh_sessions s'),
      ),
    ).toHaveLength(0);
  });

  it('returns an empty list for an authenticated user without accounts', async () => {
    await request(app.getHttpServer())
      .get('/accounts')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200)
      .expect([]);
  });

  it('creates a BRL account with the authenticated principal', async () => {
    const response = await request(app.getHttpServer())
      .post('/accounts')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ name: 'Main', currency: 'BRL' })
      .expect(201);

    const body: unknown = response.body;
    if (!isRecord(body)) {
      throw new Error('Expected an account response object');
    }

    expect(Object.keys(body).sort()).toEqual([
      'createdAt',
      'currency',
      'id',
      'name',
    ]);
    expect(body.id).toEqual(expect.any(String));
    expect(body.name).toBe('Main');
    expect(body.currency).toBe('BRL');
    expect(body.createdAt).toBe(account.created_at.toISOString());
    expect(
      query.mock.calls.find(([sql]) =>
        sql.includes('INSERT INTO accounts'),
      )?.[1],
    ).toEqual([expect.any(String), userId, 'Main', 'BRL']);
  });

  it.each([
    [{ name: '', currency: 'BRL' }],
    [{ name: '   ', currency: 'BRL' }],
    [{ name: 'Main', currency: 'USD' }],
    [{ name: 'Main', currency: 'brl' }],
    [{ name: 'Main', currency: 'BRL', userId }],
  ])('rejects invalid account payload %j', async (body) => {
    await request(app.getHttpServer())
      .post('/accounts')
      .set('Authorization', `Bearer ${accessToken}`)
      .send(body)
      .expect(400);
  });

  it('returns 401 for unauthenticated account creation', async () => {
    await request(app.getHttpServer())
      .post('/accounts')
      .send({ name: 'Main', currency: 'BRL' })
      .expect(401);
  });

  describe('balance check envelope', () => {
    const input = {
      accountId: account.id,
      observedMinor: '80000',
      referenceAt: '2026-01-01T12:00:00.123456Z',
    };

    it('requires authentication for preview, confirmation and checks', async () => {
      await request(app.getHttpServer())
        .post('/mvp/check-previews')
        .send(input)
        .expect(401);
      await request(app.getHttpServer())
        .post('/mvp/checks')
        .send(input)
        .expect(401);
      await request(app.getHttpServer())
        .get(`/mvp/account/${account.id}/checks`)
        .expect(401);
      expect(
        query.mock.calls.filter(
          ([sql]) => !sql.includes('FROM refresh_sessions s'),
        ),
      ).toHaveLength(0);
    });

    it.each([
      { observedMinor: 80000 },
      { observedMinor: '-0' },
      { observedMinor: '1.5' },
      { referenceAt: '2026-02-30T00:00:00Z' },
      { referenceAt: '2026-01-01T12:00:00' },
      { referenceAt: '2026-01-01T12:00:00.1234567Z' },
      { authorId: userId },
    ])('rejects invalid preview fields %j before storage', async (changes) => {
      await request(app.getHttpServer())
        .post('/mvp/check-previews')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ ...input, ...changes })
        .expect(400);
      expect(
        query.mock.calls.filter(
          ([sql]) => !sql.includes('FROM refresh_sessions s'),
        ),
      ).toHaveLength(0);
    });

    it('requires a UUID confirmation key and a valid revision', async () => {
      const confirm = () =>
        request(app.getHttpServer())
          .post('/mvp/checks')
          .set('Authorization', `Bearer ${accessToken}`);
      await confirm()
        .send({ ...input, expectedRevision: '1' })
        .expect(400);
      await confirm()
        .set('Idempotency-Key', userId)
        .send({ ...input, expectedRevision: '0' })
        .expect(400);
      await confirm()
        .set('Idempotency-Key', userId)
        .send({ ...input, expectedRevision: '9223372036854775808' })
        .expect(400);
      expect(
        query.mock.calls.filter(
          ([sql]) => !sql.includes('FROM refresh_sessions s'),
        ),
      ).toHaveLength(0);
    });

    it('rejects an incomplete page key and unknown view', async () => {
      const list = () =>
        request(app.getHttpServer())
          .get(`/mvp/account/${account.id}/checks`)
          .set('Authorization', `Bearer ${accessToken}`);
      await list().query({ after: userId }).expect(400);
      await list().query({ view: 'resolved' }).expect(400);
      expect(
        query.mock.calls.filter(
          ([sql]) => !sql.includes('FROM refresh_sessions s'),
        ),
      ).toHaveLength(0);
    });
  });

  afterAll(async () => app.close());
});

function makeAccessToken(userId: string): string {
  const encode = (value: object) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  const header = encode({ alg: 'HS256', typ: 'JWT' });
  const payload = encode({
    sub: userId,
    auth_method: 'password',
    sid: userId,
    iss: 'fintech-api-test',
    aud: 'fintech-clients-test',
    iat: 1_000,
    exp: Math.floor(Date.now() / 1000) + 900,
    jti: '10000000-0000-4000-8000-000000000011',
  });
  const signature = createHmac('sha256', '01234567890123456789012345678901')
    .update(`${header}.${payload}`)
    .digest('base64url');
  return `${header}.${payload}.${signature}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
