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
      .useValue({ query, getClient: jest.fn() })
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
    expect(query.mock.calls[0][1]).toEqual([
      expect.any(String),
      userId,
      'Main',
      'BRL',
    ]);
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

  afterAll(async () => app.close());
});

function makeAccessToken(userId: string): string {
  const encode = (value: object) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  const header = encode({ alg: 'HS256', typ: 'JWT' });
  const payload = encode({
    sub: userId,
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
