import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { readFileSync } from 'fs';
import { Pool } from 'pg';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from '../src/app.module';

const databaseUrl = process.env.TEST_DATABASE_URL;
const describeWithDatabase = databaseUrl ? describe : describe.skip;

interface AuthResponse {
  accessToken: string;
}

interface AccountResponse {
  id: string;
  name: string;
  currency: string;
  createdAt: string;
}

describeWithDatabase('Accounts API (PostgreSQL integration)', () => {
  let app: INestApplication<App>;
  let pool: Pool;
  let firstAccessToken: string;
  let secondAccessToken: string;

  beforeAll(async () => {
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
      .send({ email: 'accounts-first@example.com', password: 'correct horse' })
      .expect(201);
    const second = await request(app.getHttpServer())
      .post('/auth/register')
      .send({ email: 'accounts-second@example.com', password: 'correct horse' })
      .expect(201);

    firstAccessToken = authBody(first.body).accessToken;
    secondAccessToken = authBody(second.body).accessToken;
  });

  it('returns an empty list before account creation', async () => {
    await request(app.getHttpServer())
      .get('/accounts')
      .set('Authorization', `Bearer ${firstAccessToken}`)
      .expect(200)
      .expect([]);
  });

  it('creates multiple accounts and lists only the authenticated user accounts', async () => {
    const first = await createAccount(firstAccessToken, 'Main');
    const second = await createAccount(firstAccessToken, 'Savings');
    const foreign = await createAccount(secondAccessToken, 'Other');

    const firstList = await request(app.getHttpServer())
      .get('/accounts')
      .set('Authorization', `Bearer ${firstAccessToken}`)
      .expect(200);
    const secondList = await request(app.getHttpServer())
      .get('/accounts')
      .set('Authorization', `Bearer ${secondAccessToken}`)
      .expect(200);

    const firstAccounts = accountList(firstList.body);
    const secondAccounts = accountList(secondList.body);

    expect(firstAccounts).toEqual([first, second]);
    expect(secondAccounts).toEqual([foreign]);
    expect(firstAccounts.every((account) => !('userId' in account))).toBe(true);
  });

  it.each([
    [{ name: '', currency: 'BRL' }],
    [{ name: '   ', currency: 'BRL' }],
    [{ name: 'Invalid', currency: 'USD' }],
    [
      {
        name: 'Invalid',
        currency: 'BRL',
        userId: '20000000-0000-4000-8000-000000000010',
      },
    ],
  ])('rejects invalid account creation %j', async (body) => {
    await request(app.getHttpServer())
      .post('/accounts')
      .set('Authorization', `Bearer ${firstAccessToken}`)
      .send(body)
      .expect(400);
  });

  it('does not create categories or transactions', async () => {
    const categories = await pool.query<{ count: number }>(
      'SELECT COUNT(*)::int AS count FROM categories',
    );
    const transactions = await pool.query<{ count: number }>(
      'SELECT COUNT(*)::int AS count FROM transactions',
    );

    expect(categories.rows[0].count).toBe(0);
    expect(transactions.rows[0].count).toBe(0);
  });

  it('rejects unauthenticated listing and creation', async () => {
    await request(app.getHttpServer()).get('/accounts').expect(401);
    await request(app.getHttpServer())
      .post('/accounts')
      .send({ name: 'No auth', currency: 'BRL' })
      .expect(401);
  });

  afterAll(async () => {
    await app.close();
    await pool.end();
  });

  async function createAccount(token: string, name: string) {
    const response = await request(app.getHttpServer())
      .post('/accounts')
      .set('Authorization', `Bearer ${token}`)
      .send({ name, currency: 'BRL' })
      .expect(201);
    return accountBody(response.body);
  }
});

function authBody(value: unknown): AuthResponse {
  if (!isRecord(value) || typeof value.accessToken !== 'string') {
    throw new Error('Expected an authentication response');
  }

  return { accessToken: value.accessToken };
}

function accountList(value: unknown): AccountResponse[] {
  if (!Array.isArray(value)) {
    throw new Error('Expected an account list');
  }

  return value.map(accountBody);
}

function accountBody(value: unknown): AccountResponse {
  if (
    !isRecord(value) ||
    typeof value.id !== 'string' ||
    typeof value.name !== 'string' ||
    typeof value.currency !== 'string' ||
    typeof value.createdAt !== 'string'
  ) {
    throw new Error('Expected an account response');
  }

  return {
    id: value.id,
    name: value.name,
    currency: value.currency,
    createdAt: value.createdAt,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
