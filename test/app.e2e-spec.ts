import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from './../src/app.module';
import { DatabaseService } from './../src/common/database/database.service';
import { AuthGuard } from './../src/modules/auth/auth.guard';

interface StoredIdempotencyResult {
  requestHash: string;
  response: unknown;
}

describe('Application contract (e2e)', () => {
  const userId = '00000000-0000-4000-8000-000000000010';
  const requestBody = {
    accountId: '00000000-0000-4000-8000-000000000001',
    categoryId: '00000000-0000-4000-8000-000000000002',
    type: 'income',
    amountMinor: 15000,
    currency: 'BRL',
    description: 'Salary',
    occurredAt: '2026-07-30T18:00:00.000Z',
    clientMutationId: '00000000-0000-4000-8000-000000000003',
  };
  const idempotencyKey = '00000000-0000-4000-8000-000000000004';
  const idempotencyResults = new Map<string, StoredIdempotencyResult>();
  const query = jest.fn(
    (text: string, parameters?: unknown[]): Promise<{ rows: unknown[] }> => {
      const sql = text.replace(/\s+/g, ' ').trim();

      if (sql.startsWith('SELECT response, request_hash')) {
        const result = idempotencyResults.get(
          `${String(parameters?.[0])}:${String(parameters?.[1])}`,
        );
        return Promise.resolve({
          rows: result
            ? [
                {
                  response: result.response,
                  request_hash: result.requestHash,
                },
              ]
            : [],
        });
      }

      if (sql.startsWith('SELECT currency')) {
        return Promise.resolve({ rows: [{ currency: 'BRL' }] });
      }

      if (sql.startsWith('SELECT 1')) {
        return Promise.resolve({ rows: [{ exists: 1 }] });
      }

      if (sql.startsWith('INSERT INTO transactions')) {
        return Promise.resolve({
          rows: [
            {
              id: parameters?.[0],
              account_id: parameters?.[2],
              category_id: parameters?.[3],
              type: parameters?.[4],
              amount_minor: parameters?.[5],
              currency: parameters?.[6],
              description: parameters?.[7],
              occurred_at: new Date(parameters?.[8] as string),
              created_at: new Date('2026-07-30T18:00:01.000Z'),
            },
          ],
        });
      }

      if (sql.startsWith('INSERT INTO idempotency_keys')) {
        const responseJSON = parameters?.[4] as string;
        const response: unknown = JSON.parse(responseJSON);
        idempotencyResults.set(
          `${String(parameters?.[1])}:${String(parameters?.[2])}`,
          {
            requestHash: parameters?.[3] as string,
            response,
          },
        );
      }

      return Promise.resolve({ rows: [] });
    },
  );
  const release = jest.fn();
  const getClient = jest.fn().mockResolvedValue({ query, release });
  let app: INestApplication<App>;

  beforeAll(async () => {
    process.env.JWT_ACCESS_SECRET = '01234567890123456789012345678901';
    process.env.JWT_ISSUER = 'fintech-api-test';
    process.env.JWT_AUDIENCE = 'fintech-clients-test';
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(DatabaseService)
      .useValue({ getClient })
      .overrideGuard(AuthGuard)
      .useValue({
        canActivate: (context: {
          switchToHttp: () => { getRequest: () => Record<string, unknown> };
        }) => {
          context.switchToHttp().getRequest().principal = { userId };
          return true;
        },
      })
      .compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
        validationError: {
          target: false,
          value: false,
        },
      }),
    );
    await app.init();
  });

  beforeEach(() => {
    idempotencyResults.clear();
    query.mockClear();
    release.mockClear();
    getClient.mockClear();
  });

  it('returns the service status', async () => {
    await request(app.getHttpServer()).get('/').expect(200).expect({
      name: 'fintech-api',
      status: 'running',
    });
  });

  it('documents health as liveness and generates its own request ID', async () => {
    const response = await request(app.getHttpServer())
      .get('/health')
      .set('X-Request-Id', 'client-value-is-not-propagated')
      .expect(200)
      .expect({ status: 'ok' });

    expect(response.headers['x-request-id']).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });

  it('creates an income transaction and returns the identical replay', async () => {
    const first = await postTransaction(idempotencyKey, requestBody).expect(
      201,
    );
    const replay = await postTransaction(idempotencyKey, requestBody).expect(
      201,
    );
    const firstBody: unknown = first.body;
    const replayBody: unknown = replay.body;

    if (!isRecord(firstBody)) {
      throw new Error('Expected a transaction response object');
    }

    expect(typeof firstBody.id).toBe('string');
    expect(firstBody).toEqual({
      id: firstBody.id,
      accountId: requestBody.accountId,
      categoryId: requestBody.categoryId,
      type: requestBody.type,
      amountMinor: requestBody.amountMinor,
      currency: requestBody.currency,
      description: requestBody.description,
      occurredAt: requestBody.occurredAt,
      createdAt: '2026-07-30T18:00:01.000Z',
    });
    expect(replayBody).toEqual(firstBody);
    expect(JSON.stringify(firstBody)).not.toMatch(
      /account_|amount_|occurred_|created_/,
    );
    expect(
      query.mock.calls.filter(([sql]) =>
        String(sql).includes('INSERT INTO transactions'),
      ),
    ).toHaveLength(1);
  });

  it('returns the Nest error envelope for conflicting replay', async () => {
    await postTransaction(idempotencyKey, requestBody).expect(201);
    const response = await postTransaction(idempotencyKey, {
      ...requestBody,
      amountMinor: 25000,
    }).expect(409);

    expect(response.body).toEqual({
      statusCode: 409,
      message: 'Idempotency key was already used with a different request',
      error: 'Conflict',
    });
  });

  it('creates an expense transaction', async () => {
    const response = await postTransaction(
      '00000000-0000-4000-8000-000000000005',
      { ...requestBody, type: 'expense' },
    ).expect(201);

    const responseBody: unknown = response.body;

    expect(isRecord(responseBody) && responseBody.type).toBe('expense');
  });

  it.each(['debit', 'credit'])(
    'returns 400 for legacy type %s',
    async (type) => {
      const response = await postTransaction(idempotencyKey, {
        ...requestBody,
        type,
      }).expect(400);
      const responseBody: unknown = response.body;

      expect(responseBody).toMatchObject({
        statusCode: 400,
        error: 'Bad Request',
      });
      expect(
        isRecord(responseBody) && Array.isArray(responseBody.message),
      ).toBe(true);
      expect(getClient).not.toHaveBeenCalled();
    },
  );

  it('returns 400 for an invalid Idempotency-Key UUID', async () => {
    const response = await postTransaction('not-a-uuid', requestBody).expect(
      400,
    );

    expect(response.body).toEqual({
      statusCode: 400,
      message: 'Idempotency key must be a UUID',
      error: 'Bad Request',
    });
    expect(getClient).not.toHaveBeenCalled();
  });

  it('returns 400 when Idempotency-Key is missing', async () => {
    const response = await request(app.getHttpServer())
      .post('/transactions')
      .send(requestBody)
      .expect(400);

    expect(response.body).toEqual({
      statusCode: 400,
      message: 'Idempotency key required',
      error: 'Bad Request',
    });
    expect(getClient).not.toHaveBeenCalled();
  });

  it.each(['accountId', 'clientMutationId'] as const)(
    'returns 400 for an invalid %s UUID',
    async (field) => {
      const response = await postTransaction(idempotencyKey, {
        ...requestBody,
        [field]: 'not-a-uuid',
      }).expect(400);
      const responseBody: unknown = response.body;

      expect(responseBody).toMatchObject({
        statusCode: 400,
        error: 'Bad Request',
      });
      expect(
        isRecord(responseBody) && Array.isArray(responseBody.message),
      ).toBe(true);
      expect(getClient).not.toHaveBeenCalled();
    },
  );

  it('returns 400 for a non-positive amount and invalid timestamp', async () => {
    const response = await postTransaction(idempotencyKey, {
      ...requestBody,
      amountMinor: 0,
      occurredAt: '2026-07-30',
    }).expect(400);
    const responseBody: unknown = response.body;

    expect(responseBody).toMatchObject({
      statusCode: 400,
      error: 'Bad Request',
    });
    expect(isRecord(responseBody) && Array.isArray(responseBody.message)).toBe(
      true,
    );
    expect(getClient).not.toHaveBeenCalled();
  });

  afterAll(async () => {
    await app.close();
  });

  function postTransaction(key: string, body: object): request.Test {
    return request(app.getHttpServer())
      .post('/transactions')
      .set('Idempotency-Key', key)
      .send(body);
  }

  function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null;
  }
});
