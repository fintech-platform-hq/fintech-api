import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from './../src/app.module';
import { DatabaseService } from './../src/common/database/database.service';

interface StoredIdempotencyResult {
  requestHash: string;
  response: unknown;
}

describe('Application contract (e2e)', () => {
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
        const result = idempotencyResults.get(parameters?.[0] as string);
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

      if (sql.startsWith('INSERT INTO transactions')) {
        return Promise.resolve({
          rows: [
            {
              id: parameters?.[0],
              account_id: parameters?.[1],
              category_id: parameters?.[2],
              type: parameters?.[3],
              amount_minor: parameters?.[4],
              currency: parameters?.[5],
              description: parameters?.[6],
              occurred_at: new Date(parameters?.[7] as string),
              created_at: new Date('2026-07-30T18:00:01.000Z'),
            },
          ],
        });
      }

      if (sql.startsWith('INSERT INTO idempotency_keys')) {
        const responseJSON = parameters?.[3] as string;
        const response: unknown = JSON.parse(responseJSON);
        idempotencyResults.set(parameters?.[1] as string, {
          requestHash: parameters?.[2] as string,
          response,
        });
      }

      return Promise.resolve({ rows: [] });
    },
  );
  const release = jest.fn();
  const getClient = jest.fn().mockResolvedValue({ query, release });
  let app: INestApplication<App>;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(DatabaseService)
      .useValue({ getClient })
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
