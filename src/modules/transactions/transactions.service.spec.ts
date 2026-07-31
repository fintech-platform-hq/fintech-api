import { BadRequestException, ConflictException } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { DatabaseService } from '../../common/database/database.service';
import {
  CreateTransactionDto,
  TransactionType,
} from './dto/create-transaction.dto';
import { TransactionsService } from './transactions.service';

describe('TransactionsService', () => {
  interface TestQueryResult {
    rows: unknown[];
  }

  const dto: CreateTransactionDto = {
    accountId: '00000000-0000-4000-8000-000000000001',
    categoryId: '00000000-0000-4000-8000-000000000002',
    type: TransactionType.CREDIT,
    amountMinor: 15000,
    currency: 'BRL',
    description: 'Salary',
    occurredAt: '2026-07-30T18:00:00.000Z',
    clientMutationId: '00000000-0000-4000-8000-000000000003',
  };
  const idempotencyKey = '00000000-0000-4000-8000-000000000004';
  const persistenceRecord = {
    id: '00000000-0000-4000-8000-000000000005',
    account_id: dto.accountId,
    category_id: dto.categoryId ?? null,
    type: dto.type,
    amount_minor: dto.amountMinor,
    currency: dto.currency,
    description: dto.description ?? null,
    occurred_at: new Date(dto.occurredAt),
    created_at: new Date('2026-07-30T18:00:01.000Z'),
  };
  const response = {
    id: persistenceRecord.id,
    accountId: dto.accountId,
    categoryId: dto.categoryId ?? null,
    type: dto.type,
    amountMinor: dto.amountMinor,
    currency: dto.currency,
    description: dto.description ?? null,
    occurredAt: dto.occurredAt,
    createdAt: '2026-07-30T18:00:01.000Z',
  };

  let service: TransactionsService;
  let query: jest.Mock<Promise<TestQueryResult>, [string, unknown[]?]>;
  let release: jest.Mock<void, []>;
  let getClient: jest.Mock<
    Promise<{ query: typeof query; release: typeof release }>,
    []
  >;

  beforeEach(async () => {
    query = jest.fn<Promise<TestQueryResult>, [string, unknown[]?]>();
    release = jest.fn<void, []>();
    getClient = jest
      .fn<Promise<{ query: typeof query; release: typeof release }>, []>()
      .mockResolvedValue({ query, release });

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TransactionsService,
        {
          provide: DatabaseService,
          useValue: { getClient },
        },
      ],
    }).compile();

    service = module.get<TransactionsService>(TransactionsService);
  });

  it('maps a newly created PostgreSQL row to the camelCase contract', async () => {
    query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [persistenceRecord] })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [] });

    await expect(
      service.createTransaction(dto, idempotencyKey),
    ).resolves.toEqual(response);

    const idempotencyInsertParameters = query.mock.calls[4][1];
    if (typeof idempotencyInsertParameters?.[3] !== 'string') {
      throw new Error('Expected a serialized idempotency response');
    }
    const storedResponse: unknown = JSON.parse(idempotencyInsertParameters[3]);
    expect(storedResponse).toEqual(response);
    expect(query).toHaveBeenLastCalledWith('COMMIT');
    expect(release).toHaveBeenCalledTimes(1);
  });

  it('normalizes a legacy snake_case stored response on identical replay', async () => {
    const requestHash = await getRequestHash();
    query.mockReset();
    query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({
        rows: [{ response: persistenceRecord, request_hash: requestHash }],
      })
      .mockResolvedValueOnce({ rows: [] });

    await expect(
      service.createTransaction(dto, idempotencyKey),
    ).resolves.toEqual(response);
    expect(query).toHaveBeenCalledTimes(4);
    expect(query).toHaveBeenLastCalledWith('COMMIT');
  });

  it('rolls back and returns 409 for conflicting replay', async () => {
    query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({
        rows: [{ response, request_hash: 'different-request-hash' }],
      })
      .mockResolvedValueOnce({ rows: [] });

    await expect(
      service.createTransaction(dto, idempotencyKey),
    ).rejects.toBeInstanceOf(ConflictException);
    expect(query).toHaveBeenLastCalledWith('ROLLBACK');
    expect(release).toHaveBeenCalledTimes(1);
  });

  it('rejects a missing idempotency key before opening a connection', async () => {
    await expect(service.createTransaction(dto, '')).rejects.toBeInstanceOf(
      BadRequestException,
    );
    expect(getClient).not.toHaveBeenCalled();
  });

  it('rejects an invalid idempotency key before opening a connection', async () => {
    await expect(
      service.createTransaction(dto, 'not-a-uuid'),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(getClient).not.toHaveBeenCalled();
  });

  async function getRequestHash(): Promise<string> {
    query.mockReset();
    query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [persistenceRecord] })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [] });

    await service.createTransaction(dto, idempotencyKey);
    const parameters = query.mock.calls[4][1];
    if (typeof parameters?.[2] !== 'string') {
      throw new Error('Expected the request hash insert parameter');
    }
    return parameters[2];
  }
});
