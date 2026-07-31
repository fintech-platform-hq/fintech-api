import { Test, TestingModule } from '@nestjs/testing';
import {
  CreateTransactionDto,
  TransactionType,
} from './dto/create-transaction.dto';
import { TransactionResponseDto } from './dto/transaction-response.dto';
import { TransactionsController } from './transactions.controller';
import { TransactionsService } from './transactions.service';

describe('TransactionsController', () => {
  const dto: CreateTransactionDto = {
    accountId: '00000000-0000-4000-8000-000000000001',
    type: TransactionType.DEBIT,
    amountMinor: 500,
    currency: 'BRL',
    occurredAt: '2026-07-30T18:00:00.000Z',
    clientMutationId: '00000000-0000-4000-8000-000000000002',
  };
  const idempotencyKey = '00000000-0000-4000-8000-000000000003';
  const response: TransactionResponseDto = {
    id: '00000000-0000-4000-8000-000000000004',
    accountId: dto.accountId,
    categoryId: null,
    type: dto.type,
    amountMinor: dto.amountMinor,
    currency: dto.currency,
    description: null,
    occurredAt: dto.occurredAt,
    createdAt: '2026-07-30T18:00:01.000Z',
  };

  let controller: TransactionsController;
  let createTransaction: jest.Mock;

  beforeEach(async () => {
    createTransaction = jest.fn().mockResolvedValue(response);
    const module: TestingModule = await Test.createTestingModule({
      controllers: [TransactionsController],
      providers: [
        {
          provide: TransactionsService,
          useValue: { createTransaction },
        },
      ],
    }).compile();

    controller = module.get<TransactionsController>(TransactionsController);
  });

  it('returns the transaction service response without exposing persistence rows', async () => {
    await expect(
      controller.createTransaction(dto, idempotencyKey),
    ).resolves.toEqual(response);
    expect(createTransaction).toHaveBeenCalledWith(dto, idempotencyKey);
  });
});
