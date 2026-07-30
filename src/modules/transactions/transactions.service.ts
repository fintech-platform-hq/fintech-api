import { ConflictException, Injectable } from '@nestjs/common';
import { createHash, randomUUID } from 'crypto';
import { DatabaseService } from '../../common/database/database.service';
import {
  CreateTransactionDto,
  TransactionType,
} from './dto/create-transaction.dto';

export interface TransactionRow {
  id: string;
  account_id: string;
  category_id: string | null;
  type: TransactionType;
  amount_minor: number;
  currency: string;
  description: string | null;
  occurred_at: Date;
  created_at: Date;
}

interface IdempotencyKeyRow {
  response: TransactionRow;
  request_hash: string;
}

@Injectable()
export class TransactionsService {
  constructor(private readonly db: DatabaseService) {}

  async createTransaction(
    dto: CreateTransactionDto,
    idempotencyKey: string,
  ): Promise<TransactionRow> {
    if (!idempotencyKey) {
      throw new Error('Idempotency key required');
    }

    const requestHash = createHash('sha256')
      .update(
        JSON.stringify({
          accountId: dto.accountId,
          categoryId: dto.categoryId ?? null,
          type: dto.type,
          amountMinor: dto.amountMinor,
          currency: dto.currency,
          description: dto.description ?? null,
          occurredAt: dto.occurredAt,
          clientMutationId: dto.clientMutationId,
        }),
      )
      .digest('hex');

    const client = await this.db.getClient();

    try {
      await client.query('BEGIN');

      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [
        idempotencyKey,
      ]);

      const idempotencyResult = await client.query<IdempotencyKeyRow>(
        `
          SELECT response, request_hash
          FROM idempotency_keys
          WHERE idempotency_key = $1
          FOR UPDATE
        `,
        [idempotencyKey],
      );

      const existingIdempotencyKey = idempotencyResult.rows[0];

      if (existingIdempotencyKey) {
        if (existingIdempotencyKey.request_hash !== requestHash) {
          throw new ConflictException(
            'Idempotency key was already used with a different request',
          );
        }

        await client.query('COMMIT');

        return existingIdempotencyKey.response;
      }

      const transactionResult = await client.query<TransactionRow>(
        `
          INSERT INTO transactions (
            id,
            account_id,
            category_id,
            type,
            amount_minor,
            currency,
            description,
            occurred_at
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
          RETURNING *
        `,
        [
          randomUUID(),
          dto.accountId,
          dto.categoryId ?? null,
          dto.type,
          dto.amountMinor,
          dto.currency,
          dto.description ?? null,
          dto.occurredAt,
        ],
      );

      const response = transactionResult.rows[0];

      await client.query(
        `
          INSERT INTO idempotency_keys (
            id,
            idempotency_key,
            request_hash,
            response
          )
          VALUES ($1, $2, $3, $4::jsonb)
        `,
        [randomUUID(), idempotencyKey, requestHash, JSON.stringify(response)],
      );

      await client.query('COMMIT');

      return response;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
}
