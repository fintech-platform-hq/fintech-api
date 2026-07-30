import { Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
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

    const client = await this.db.getClient();

    try {
      await client.query('BEGIN');

      const result = await client.query<TransactionRow>(
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

      await client.query('COMMIT');

      return result.rows[0];
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
}
