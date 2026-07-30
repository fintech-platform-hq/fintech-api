import { Injectable } from '@nestjs/common';
import { DatabaseService } from '../../common/database/database.service';
import { CreateTransactionDto } from './dto/create-transaction.dto';

@Injectable()
export class TransactionsService {
  constructor(private readonly db: DatabaseService) {}

  async createTransaction(dto: CreateTransactionDto, idempotencyKey: string) {
    if (!idempotencyKey) {
      throw new Error('Idempotency key required');
    }

    void dto;

    const client = await this.db.getClient();

    try {
      await client.query('BEGIN');

      const now = await client.query<{ now: Date }>('SELECT NOW()');

      await client.query('COMMIT');

      return now.rows[0];
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
}
