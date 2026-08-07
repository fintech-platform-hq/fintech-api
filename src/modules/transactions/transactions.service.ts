import {
  BadRequestException,
  ConflictException,
  Injectable,
} from '@nestjs/common';
import { createHash, randomUUID } from 'crypto';
import { isUUID } from 'class-validator';
import { DatabaseService } from '../../common/database/database.service';
import {
  CreateTransactionDto,
  TransactionType,
} from './dto/create-transaction.dto';
import {
  TransactionPersistenceRecord,
  TransactionResponseDto,
} from './dto/transaction-response.dto';

interface IdempotencyKeyRow {
  response: TransactionPersistenceRecord | TransactionResponseDto;
  request_hash: string;
}

@Injectable()
export class TransactionsService {
  constructor(private readonly db: DatabaseService) {}

  async createTransaction(
    dto: CreateTransactionDto,
    idempotencyKey: string,
  ): Promise<TransactionResponseDto> {
    if (!idempotencyKey) {
      throw new BadRequestException('Idempotency key required');
    }

    if (!isUUID(idempotencyKey)) {
      throw new BadRequestException('Idempotency key must be a UUID');
    }

    const requestHash = this.getRequestHash(dto);
    const legacyRequestHash = this.getLegacyRequestHash(dto);

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
        if (
          existingIdempotencyKey.request_hash !== requestHash &&
          existingIdempotencyKey.request_hash !== legacyRequestHash
        ) {
          throw new ConflictException(
            'Idempotency key was already used with a different request',
          );
        }

        await client.query('COMMIT');

        return TransactionResponseDto.fromStoredResponse(
          existingIdempotencyKey.response,
        );
      }

      const transactionResult =
        await client.query<TransactionPersistenceRecord>(
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

      const response = TransactionResponseDto.fromPersistence(
        transactionResult.rows[0],
      );

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

      if (
        error instanceof ConflictException ||
        error instanceof BadRequestException
      ) {
        throw error;
      }

      const databaseError = error as { code?: string };

      if (databaseError.code === '23505') {
        throw new ConflictException();
      }

      if (databaseError.code === '23514' || databaseError.code === '22P02') {
        throw new BadRequestException();
      }

      throw error;
    } finally {
      client.release();
    }
  }

  private getRequestHash(
    dto: CreateTransactionDto,
    type: string = dto.type,
  ): string {
    return createHash('sha256')
      .update(
        JSON.stringify({
          accountId: dto.accountId,
          categoryId: dto.categoryId ?? null,
          type,
          amountMinor: dto.amountMinor,
          currency: dto.currency,
          description: dto.description ?? null,
          occurredAt: dto.occurredAt,
          clientMutationId: dto.clientMutationId,
        }),
      )
      .digest('hex');
  }

  private getLegacyRequestHash(dto: CreateTransactionDto): string | undefined {
    const legacyType =
      dto.type === TransactionType.EXPENSE
        ? 'debit'
        : dto.type === TransactionType.INCOME
          ? 'credit'
          : undefined;

    return legacyType ? this.getRequestHash(dto, legacyType) : undefined;
  }
}
