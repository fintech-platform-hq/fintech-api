import {
  BadRequestException,
  ConflictException,
  HttpException,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { createHash, randomUUID } from 'crypto';
import { isUUID } from 'class-validator';
import { DatabaseService } from '../../common/database/database.service';
import {
  MvpTransactionDto,
  MvpTransactionReceipt,
} from './dto/mvp-transaction.dto';
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

interface AccountRow {
  currency: string;
}

@Injectable()
export class TransactionsService {
  constructor(private readonly db: DatabaseService) {}

  async registerMvp(
    dto: MvpTransactionDto,
    key: string,
    userId: string,
  ): Promise<MvpTransactionReceipt> {
    if (!isUUID(key)) {
      throw new BadRequestException('Idempotency-Key must be a UUID');
    }
    const revision = BigInt(dto.expectedRevision);
    if (revision >= (1n << 63n) - 1n) {
      throw new BadRequestException('Invalid expected revision');
    }
    key = key.toLowerCase();
    const accountId = dto.accountId.toLowerCase();
    const hash = createHash('sha256')
      .update(
        JSON.stringify([
          'mvp.transactions.register',
          1,
          userId,
          accountId,
          dto.expectedRevision,
          dto.type,
          dto.amountMinor,
          dto.currency,
          dto.description ?? null,
          dto.occurredAt,
          dto.clientMutationId.toLowerCase(),
        ]),
      )
      .digest('hex');

    const client = await this.db.getClient();
    try {
      await client.query('BEGIN');
      await client.query("SET LOCAL lock_timeout = '3s'");
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [
        `${userId}:${key}`,
      ]);
      const {
        rows: [receipt],
      } = await client.query<{
        request_hash: string;
        response: MvpTransactionReceipt;
      }>(
        'SELECT request_hash, response FROM idempotency_keys WHERE user_id = $1 AND idempotency_key = $2 FOR UPDATE',
        [userId, key],
      );
      if (receipt) {
        if (receipt.request_hash !== hash) {
          throw new ConflictException({
            statusCode: 409,
            code: 'IDEMPOTENCY_CONFLICT',
            message: 'Idempotency key already used for another request',
          });
        }
        await client.query('COMMIT');
        return receipt.response;
      }

      const { rowCount } = await client.query(
        "SELECT 1 FROM accounts WHERE user_id = $1 AND id = $2 AND currency = 'BRL' FOR NO KEY UPDATE",
        [userId, accountId],
      );
      if (!rowCount) throw new NotFoundException('Account not found');

      // The trigger checks coverage and expected revision under lock, and advances
      // the account revision. The deferred constraint requires this receipt at commit.
      const {
        rows: [response],
      } = await client.query<MvpTransactionReceipt>(
        `INSERT INTO transactions (id, user_id, account_id, type, amount_minor,
            currency, description, occurred_at, mvp_write_key, mvp_revision)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         RETURNING id, account_id AS "accountId", type, amount_minor::text AS "amountMinor",
           currency, description, mvp_revision::text AS revision,
           to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "occurredAt",
           to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "createdAt"`,
        [
          randomUUID(),
          userId,
          accountId,
          dto.type,
          dto.amountMinor,
          dto.currency,
          dto.description ?? null,
          dto.occurredAt,
          key,
          (revision + 1n).toString(),
        ],
      );
      await client.query(
        `INSERT INTO idempotency_keys (id, user_id, idempotency_key, request_hash, response)
         VALUES ($1, $2, $3, $4, $5::jsonb)`,
        [randomUUID(), userId, key, hash, JSON.stringify(response)],
      );
      await client.query('COMMIT');
      return response;
    } catch (error) {
      await client.query('ROLLBACK');
      const { code, constraint } = error as {
        code?: string;
        constraint?: string;
      };
      if (constraint === 'mvp_transaction_stale_revision') {
        throw new ConflictException({
          statusCode: 409,
          code: 'STALE_REVISION',
          message: 'Account revision changed',
        });
      }
      if (constraint === 'mvp_base_suspended') {
        throw new ConflictException({
          statusCode: 409,
          code: 'BASE_SUSPENDED',
          message: 'The opening balance is under review',
        });
      }
      if (constraint === 'mvp_transaction_base_required') {
        throw new ConflictException({
          statusCode: 409,
          code: 'BASE_REQUIRED',
          message: 'A confirmed base is required',
        });
      }
      if (
        constraint === 'mvp_transaction_coverage' ||
        code === '22008' ||
        code === '22007' ||
        code === '22009'
      ) {
        throw new BadRequestException(
          'Occurrence must be within the confirmed coverage and in the past or present',
        );
      }
      if (code === '55P03') {
        throw new ServiceUnavailableException(
          'Registration temporarily unavailable',
        );
      }
      throw error;
    } finally {
      client.release();
    }
  }

  async createTransaction(
    dto: CreateTransactionDto,
    idempotencyKey: string,
    userId: string,
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
        `${userId}:${idempotencyKey.toLowerCase()}`,
      ]);

      const idempotencyResult = await client.query<IdempotencyKeyRow>(
        `
            SELECT response, request_hash
            FROM idempotency_keys
            WHERE user_id = $1 AND idempotency_key = $2
            FOR UPDATE
          `,
        [userId, idempotencyKey],
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

      const accountResult = await client.query<AccountRow>(
        `
          SELECT currency
          FROM accounts
          WHERE user_id = $1 AND id = $2
          FOR KEY SHARE
        `,
        [userId, dto.accountId],
      );
      const account = accountResult.rows[0];
      if (!account) {
        throw new NotFoundException('Account not found');
      }
      if (account.currency !== dto.currency) {
        throw new BadRequestException(
          'Transaction currency must match account currency',
        );
      }

      if (dto.categoryId) {
        const categoryResult = await client.query(
          `
            SELECT 1
            FROM categories
            WHERE user_id = $1 AND id = $2
            FOR KEY SHARE
          `,
          [userId, dto.categoryId],
        );
        if (!categoryResult.rows[0]) {
          throw new NotFoundException('Category not found');
        }
      }

      const transactionResult =
        await client.query<TransactionPersistenceRecord>(
          `
            INSERT INTO transactions (
              id,
              user_id,
              account_id,
              category_id,
              type,
              amount_minor,
              currency,
              description,
              occurred_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
          `,
          [
            randomUUID(),
            userId,
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
              user_id,
              idempotency_key,
              request_hash,
              response
            )
            VALUES ($1, $2, $3, $4, $5::jsonb)
          `,
        [
          randomUUID(),
          userId,
          idempotencyKey,
          requestHash,
          JSON.stringify(response),
        ],
      );

      await client.query('COMMIT');

      return response;
    } catch (error) {
      await client.query('ROLLBACK');

      if (error instanceof HttpException) {
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
