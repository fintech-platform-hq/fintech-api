import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { Pool, QueryResult, QueryResultRow } from 'pg';

@Injectable()
export class DatabaseService implements OnModuleDestroy {
  private pool: Pool;

  constructor() {
    this.pool = new Pool({
      connectionString:
        process.env.DATABASE_URL || 'postgresql://localhost:5432/fintech',
      connectionTimeoutMillis: 5_000,
    });
  }

  async query<T extends QueryResultRow = QueryResultRow>(
    text: string,
    params?: unknown[],
  ): Promise<QueryResult<T>> {
    return this.pool.query(text, params);
  }

  async queryWithTimeout<T extends QueryResultRow = QueryResultRow>(
    text: string,
    timeoutMilliseconds: number,
  ): Promise<QueryResult<T>> {
    if (
      !Number.isSafeInteger(timeoutMilliseconds) ||
      timeoutMilliseconds < 1 ||
      timeoutMilliseconds > 30_000
    ) {
      throw new RangeError(
        'Query timeout must be between 1 and 30000 milliseconds',
      );
    }

    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SELECT set_config('statement_timeout', $1, true)", [
        `${timeoutMilliseconds}ms`,
      ]);
      const result = await client.query<T>(text);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async getClient() {
    return this.pool.connect();
  }

  async onModuleDestroy() {
    await this.pool.end();
  }
}
