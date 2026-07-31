import { TransactionType } from './create-transaction.dto';

export interface TransactionPersistenceRecord {
  id: string;
  account_id: string;
  category_id: string | null;
  type: TransactionType;
  amount_minor: number;
  currency: string;
  description: string | null;
  occurred_at: Date | string;
  created_at: Date | string;
}

export class TransactionResponseDto {
  id: string;
  accountId: string;
  categoryId: string | null;
  type: TransactionType;
  amountMinor: number;
  currency: string;
  description: string | null;
  occurredAt: string;
  createdAt: string;

  static fromPersistence(
    transaction: TransactionPersistenceRecord,
  ): TransactionResponseDto {
    return {
      id: transaction.id,
      accountId: transaction.account_id,
      categoryId: transaction.category_id,
      type: transaction.type,
      amountMinor: transaction.amount_minor,
      currency: transaction.currency,
      description: transaction.description,
      occurredAt: this.toISOString(transaction.occurred_at),
      createdAt: this.toISOString(transaction.created_at),
    };
  }

  static fromStoredResponse(
    transaction: TransactionPersistenceRecord | TransactionResponseDto,
  ): TransactionResponseDto {
    if ('account_id' in transaction) {
      return this.fromPersistence(transaction);
    }

    return transaction;
  }

  private static toISOString(value: Date | string): string {
    return value instanceof Date ? value.toISOString() : value;
  }
}
