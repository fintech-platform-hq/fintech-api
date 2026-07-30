import {
  IsUUID,
  IsEnum,
  IsInt,
  IsString,
  IsOptional,
  Matches,
} from 'class-validator';

export enum TransactionType {
  DEBIT = 'debit',
  CREDIT = 'credit',
}

export class CreateTransactionDto {
  @IsUUID()
  accountId: string;

  @IsUUID()
  @IsOptional()
  categoryId?: string;

  @IsEnum(TransactionType)
  type: TransactionType;

  @IsInt()
  amountMinor: number;

  @Matches(/^[A-Z]{3}$/)
  currency: string;

  @IsString()
  @IsOptional()
  description?: string;

  @IsString()
  occurredAt: string;

  @IsUUID()
  clientMutationId: string;
}
