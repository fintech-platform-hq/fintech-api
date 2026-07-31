import {
  IsUUID,
  IsEnum,
  IsInt,
  IsISO8601,
  IsString,
  IsOptional,
  Matches,
  Min,
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
  @Min(1)
  amountMinor: number;

  @Matches(/^[A-Z]{3}$/)
  currency: string;

  @IsString()
  @IsOptional()
  description?: string;

  @IsISO8601({ strict: true, strictSeparator: true })
  @Matches(/T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/)
  occurredAt: string;

  @IsUUID()
  clientMutationId: string;
}
