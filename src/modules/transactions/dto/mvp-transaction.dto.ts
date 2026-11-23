import {
  IsEnum,
  IsISO8601,
  IsInt,
  IsOptional,
  IsString,
  IsUUID,
  Matches,
  Max,
  MaxLength,
  Min,
} from 'class-validator';
import { TransactionType } from './create-transaction.dto';

export class MvpTransactionDto {
  @IsUUID()
  accountId: string;

  @IsEnum(TransactionType)
  type: TransactionType;

  @IsInt()
  @Min(1)
  @Max(999999999)
  amountMinor: number;

  @Matches(/^BRL$/)
  currency: 'BRL';

  @IsOptional()
  @IsString()
  @MaxLength(255)
  description?: string;

  @IsISO8601({ strict: true, strictSeparator: true })
  @Matches(
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/,
  )
  occurredAt: string;

  @IsUUID()
  clientMutationId: string;

  @Matches(/^[1-9]\d{0,18}$/)
  expectedRevision: string;
}

export interface MvpTransactionReceipt {
  id: string;
  accountId: string;
  type: TransactionType;
  amountMinor: string;
  currency: 'BRL';
  description: string | null;
  occurredAt: string;
  createdAt: string;
  revision: string;
}
