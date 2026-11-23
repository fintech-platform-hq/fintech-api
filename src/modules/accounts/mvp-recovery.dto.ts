import {
  IsIn,
  IsISO8601,
  IsOptional,
  IsString,
  IsUUID,
  Matches,
  MaxLength,
} from 'class-validator';

export class MvpRecoveryInput {
  @IsUUID()
  accountId: string;

  @IsUUID()
  checkId: string;

  @Matches(/^[1-9]\d{0,8}$/)
  amountMinor: string;

  @IsISO8601({ strict: true })
  @Matches(/^(?!0000)\d{4}-\d{2}-\d{2}$/)
  day: string;

  @IsOptional()
  @IsISO8601({ strict: true, strictSeparator: true })
  @Matches(
    /^(?!0000)\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,6})?Z$/,
  )
  occurredAt?: string;

  @IsOptional()
  @IsString()
  @MaxLength(240)
  description?: string;

  @IsOptional()
  @Matches(/^[a-z0-9][a-z0-9._-]{0,63}$/)
  externalSource?: string;

  @IsOptional()
  @IsString()
  @MaxLength(200)
  externalReference?: string;
}

export class MvpRecoveryConfirmation extends MvpRecoveryInput {
  @Matches(/^[1-9]\d{0,18}$/)
  expectedRevision: string;

  @IsIn(['link', 'create'])
  action: 'link' | 'create';

  @IsOptional()
  @IsUUID()
  transactionId?: string;

  @IsString()
  @MaxLength(1000)
  @Matches(/\S/u)
  evidence: string;
}
