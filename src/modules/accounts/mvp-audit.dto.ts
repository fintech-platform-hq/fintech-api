import {
  IsIn,
  IsISO8601,
  IsOptional,
  IsString,
  IsUUID,
  Matches,
  MaxLength,
} from 'class-validator';

const utcInstant =
  /^(?!0000)\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,6})?Z$/;

export class MvpAuditInput {
  @IsUUID()
  accountId: string;

  @IsUUID()
  targetId: string;

  @IsIn(['correct', 'invalidate', 'replace_check'])
  action: 'correct' | 'invalidate' | 'replace_check';

  @IsString()
  @Matches(/\S/u)
  @MaxLength(1000)
  reason: string;

  @IsOptional()
  @Matches(/^[1-9]\d{0,8}$/)
  amountMinor?: string;

  @IsOptional()
  @IsString()
  @MaxLength(240)
  description?: string;

  @IsOptional()
  @IsISO8601({ strict: true, strictSeparator: true })
  @Matches(utcInstant)
  occurredAt?: string;

  @IsOptional()
  @Matches(/^(0|-?[1-9]\d{0,18})$/)
  observedMinor?: string;

  @IsOptional()
  @IsISO8601({ strict: true, strictSeparator: true })
  @Matches(utcInstant)
  referenceAt?: string;
}

export class MvpAuditConfirmation extends MvpAuditInput {
  @Matches(/^[1-9]\d{0,18}$/)
  expectedRevision: string;

  @Matches(/^[0-9a-f]{64}$/)
  previewToken: string;
}
