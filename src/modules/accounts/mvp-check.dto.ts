import {
  IsISO8601,
  IsOptional,
  IsString,
  IsUUID,
  Matches,
} from 'class-validator';

export class MvpCheckInput {
  @IsUUID()
  accountId: string;

  @IsString()
  @Matches(/^(0|-?[1-9]\d{0,18})$/)
  observedMinor: string;

  @IsISO8601({ strict: true, strictSeparator: true })
  @Matches(
    /^(?!0000)\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,6})?Z$/,
  )
  referenceAt: string;
}

export class MvpCheckConfirmation extends MvpCheckInput {
  @Matches(/^[1-9]\d{0,18}$/)
  expectedRevision: string;
}

export class MvpCheckQuery {
  @IsOptional()
  @Matches(/^(all|pending)$/)
  view?: 'all' | 'pending';

  @IsOptional()
  @IsUUID()
  after?: string;

  @IsOptional()
  @Matches(/^[1-9]\d{0,18}$/)
  revision?: string;
}
