import {
  IsISO8601,
  IsString,
  IsUUID,
  Matches,
  MaxLength,
  ValidateIf,
} from 'class-validator';

export class MvpOpeningDto {
  @IsString()
  @Matches(/^(0|-?[1-9][0-9]{0,18})$/)
  baseMinor: string;

  @IsString()
  @IsISO8601({ strict: true, strictSeparator: true })
  @Matches(
    /^(?!0000)[0-9]{4}-[0-9]{2}-[0-9]{2}T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,6})?Z$/,
  )
  coverageStart: string;

  @IsString()
  @MaxLength(64)
  @Matches(/^[A-Za-z][A-Za-z0-9_+.-]*(?:\/[A-Za-z0-9_+.-]+)*$/)
  referenceZone: string;

  @ValidateIf((dto: MvpOpeningDto) => dto.accountId !== undefined)
  @IsUUID()
  accountId?: string;
}
