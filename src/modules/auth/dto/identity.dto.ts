import { Transform } from 'class-transformer';
import {
  IsBoolean,
  IsEmail,
  IsString,
  IsUUID,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';
import { AppleAuthenticationDto } from './apple-authentication.dto';

export class EmailDto {
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim().toLowerCase() : value,
  )
  @IsEmail()
  @MaxLength(254)
  email: string;
}

export class EmailProofDto {
  @Matches(/^[0-9]{6}$/)
  code: string;
}

export class PasswordProofDto {
  @IsString()
  @MinLength(12)
  @MaxLength(128)
  password: string;
}

export class ResetPasswordDto extends EmailDto {
  @Matches(/^[0-9]{6}$/)
  code: string;

  @IsString()
  @MinLength(12)
  @MaxLength(128)
  newPassword: string;
}

export class AppleLinkDto extends AppleAuthenticationDto {
  @IsString()
  @MinLength(12)
  @MaxLength(128)
  password: string;

  @IsBoolean()
  consent: boolean;
}

export class PreparePasswordChangeDto extends PasswordProofDto {
  @IsUUID()
  operationId: string;
}

export class CommitPasswordChangeDto {
  @IsUUID()
  operationId: string;

  @Matches(/^[A-Za-z0-9_-]{43}$/)
  proof: string;

  @IsString()
  @MinLength(12)
  @MaxLength(128)
  newPassword: string;
}

export class ChangePendingEmailDto extends EmailDto {
  @IsString()
  @MinLength(12)
  @MaxLength(128)
  password: string;
}

export class RequestPasswordLinkDto extends AppleAuthenticationDto {
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim().toLowerCase() : value,
  )
  @IsEmail()
  @MaxLength(254)
  email: string;

  @IsBoolean()
  consent: boolean;
}
