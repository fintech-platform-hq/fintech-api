import { IsNotEmpty, IsString, Matches, MaxLength } from 'class-validator';

export class AppleAuthenticationDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(16_384)
  identityToken: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(4_096)
  authorizationCode: string;

  @IsString()
  @Matches(/^[A-Za-z0-9_-]{43}$/)
  nonce: string;
}
