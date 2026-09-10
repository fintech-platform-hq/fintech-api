import { Injectable } from '@nestjs/common';

@Injectable()
export class AuthConfig {
  readonly jwtSecret = this.required('JWT_ACCESS_SECRET', 32);
  readonly jwtIssuer = this.required('JWT_ISSUER');
  readonly jwtAudience = this.required('JWT_AUDIENCE');
  readonly accessTokenSeconds = 15 * 60;
  readonly refreshTokenSeconds = 30 * 24 * 60 * 60;

  private required(name: string, minimumLength = 1): string {
    const value = process.env[name];

    if (!value || value.length < minimumLength) {
      throw new Error(
        `${name} is required and must contain at least ${minimumLength} characters`,
      );
    }

    return value;
  }
}
