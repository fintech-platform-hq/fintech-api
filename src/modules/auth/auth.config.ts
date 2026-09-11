import { Injectable } from '@nestjs/common';
import { AppleAuthError } from './apple-auth.errors';

@Injectable()
export class AuthConfig {
  readonly jwtSecret = this.required('JWT_ACCESS_SECRET', 32);
  readonly jwtIssuer = this.required('JWT_ISSUER');
  readonly jwtAudience = this.required('JWT_AUDIENCE');
  readonly accessTokenSeconds = 15 * 60;
  readonly refreshTokenSeconds = 30 * 24 * 60 * 60;

  get appleClientId(): string {
    return this.requiredAppleValue('APPLE_CLIENT_ID');
  }

  get appleTeamId(): string {
    return this.appleIdentifier('APPLE_TEAM_ID');
  }

  get appleKeyId(): string {
    return this.appleIdentifier('APPLE_KEY_ID');
  }

  get applePrivateKeyP8(): string {
    const value = process.env.APPLE_PRIVATE_KEY_P8;
    if (!value || value.trim().length === 0) {
      throw new AppleAuthError(
        'INVALID_APPLE_CONFIGURATION',
        'APPLE_PRIVATE_KEY_P8 is required',
      );
    }
    return value.replace(/\\n/g, '\n');
  }

  private required(name: string, minimumLength = 1): string {
    const value = process.env[name];

    if (!value || value.length < minimumLength) {
      throw new Error(
        `${name} is required and must contain at least ${minimumLength} characters`,
      );
    }

    return value;
  }

  private requiredAppleValue(name: string): string {
    const value = process.env[name];

    if (!value || value.trim().length === 0 || value !== value.trim()) {
      throw new AppleAuthError(
        'INVALID_APPLE_CONFIGURATION',
        `${name} is required and must not contain surrounding whitespace`,
      );
    }

    return value;
  }

  private appleIdentifier(name: string): string {
    const value = this.requiredAppleValue(name);
    if (!/^[A-Za-z0-9]{10}$/.test(value)) {
      throw new AppleAuthError(
        'INVALID_APPLE_CONFIGURATION',
        `${name} must be a 10-character alphanumeric identifier`,
      );
    }

    return value;
  }
}
