import { Injectable } from '@nestjs/common';
import { createPrivateKey, KeyObject, sign } from 'crypto';
import { AppleAuthError } from './apple-auth.errors';
import { AuthConfig } from './auth.config';

const APPLE_AUDIENCE = 'https://appleid.apple.com';
const CLIENT_SECRET_TTL_SECONDS = 5 * 60;

@Injectable()
export class AppleClientSecretService {
  private signingKey?: KeyObject;

  constructor(private readonly config: AuthConfig) {}

  generate(): string {
    const now = Math.floor(Date.now() / 1_000);
    const header = encodeJson({ alg: 'ES256', kid: this.config.appleKeyId });
    const payload = encodeJson({
      iss: this.config.appleTeamId,
      iat: now,
      exp: now + CLIENT_SECRET_TTL_SECONDS,
      aud: APPLE_AUDIENCE,
      sub: this.config.appleClientId,
    });

    const signature = sign(
      'sha256',
      Buffer.from(`${header}.${payload}`, 'ascii'),
      { key: this.key(), dsaEncoding: 'ieee-p1363' },
    );
    if (signature.length !== 64) throw invalidConfiguration();
    return `${header}.${payload}.${signature.toString('base64url')}`;
  }

  private key(): KeyObject {
    if (this.signingKey) return this.signingKey;

    try {
      const key = createPrivateKey(this.config.applePrivateKeyP8);
      const curve = key.asymmetricKeyDetails?.namedCurve;
      if (
        key.asymmetricKeyType !== 'ec' ||
        (curve !== 'prime256v1' && curve !== 'P-256')
      ) {
        throw new Error('Not a P-256 private key');
      }
      this.signingKey = key;
      return key;
    } catch (error) {
      if (error instanceof AppleAuthError) throw error;
      throw invalidConfiguration();
    }
  }
}

function encodeJson(value: object): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function invalidConfiguration(): AppleAuthError {
  return new AppleAuthError(
    'INVALID_APPLE_CONFIGURATION',
    'Apple private key configuration is invalid',
  );
}
