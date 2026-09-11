import { Injectable } from '@nestjs/common';
import { AppleAuthError } from './apple-auth.errors';

const APPLE_JWKS_URL = 'https://appleid.apple.com/auth/keys';
const REQUEST_TIMEOUT_MS = 5_000;

@Injectable()
export class AppleApiClient {
  async fetchJwks(): Promise<unknown> {
    try {
      const response = await fetch(APPLE_JWKS_URL, {
        headers: { Accept: 'application/json' },
        redirect: 'error',
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (!response.ok) throw new Error('Unexpected Apple JWKS response');
      return await response.json();
    } catch {
      throw new AppleAuthError(
        'APPLE_JWKS_UNAVAILABLE',
        'Apple JWKS is unavailable',
      );
    }
  }
}
