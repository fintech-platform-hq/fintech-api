import { Injectable } from '@nestjs/common';
import { createPublicKey, JsonWebKey, KeyObject } from 'crypto';
import { AppleApiClient } from './apple-api.client';
import { AppleAuthError } from './apple-auth.errors';

const CACHE_TTL_MS = 60 * 60 * 1_000;
const UNKNOWN_KID_REFRESH_COOLDOWN_MS = 60 * 1_000;

interface AppleJwk {
  alg: unknown;
  e: unknown;
  kid: unknown;
  kty: unknown;
  n: unknown;
  use: unknown;
}

interface CachedAppleKey {
  jwk: AppleJwk;
  key?: KeyObject;
}

@Injectable()
export class AppleJwksService {
  private keys = new Map<string, CachedAppleKey>();
  private expiresAt = 0;
  private lastRefreshAttemptAt = Number.NEGATIVE_INFINITY;
  private refreshPromise?: Promise<void>;

  constructor(private readonly appleApi: AppleApiClient) {}

  async getVerificationKey(kid: string): Promise<KeyObject> {
    const now = Date.now();
    if (now >= this.expiresAt) await this.refresh();

    let entry = this.keys.get(kid);
    if (!entry && this.refreshPromise) {
      await this.refreshPromise;
      entry = this.keys.get(kid);
    }
    if (
      !entry &&
      Date.now() - this.lastRefreshAttemptAt >= UNKNOWN_KID_REFRESH_COOLDOWN_MS
    ) {
      await this.refresh();
      entry = this.keys.get(kid);
    }
    if (!entry) {
      throw new AppleAuthError(
        'UNKNOWN_APPLE_KID',
        'Apple identity token uses an unknown key identifier',
      );
    }

    if (!entry.key) entry.key = this.importCompatibleKey(entry.jwk);
    return entry.key;
  }

  private async refresh(): Promise<void> {
    if (this.refreshPromise) return this.refreshPromise;

    this.lastRefreshAttemptAt = Date.now();
    this.refreshPromise = this.loadKeys();
    try {
      await this.refreshPromise;
    } finally {
      this.refreshPromise = undefined;
    }
  }

  private async loadKeys(): Promise<void> {
    const response = await this.appleApi.fetchJwks();
    if (!isRecord(response) || !Array.isArray(response.keys)) {
      throw unavailableJwks();
    }

    const nextKeys = new Map<string, CachedAppleKey>();
    for (const value of response.keys) {
      if (!isAppleJwk(value) || typeof value.kid !== 'string' || !value.kid) {
        throw unavailableJwks();
      }
      if (nextKeys.has(value.kid)) throw unavailableJwks();
      nextKeys.set(value.kid, { jwk: value });
    }
    if (nextKeys.size === 0) throw unavailableJwks();

    const now = Date.now();
    this.keys = nextKeys;
    this.expiresAt = now + CACHE_TTL_MS;
  }

  private importCompatibleKey(jwk: AppleJwk): KeyObject {
    if (
      jwk.kty !== 'RSA' ||
      jwk.alg !== 'RS256' ||
      jwk.use !== 'sig' ||
      !isBase64Url(jwk.n) ||
      !isBase64Url(jwk.e)
    ) {
      throw invalidIdentityToken();
    }

    try {
      const key = createPublicKey({
        key: jwk as unknown as JsonWebKey,
        format: 'jwk',
      });
      if (key.asymmetricKeyType !== 'rsa') throw new Error('Not an RSA key');
      return key;
    } catch {
      throw invalidIdentityToken();
    }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isAppleJwk(value: unknown): value is AppleJwk {
  return (
    isRecord(value) &&
    'alg' in value &&
    'e' in value &&
    'kid' in value &&
    'kty' in value &&
    'n' in value &&
    'use' in value
  );
}

function isBase64Url(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value);
}

function unavailableJwks(): AppleAuthError {
  return new AppleAuthError(
    'APPLE_JWKS_UNAVAILABLE',
    'Apple JWKS is unavailable',
  );
}

function invalidIdentityToken(): AppleAuthError {
  return new AppleAuthError(
    'INVALID_IDENTITY_TOKEN',
    'Invalid Apple identity token',
  );
}
