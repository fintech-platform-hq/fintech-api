import { Injectable } from '@nestjs/common';
import { constants, timingSafeEqual, verify as verifySignature } from 'crypto';
import { isEmail } from 'class-validator';
import { AppleAuthError } from './apple-auth.errors';
import { AppleJwksService } from './apple-jwks.service';
import { AuthConfig } from './auth.config';

const APPLE_ISSUER = 'https://appleid.apple.com';
const CLOCK_SKEW_SECONDS = 60;

export interface VerifiedAppleIdentity {
  subject: string;
  email?: string;
  isPrivateEmail?: boolean;
}

@Injectable()
export class AppleIdentityTokenVerifier {
  constructor(
    private readonly config: AuthConfig,
    private readonly jwks: AppleJwksService,
  ) {}

  async verify(
    identityToken: string,
    expectedNonce: string,
  ): Promise<VerifiedAppleIdentity> {
    return this.verifyToken(identityToken, expectedNonce, true);
  }

  async verifyTokenResponse(
    identityToken: string,
    expectedNonce: string,
  ): Promise<VerifiedAppleIdentity> {
    return this.verifyToken(identityToken, expectedNonce, false);
  }

  async verifyRefreshToken(
    identityToken: string,
  ): Promise<VerifiedAppleIdentity> {
    return this.verifyToken(identityToken, '', false);
  }

  private async verifyToken(
    identityToken: string,
    expectedNonce: string,
    requireNonce: boolean,
  ): Promise<VerifiedAppleIdentity> {
    try {
      if (requireNonce && !expectedNonce) throw invalidIdentityToken();
      const segments = identityToken.split('.');
      if (segments.length !== 3) throw invalidIdentityToken();

      const [encodedHeader, encodedPayload, encodedSignature] = segments;
      const header = decodeJson(encodedHeader);
      const payload = decodeJson(encodedPayload);
      if (
        !isRecord(header) ||
        header.alg !== 'RS256' ||
        typeof header.kid !== 'string' ||
        !header.kid ||
        header.crit !== undefined ||
        !isRecord(payload)
      ) {
        throw invalidIdentityToken();
      }

      const key = await this.jwks.getVerificationKey(header.kid);
      const signature = decodeBase64Url(encodedSignature);
      const validSignature = verifySignature(
        'RSA-SHA256',
        Buffer.from(`${encodedHeader}.${encodedPayload}`, 'ascii'),
        { key, padding: constants.RSA_PKCS1_PADDING },
        signature,
      );
      if (!validSignature) throw invalidIdentityToken();

      const now = Math.floor(Date.now() / 1_000);
      if (
        payload.iss !== APPLE_ISSUER ||
        payload.aud !== this.config.appleClientId ||
        !isPositiveInteger(payload.iat) ||
        !isPositiveInteger(payload.exp) ||
        payload.iat > now + CLOCK_SKEW_SECONDS ||
        payload.exp <= now - CLOCK_SKEW_SECONDS ||
        payload.iat >= payload.exp ||
        typeof payload.sub !== 'string' ||
        payload.sub.trim().length === 0 ||
        !validNonce(payload.nonce, expectedNonce, requireNonce)
      ) {
        throw invalidIdentityToken();
      }

      return { subject: payload.sub, ...verifiedEmail(payload) };
    } catch (error) {
      if (error instanceof AppleAuthError) throw error;
      throw invalidIdentityToken();
    }
  }
}

function verifiedEmail(
  payload: Record<string, unknown>,
): Pick<VerifiedAppleIdentity, 'email' | 'isPrivateEmail'> {
  if (
    typeof payload.email !== 'string' ||
    !isVerified(payload.email_verified)
  ) {
    return {};
  }

  const email = payload.email.trim().toLowerCase();
  if (!email || email.length > 254 || !isEmail(email)) return {};
  return {
    email,
    isPrivateEmail:
      payload.is_private_email === true || payload.is_private_email === 'true',
  };
}

function isVerified(value: unknown): boolean {
  return value === true || value === 'true';
}

function validNonce(
  actual: unknown,
  expected: string,
  required: boolean,
): boolean {
  if (!required && expected === '') return true;
  if (actual === undefined) return !required;
  return typeof actual === 'string' && noncesMatch(actual, expected);
}

function decodeJson(segment: string): unknown {
  return JSON.parse(decodeBase64Url(segment).toString('utf8')) as unknown;
}

function decodeBase64Url(value: string): Buffer {
  if (!value || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    throw invalidIdentityToken();
  }
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.toString('base64url') !== value) throw invalidIdentityToken();
  return decoded;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isPositiveInteger(value: unknown): value is number {
  return Number.isInteger(value) && Number(value) > 0;
}

function noncesMatch(actual: string, expected: string): boolean {
  const actualBytes = Buffer.from(actual, 'utf8');
  const expectedBytes = Buffer.from(expected, 'utf8');
  return (
    actualBytes.length === expectedBytes.length &&
    timingSafeEqual(actualBytes, expectedBytes)
  );
}

function invalidIdentityToken(): AppleAuthError {
  return new AppleAuthError(
    'INVALID_IDENTITY_TOKEN',
    'Invalid Apple identity token',
  );
}
