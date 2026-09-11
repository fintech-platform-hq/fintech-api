import { Injectable } from '@nestjs/common';
import { AppleAuthError } from './apple-auth.errors';

const APPLE_JWKS_URL = 'https://appleid.apple.com/auth/keys';
const APPLE_TOKEN_URL = 'https://appleid.apple.com/auth/token';
const REQUEST_TIMEOUT_MS = 5_000;

export interface AppleTokenResponse {
  accessToken: string;
  expiresIn: number;
  idToken: string;
  refreshToken: string;
}

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

  async exchangeAuthorizationCode(
    authorizationCode: string,
    clientId: string,
    clientSecret: string,
  ): Promise<AppleTokenResponse> {
    const body = new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      code: authorizationCode,
      grant_type: 'authorization_code',
    });

    let response: Response;
    try {
      response = await fetch(APPLE_TOKEN_URL, {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body,
        redirect: 'error',
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch {
      throw tokenApiUnavailable();
    }

    if (
      response.status >= 500 ||
      (response.status !== 200 && response.status !== 400)
    ) {
      throw tokenApiUnavailable();
    }
    if (
      !response.headers
        .get('content-type')
        ?.toLowerCase()
        .startsWith('application/json')
    ) {
      throw invalidTokenResponse();
    }

    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      throw invalidTokenResponse();
    }

    if (response.status === 400) throw tokenRequestError(payload);
    return parseTokenResponse(payload);
  }
}

function parseTokenResponse(value: unknown): AppleTokenResponse {
  if (
    !isRecord(value) ||
    !isNonEmptyString(value.access_token) ||
    typeof value.token_type !== 'string' ||
    value.token_type.toLowerCase() !== 'bearer' ||
    !Number.isInteger(value.expires_in) ||
    Number(value.expires_in) <= 0 ||
    !isNonEmptyString(value.refresh_token) ||
    !isNonEmptyString(value.id_token)
  ) {
    throw invalidTokenResponse();
  }

  return {
    accessToken: value.access_token,
    expiresIn: Number(value.expires_in),
    idToken: value.id_token,
    refreshToken: value.refresh_token,
  };
}

function tokenRequestError(value: unknown): AppleAuthError {
  if (!isRecord(value) || typeof value.error !== 'string') {
    return invalidTokenResponse();
  }

  if (value.error === 'invalid_grant') {
    return new AppleAuthError(
      'APPLE_AUTHORIZATION_CODE_REJECTED',
      'Apple authorization code was rejected',
    );
  }
  if (
    value.error === 'invalid_client' ||
    value.error === 'unauthorized_client'
  ) {
    return new AppleAuthError(
      'INVALID_APPLE_CONFIGURATION',
      'Apple client configuration was rejected',
    );
  }
  if (
    value.error === 'invalid_request' ||
    value.error === 'unsupported_grant_type' ||
    value.error === 'invalid_scope'
  ) {
    return new AppleAuthError(
      'APPLE_TOKEN_REQUEST_REJECTED',
      'Apple token request was rejected',
    );
  }
  return invalidTokenResponse();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function tokenApiUnavailable(): AppleAuthError {
  return new AppleAuthError(
    'APPLE_TOKEN_API_UNAVAILABLE',
    'Apple token API is unavailable',
  );
}

function invalidTokenResponse(): AppleAuthError {
  return new AppleAuthError(
    'INVALID_APPLE_TOKEN_RESPONSE',
    'Apple token response is invalid',
  );
}
