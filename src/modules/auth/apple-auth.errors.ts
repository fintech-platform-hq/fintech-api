export type AppleAuthErrorCode =
  | 'INVALID_IDENTITY_TOKEN'
  | 'UNKNOWN_APPLE_KID'
  | 'APPLE_JWKS_UNAVAILABLE'
  | 'INVALID_APPLE_CONFIGURATION'
  | 'APPLE_AUTHORIZATION_CODE_REJECTED'
  | 'APPLE_TOKEN_REQUEST_REJECTED'
  | 'APPLE_TOKEN_API_UNAVAILABLE'
  | 'INVALID_APPLE_TOKEN_RESPONSE';

export class AppleAuthError extends Error {
  constructor(
    readonly code: AppleAuthErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'AppleAuthError';
  }
}
