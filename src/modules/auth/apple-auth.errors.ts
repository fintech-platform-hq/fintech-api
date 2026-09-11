export type AppleAuthErrorCode =
  | 'INVALID_IDENTITY_TOKEN'
  | 'UNKNOWN_APPLE_KID'
  | 'APPLE_JWKS_UNAVAILABLE'
  | 'INVALID_APPLE_CONFIGURATION';

export class AppleAuthError extends Error {
  constructor(
    readonly code: AppleAuthErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'AppleAuthError';
  }
}
