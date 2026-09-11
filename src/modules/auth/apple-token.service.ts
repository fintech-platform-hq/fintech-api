import { Injectable } from '@nestjs/common';
import { AppleApiClient } from './apple-api.client';
import { AppleAuthError } from './apple-auth.errors';
import { AppleClientSecretService } from './apple-client-secret.service';
import { AppleIdentityTokenVerifier } from './apple-identity-token.verifier';
import { AuthConfig } from './auth.config';

export interface AppleAuthorizationExchange {
  subject: string;
  refreshToken: string;
}

@Injectable()
export class AppleTokenService {
  constructor(
    private readonly api: AppleApiClient,
    private readonly clientSecrets: AppleClientSecretService,
    private readonly identityTokens: AppleIdentityTokenVerifier,
    private readonly config: AuthConfig,
  ) {}

  async exchangeAuthorizationCode(
    identityToken: string,
    authorizationCode: string,
    nonce: string,
  ): Promise<AppleAuthorizationExchange> {
    if (!authorizationCode) throw rejectedAuthorizationCode();

    const originalIdentity = await this.identityTokens.verify(
      identityToken,
      nonce,
    );
    const response = await this.api.exchangeAuthorizationCode(
      authorizationCode,
      this.config.appleClientId,
      this.clientSecrets.generate(),
    );
    const exchangedIdentity = await this.identityTokens.verifyTokenResponse(
      response.idToken,
      nonce,
    );
    if (exchangedIdentity.subject !== originalIdentity.subject) {
      throw invalidIdentityToken();
    }

    return {
      subject: originalIdentity.subject,
      refreshToken: response.refreshToken,
    };
  }
}

function rejectedAuthorizationCode(): AppleAuthError {
  return new AppleAuthError(
    'APPLE_AUTHORIZATION_CODE_REJECTED',
    'Apple authorization code was rejected',
  );
}

function invalidIdentityToken(): AppleAuthError {
  return new AppleAuthError(
    'INVALID_IDENTITY_TOKEN',
    'Invalid Apple identity token',
  );
}
