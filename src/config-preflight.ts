import { AppleClientSecretService } from './modules/auth/apple-client-secret.service';
import { AppleRefreshTokenCipherService } from './modules/auth/apple-refresh-token-cipher.service';
import { AuthConfig } from './modules/auth/auth.config';

const APPLE_CLIENT_ID = 'com.ferrari.Fintech';

export type ConfigPreflightResult = {
  databaseConfigured: boolean;
  jwtConfigured: boolean;
  appleConfigured: boolean;
};

export function runConfigPreflight(): ConfigPreflightResult {
  const databaseConfigured = hasValidDatabaseUrl(process.env.DATABASE_URL);
  let config: AuthConfig;

  try {
    config = new AuthConfig();
  } catch {
    return {
      databaseConfigured,
      jwtConfigured: false,
      appleConfigured: false,
    };
  }

  let appleConfigured = false;
  try {
    if (config.appleClientId === APPLE_CLIENT_ID) {
      void new AppleClientSecretService(config).generate();
      new AppleRefreshTokenCipherService(config).assertConfigured();
      appleConfigured = true;
    }
  } catch {
    // Keep operational output boolean-only so configuration values never leak.
  }

  return { databaseConfigured, jwtConfigured: true, appleConfigured };
}

function hasValidDatabaseUrl(value: string | undefined): boolean {
  if (!value) return false;

  try {
    const url = new URL(value);
    return (
      (url.protocol === 'postgres:' || url.protocol === 'postgresql:') &&
      Boolean(url.hostname && url.username && url.password) &&
      url.pathname.length > 1
    );
  } catch {
    return false;
  }
}

if (require.main === module) {
  const result = runConfigPreflight();
  console.log(JSON.stringify(result));
  if (!Object.values(result).every(Boolean)) process.exitCode = 1;
}
