import { INestApplication, Logger, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { randomUUID } from 'crypto';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from '../src/app.module';
import { DatabaseService } from '../src/common/database/database.service';
import { AppleTokenService } from '../src/modules/auth/apple-token.service';
import { AppleRefreshTokenCipherService } from '../src/modules/auth/apple-refresh-token-cipher.service';
import { AppleAuthError } from '../src/modules/auth/apple-auth.errors';

describe('Refresh public contract (e2e)', () => {
  let app: INestApplication<App>;
  const validateRefreshToken = jest.fn<Promise<void>, [string, string]>();
  let due = false;
  let session: {
    user_id: string;
    auth_identity_id: string | null;
    family_id: string;
    expires_at: Date;
    revoked_at: Date | null;
  };
  let identity: {
    id: string;
    provider_subject: string;
    provider_refresh_token_ciphertext: string;
    revoked_at: Date | null;
  };
  let originalRevocation: Date | null;
  const query = jest.fn((sql: string): Promise<{ rows: unknown[] }> => {
    if (sql === 'BEGIN') originalRevocation = session.revoked_at;
    if (sql === 'ROLLBACK') session.revoked_at = originalRevocation;
    if (sql.includes('AS validation_due'))
      return Promise.resolve({ rows: [{ validation_due: due }] });
    if (sql.includes('FROM auth_identities'))
      return Promise.resolve({ rows: [identity] });
    if (sql.includes('FROM refresh_sessions'))
      return Promise.resolve({ rows: [session] });
    if (sql.includes('UPDATE refresh_sessions'))
      session.revoked_at = new Date();
    return Promise.resolve({ rows: [] });
  });
  const client = { query, release: jest.fn() };
  const errorLogs: unknown[] = [];

  beforeAll(async () => {
    process.env.JWT_ACCESS_SECRET = 'e2e-secret-with-at-least-32-characters';
    process.env.JWT_ISSUER = 'fintech-api-test';
    process.env.JWT_AUDIENCE = 'fintech-clients-test';
    process.env.APPLE_REFRESH_TOKEN_ENCRYPTION_KEY = Buffer.alloc(
      32,
      8,
    ).toString('base64url');
    const module = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(DatabaseService)
      .useValue({ getClient: jest.fn().mockResolvedValue(client) })
      .overrideProvider(AppleTokenService)
      .useValue({ validateRefreshToken })
      .compile();
    app = module.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
        validationError: { target: false, value: false },
      }),
    );
    await app.init();
  });
  beforeEach(() => {
    jest
      .spyOn(Logger.prototype, 'error')
      .mockImplementation((message: unknown) => {
        errorLogs.push(message);
      });
    errorLogs.length = 0;
    validateRefreshToken.mockReset().mockResolvedValue();
    query.mockClear();
    client.release.mockClear();
    due = false;
    const id = randomUUID();
    identity = {
      id,
      provider_subject: 'subject',
      provider_refresh_token_ciphertext: app
        .get(AppleRefreshTokenCipherService)
        .encrypt('secret-apple-token', id),
      revoked_at: null,
    };
    session = {
      user_id: randomUUID(),
      auth_identity_id: id,
      family_id: randomUUID(),
      expires_at: new Date('2099-01-01'),
      revoked_at: null,
    };
  });
  afterEach(() => jest.restoreAllMocks());
  afterAll(async () => {
    await app.close();
  });
  const refresh = () =>
    request(app.getHttpServer())
      .post('/auth/refresh')
      .send({ refreshToken: 'same-fintech-token' });

  it.each(['password', 'fresh Apple', 'due Apple'])(
    'preserves the auth response for %s',
    async (mode) => {
      if (mode === 'password') session.auth_identity_id = null;
      due = mode === 'due Apple';
      const response = await refresh().expect(200);
      const body = response.body as {
        accessToken: string;
        refreshToken: string;
        tokenType: string;
        expiresIn: number;
      };
      expect(Object.keys(body).sort()).toEqual([
        'accessToken',
        'expiresIn',
        'refreshToken',
        'tokenType',
      ]);
      expect(body).toMatchObject({ tokenType: 'Bearer', expiresIn: 900 });
      expect(body.refreshToken).not.toBe('same-fintech-token');
      const claims = JSON.parse(
        Buffer.from(body.accessToken.split('.')[1], 'base64url').toString(),
      ) as { auth_method: string };
      expect(claims.auth_method).toBe(
        mode === 'password' ? 'password' : 'apple',
      );
      expect(validateRefreshToken).toHaveBeenCalledTimes(due ? 1 : 0);
    },
  );

  it('rejects a revoked identity without an Apple call', async () => {
    identity.revoked_at = new Date();
    const response = await refresh().expect(401);
    expect(response.body).toEqual({
      statusCode: 401,
      message: 'Invalid refresh token',
      error: 'Unauthorized',
    });
    expect(validateRefreshToken).not.toHaveBeenCalled();
  });

  it('returns 503 without consuming the token, then accepts that same token after backoff', async () => {
    due = true;
    const now = Date.now();
    const clock = jest.spyOn(Date, 'now').mockReturnValue(now);
    validateRefreshToken.mockRejectedValueOnce(
      new AppleAuthError(
        'APPLE_TOKEN_API_UNAVAILABLE',
        'secret-provider-detail',
      ),
    );
    const response = await refresh().expect(503);
    expect(response.body).toEqual({
      statusCode: 503,
      message: 'Apple authentication is temporarily unavailable',
      error: 'Service Unavailable',
    });
    expect(session.revoked_at).toBeNull();
    expect(query.mock.calls.some(([sql]) => /UPDATE |INSERT /.test(sql))).toBe(
      false,
    );
    clock.mockReturnValue(now + 60_000);
    await refresh().expect(200);
    expect(validateRefreshToken).toHaveBeenCalledTimes(2);
    expect(JSON.stringify(errorLogs)).not.toContain('secret-provider-detail');
    expect(JSON.stringify(errorLogs)).not.toContain('secret-apple-token');
    expect(JSON.stringify(errorLogs)).not.toContain(
      identity.provider_refresh_token_ciphertext,
    );
  });

  it('sanitizes provider rejection after committing revocation', async () => {
    due = true;
    validateRefreshToken.mockRejectedValueOnce(
      new AppleAuthError(
        'APPLE_REFRESH_TOKEN_REJECTED',
        'secret-provider-detail',
      ),
    );
    const response = await refresh().expect(401);
    expect(response.body).toEqual({
      statusCode: 401,
      message: 'Invalid refresh token',
      error: 'Unauthorized',
    });
    expect(query.mock.calls.at(-1)?.[0]).toBe('COMMIT');
    expect(JSON.stringify(errorLogs)).not.toContain('secret-provider-detail');
  });
});
