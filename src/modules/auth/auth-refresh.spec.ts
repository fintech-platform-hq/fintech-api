import { InternalServerErrorException } from '@nestjs/common';
import { createHash } from 'crypto';
import { AuthService } from './auth.service';
import { AuthConfig } from './auth.config';
import { AppleAuthError, AppleAuthErrorCode } from './apple-auth.errors';

const identityId = '10000000-0000-4000-8000-000000000002';
const ciphertext = 'ciphertext-sentinel';

function fixture(apple = true, validationDue = true) {
  const identity = {
    id: identityId,
    provider_subject: 'subject',
    provider_refresh_token_ciphertext: ciphertext,
    revoked_at: null as Date | null,
  };
  const session = {
    user_id: '10000000-0000-4000-8000-000000000001',
    auth_identity_id: apple ? identityId : null,
    family_id: '10000000-0000-4000-8000-000000000003',
    expires_at: new Date('2099-01-01'),
    revoked_at: null as Date | null,
  };
  const query = jest.fn((sql: string): Promise<{ rows: unknown[] }> => {
    if (sql.includes('AS validation_due'))
      return Promise.resolve({ rows: [{ validation_due: validationDue }] });
    if (sql.includes('FROM auth_identities'))
      return Promise.resolve({ rows: [identity] });
    if (sql.includes('FROM refresh_sessions'))
      return Promise.resolve({ rows: [session] });
    return Promise.resolve({ rows: [] });
  });
  const release = jest.fn();
  const validateRefreshToken = jest
    .fn<Promise<void>, [string, string]>()
    .mockResolvedValue();
  const decrypt = jest.fn().mockReturnValue('provider-token-sentinel');
  const service = new AuthService(
    { getClient: jest.fn().mockResolvedValue({ query, release }) } as never,
    {
      jwtSecret: 'unit-secret',
      jwtIssuer: 'test',
      jwtAudience: 'test',
      accessTokenSeconds: 900,
    } as AuthConfig,
    { validateRefreshToken } as never,
    { decrypt } as never,
  );
  return {
    service,
    identity,
    session,
    query,
    release,
    validateRefreshToken,
    decrypt,
  };
}

describe('Apple refresh decisions and transaction cleanup', () => {
  afterEach(() => jest.restoreAllMocks());

  it.each([false, true])(
    'does not contact Apple for password or a fresh identity (apple=%s)',
    async (apple) => {
      const f = fixture(apple, false);
      const response = await f.service.refresh('fintech-token');
      expect(response.expiresIn).toBe(900);
      expect(f.decrypt).not.toHaveBeenCalled();
      expect(f.validateRefreshToken).not.toHaveBeenCalled();
      const claims = f.service.verifyAccessToken(response.accessToken);
      expect(claims.authMethod).toBe(apple ? 'apple' : 'password');
      if (!apple)
        expect(
          f.query.mock.calls.some(([sql]) => sql.includes('auth_identities')),
        ).toBe(false);
    },
  );

  it('uses the database decision even when the Node clock differs, updating success before rotation', async () => {
    jest.spyOn(Date, 'now').mockReturnValue(0);
    const f = fixture();
    await f.service.refresh('fintech-token');
    expect(f.validateRefreshToken).toHaveBeenCalledWith(
      'provider-token-sentinel',
      'subject',
    );
    const sql = f.query.mock.calls.map(([statement]) => statement);
    const success = sql.findIndex((s) =>
      s.includes('SET last_provider_validation_at = clock_timestamp()'),
    );
    expect(success).toBeGreaterThan(
      sql.findIndex((s) => s.includes('AS validation_due')),
    );
    expect(success).toBeLessThan(
      sql.findIndex((s) => s.includes('INSERT INTO refresh_sessions')),
    );
    expect(sql.indexOf('COMMIT')).toBeGreaterThan(success);
    expect(sql.findIndex((s) => s.includes('FOR NO KEY UPDATE'))).toBeLessThan(
      sql.findIndex((s) => s.includes('pg_advisory_xact_lock(hashtext($1))')),
    );
    expect(
      sql.findIndex((s) => s.includes('pg_advisory_xact_lock(hashtext($1))')),
    ).toBeLessThan(sql.findIndex((s) => s.includes('FOR UPDATE')));
  });

  it.each<AppleAuthErrorCode>([
    'APPLE_TOKEN_API_UNAVAILABLE',
    'INVALID_APPLE_CONFIGURATION',
    'INVALID_APPLE_TOKEN_RESPONSE',
    'INVALID_IDENTITY_TOKEN',
    'APPLE_TOKEN_REQUEST_REJECTED',
  ])('fails closed without writes for %s', async (code) => {
    const f = fixture();
    f.validateRefreshToken.mockRejectedValue(
      new AppleAuthError(code, 'secret-provider-detail'),
    );
    await expect(f.service.refresh('fintech-token')).rejects.toMatchObject({
      status: 503,
      message: 'Apple authentication is temporarily unavailable',
    });
    expect(
      f.query.mock.calls.some(([sql]) => /UPDATE |INSERT /.test(sql)),
    ).toBe(false);
    expect(f.query).toHaveBeenCalledWith('ROLLBACK');
    expect(f.query).not.toHaveBeenCalledWith('COMMIT');
    expect(f.release).toHaveBeenCalledTimes(1);
  });

  it('sanitizes cipher failure before Apple and leaves the session untouched', async () => {
    const f = fixture();
    f.decrypt.mockImplementation(() => {
      throw new Error('key-and-token-sentinel');
    });
    await expect(f.service.refresh('fintech-token')).rejects.toMatchObject({
      status: 503,
      message: 'Apple authentication is temporarily unavailable',
    });
    expect(f.validateRefreshToken).not.toHaveBeenCalled();
    expect(
      f.query.mock.calls.some(([sql]) => /UPDATE |INSERT /.test(sql)),
    ).toBe(false);
  });

  it('commits only selective revocation before returning 401 for invalid_grant', async () => {
    const f = fixture();
    f.validateRefreshToken.mockRejectedValue(
      new AppleAuthError('APPLE_REFRESH_TOKEN_REJECTED', 'secret'),
    );
    await expect(f.service.refresh('fintech-token')).rejects.toMatchObject({
      status: 401,
      message: 'Invalid refresh token',
    });
    const sql = f.query.mock.calls.map(([s]) => s);
    expect(sql.filter((s) => s.trimStart().startsWith('UPDATE '))).toHaveLength(
      2,
    );
    expect(sql.some((s) => s.includes('SET last_provider_validation_at'))).toBe(
      false,
    );
    expect(sql.some((s) => s.includes('INSERT INTO refresh_sessions'))).toBe(
      false,
    );
    expect(sql.at(-1)).toBe('COMMIT');
  });

  it('rejects an already revoked identity without contacting Apple', async () => {
    const f = fixture();
    f.identity.revoked_at = new Date();
    await expect(f.service.refresh('fintech-token')).rejects.toMatchObject({
      status: 401,
    });
    expect(f.validateRefreshToken).not.toHaveBeenCalled();
    expect(f.query).toHaveBeenCalledWith('COMMIT');
  });

  it('backs off until exactly 60s, then permits the same refresh token', async () => {
    const now = jest.spyOn(Date, 'now').mockReturnValue(1_000);
    const f = fixture();
    f.validateRefreshToken.mockRejectedValueOnce(
      new Error('secret-network-detail'),
    );
    await expect(f.service.refresh('same-token')).rejects.toMatchObject({
      status: 503,
    });
    now.mockReturnValue(60_999);
    await expect(f.service.refresh('same-token')).rejects.toMatchObject({
      status: 503,
    });
    expect(f.validateRefreshToken).toHaveBeenCalledTimes(1);
    now.mockReturnValue(61_000);
    await expect(f.service.refresh('same-token')).resolves.toMatchObject({
      expiresIn: 900,
    });
    expect(f.validateRefreshToken).toHaveBeenCalledTimes(2);
  });

  it('bounds backoff storage, evicts oldest insertion, and removes expired entries', async () => {
    const now = jest.spyOn(Date, 'now').mockReturnValue(1_000);
    const f = fixture();
    // Seed capacity without making 10,000 unrelated authentication requests.
    const entries = f.service['appleValidationBackoff'];
    for (let i = 0; i < 10_000; i++)
      entries.set(`identity-fingerprint-${i}`, 61_000);
    f.validateRefreshToken.mockRejectedValue(new Error('secret'));
    await expect(f.service.refresh('same-token')).rejects.toMatchObject({
      status: 503,
    });
    expect(entries.size).toBe(10_000);
    expect(entries.has('identity-fingerprint-0')).toBe(false);
    expect(
      entries.get(
        `${identityId}:${createHash('sha256').update(ciphertext).digest('hex')}`,
      ),
    ).toBe(61_000);
    expect(JSON.stringify([...entries])).not.toContain(ciphertext);
    now.mockReturnValue(61_000);
    f.validateRefreshToken.mockResolvedValue();
    await f.service.refresh('same-token');
    expect(entries.size).toBe(0);
  });

  it.each([false, true])(
    'sanitizes failed revocation commit, cleans up and releases (rollback fails=%s)',
    async (rollbackFails) => {
      const f = fixture();
      f.validateRefreshToken.mockRejectedValue(
        new AppleAuthError('APPLE_REFRESH_TOKEN_REJECTED', 'secret'),
      );
      const execute = f.query.getMockImplementation()!;
      f.query.mockImplementation((sql: string, values?: unknown[]) => {
        if (sql === 'COMMIT' || (sql === 'ROLLBACK' && rollbackFails))
          return Promise.reject(new Error('postgres-secret-detail'));
        return execute(sql, values);
      });
      await expect(f.service.refresh('fintech-token')).rejects.toBeInstanceOf(
        InternalServerErrorException,
      );
      expect(f.query).toHaveBeenCalledWith('ROLLBACK');
      expect(f.release).toHaveBeenCalledWith(rollbackFails ? true : undefined);
    },
  );
});
