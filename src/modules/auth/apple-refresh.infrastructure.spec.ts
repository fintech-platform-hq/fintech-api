import { generateKeyPairSync, sign } from 'crypto';
import { AppleApiClient } from './apple-api.client';
import { AppleRefreshTokenCipherService } from './apple-refresh-token-cipher.service';
import { AppleIdentityTokenVerifier } from './apple-identity-token.verifier';
import { AppleTokenService } from './apple-token.service';
import { AuthConfig } from './auth.config';

const config = {
  appleRefreshTokenEncryptionKey: Buffer.alloc(32, 7),
  appleClientId: 'client-id',
} as AuthConfig;
const cipher = new AppleRefreshTokenCipherService(config);
const token = 'secret-apple-refresh-token';
const identityId = 'identity-id';
const encrypted = cipher.encrypt(token, identityId);
const parts = encrypted.split('.');
const responseBody = {
  access_token: 'secret-apple-access',
  token_type: 'Bearer',
  expires_in: 3600,
  id_token: 'identity-jwt',
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

describe('Apple provider refresh infrastructure', () => {
  afterEach(() => jest.restoreAllMocks());

  it('decrypts the existing encrypted representation', () => {
    expect(cipher.decrypt(encrypted, identityId)).toBe(token);
  });

  it.each([
    ['extra segment', `${encrypted}.extra`],
    ['missing segment', parts.slice(0, 3).join('.')],
    ['wrong version', ['v2', ...parts.slice(1)].join('.')],
    ['empty ciphertext', [parts[0], parts[1], '', parts[3]].join('.')],
    [
      'short IV',
      ['v1', Buffer.alloc(11).toString('base64url'), parts[2], parts[3]].join(
        '.',
      ),
    ],
    [
      'short tag',
      [...parts.slice(0, 3), Buffer.alloc(15).toString('base64url')].join('.'),
    ],
    ['padded base64', ['v1', `${parts[1]}=`, parts[2], parts[3]].join('.')],
    ['invalid base64', ['v1', '%%%', parts[2], parts[3]].join('.')],
    [
      'tampered ciphertext',
      ['v1', parts[1], Buffer.alloc(25).toString('base64url'), parts[3]].join(
        '.',
      ),
    ],
    [
      'tampered tag',
      [...parts.slice(0, 3), Buffer.alloc(16).toString('base64url')].join('.'),
    ],
  ])('rejects %s without exposing the envelope', (_label, envelope) => {
    expect(() => cipher.decrypt(envelope, identityId)).toThrow(
      'Invalid Apple refresh token envelope',
    );
  });

  it('authenticates identity AAD and key before returning plaintext', () => {
    expect(() => cipher.decrypt(encrypted, 'other-identity')).toThrow(
      'Invalid Apple refresh token envelope',
    );
    const other = new AppleRefreshTokenCipherService({
      appleRefreshTokenEncryptionKey: Buffer.alloc(32, 9),
    } as AuthConfig);
    expect(() => other.decrypt(encrypted, identityId)).toThrow(
      'Invalid Apple refresh token envelope',
    );
  });

  it('submits one refresh grant and accepts a response without a new refresh token', async () => {
    const fetch = jest
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(json(responseBody));
    await expect(
      new AppleApiClient().validateRefreshToken(
        token,
        'client-id',
        'secret-client-jwt',
      ),
    ).resolves.toMatchObject({ idToken: 'identity-jwt' });
    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, options] = fetch.mock.calls[0];
    expect(url).toBe('https://appleid.apple.com/auth/token');
    expect(options).toMatchObject({ method: 'POST', redirect: 'error' });
    expect(options?.signal).toBeInstanceOf(AbortSignal);
    expect(Object.fromEntries(options?.body as URLSearchParams)).toEqual({
      grant_type: 'refresh_token',
      client_id: 'client-id',
      client_secret: 'secret-client-jwt',
      refresh_token: token,
    });
  });

  it.each([
    ['invalid_grant', 'APPLE_REFRESH_TOKEN_REJECTED'],
    ['invalid_client', 'INVALID_APPLE_CONFIGURATION'],
    ['unauthorized_client', 'INVALID_APPLE_CONFIGURATION'],
    ['invalid_request', 'APPLE_TOKEN_REQUEST_REJECTED'],
    ['unsupported_grant_type', 'APPLE_TOKEN_REQUEST_REJECTED'],
    ['invalid_scope', 'APPLE_TOKEN_REQUEST_REJECTED'],
    ['unknown', 'INVALID_APPLE_TOKEN_RESPONSE'],
  ])(
    'classifies %s without leaking provider detail or retrying',
    async (error, code) => {
      const fetch = jest
        .spyOn(globalThis, 'fetch')
        .mockResolvedValue(json({ error, error_description: token }, 400));
      const failure: unknown = await new AppleApiClient()
        .validateRefreshToken(token, 'client-id', 'secret-client-jwt')
        .catch((e: unknown) => e);
      expect(failure).toMatchObject({ code });
      expect(String(failure)).not.toContain(token);
      expect(fetch).toHaveBeenCalledTimes(1);
    },
  );

  it.each([429, 500, 503])(
    'treats HTTP %s as unavailable even if its body says invalid_grant',
    async (status) => {
      const fetch = jest
        .spyOn(globalThis, 'fetch')
        .mockResolvedValue(json({ error: 'invalid_grant' }, status));
      await expect(
        new AppleApiClient().validateRefreshToken(token, 'client-id', 'secret'),
      ).rejects.toMatchObject({ code: 'APPLE_TOKEN_API_UNAVAILABLE' });
      expect(fetch).toHaveBeenCalledTimes(1);
    },
  );

  it.each(['TimeoutError', 'TypeError'])(
    'does not retry %s or disclose fetch errors',
    async (name) => {
      const error = new Error(token);
      error.name = name;
      const fetch = jest.spyOn(globalThis, 'fetch').mockRejectedValue(error);
      await expect(
        new AppleApiClient().validateRefreshToken(token, 'client-id', 'secret'),
      ).rejects.toMatchObject({
        code: 'APPLE_TOKEN_API_UNAVAILABLE',
        message: 'Apple token API is unavailable',
      });
      expect(fetch).toHaveBeenCalledTimes(1);
    },
  );

  it.each([
    { ...responseBody, access_token: '' },
    { ...responseBody, expires_in: 0 },
    { ...responseBody, id_token: undefined },
    { ...responseBody, token_type: 'mac' },
  ])('rejects an incomplete refresh response', async (body) => {
    jest.spyOn(globalThis, 'fetch').mockResolvedValue(json(body));
    await expect(
      new AppleApiClient().validateRefreshToken(token, 'client-id', 'secret'),
    ).rejects.toMatchObject({ code: 'INVALID_APPLE_TOKEN_RESPONSE' });
  });
});

describe('Refresh identity JWT verification', () => {
  const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const getVerificationKey = jest.fn().mockResolvedValue(keys.publicKey);
  const verifier = new AppleIdentityTokenVerifier(config, {
    getVerificationKey,
  } as never);
  const jwt = (claims: Record<string, unknown> = {}, alg = 'RS256') => {
    const now = Math.floor(Date.now() / 1000);
    const encoded = [
      { alg, kid: 'key' },
      {
        iss: 'https://appleid.apple.com',
        aud: 'client-id',
        sub: 'subject',
        iat: now,
        exp: now + 300,
        ...claims,
      },
    ]
      .map((v) => Buffer.from(JSON.stringify(v)).toString('base64url'))
      .join('.');
    return `${encoded}.${sign('RSA-SHA256', Buffer.from(encoded), keys.privateKey).toString('base64url')}`;
  };
  afterEach(() => jest.restoreAllMocks());

  it.each([{}, { nonce: 'old-interactive-nonce' }])(
    'accepts refresh JWT without requiring interactive nonce',
    async (claims) => {
      await expect(
        verifier.verifyRefreshToken(jwt(claims)),
      ).resolves.toMatchObject({ subject: 'subject' });
    },
  );

  it.each([
    { iss: 'other' },
    { aud: 'other' },
    { exp: 1 },
    { iat: 4_000_000_000 },
    { sub: '' },
  ])('rejects invalid JWT claims', async (claims) => {
    await expect(
      verifier.verifyRefreshToken(jwt(claims)),
    ).rejects.toMatchObject({ code: 'INVALID_IDENTITY_TOKEN' });
  });

  it('requires RS256 and an authentic signature', async () => {
    await expect(
      verifier.verifyRefreshToken(jwt({}, 'HS256')),
    ).rejects.toMatchObject({ code: 'INVALID_IDENTITY_TOKEN' });
    const segments = jwt().split('.');
    segments[2] = Buffer.alloc(256).toString('base64url');
    await expect(
      verifier.verifyRefreshToken(segments.join('.')),
    ).rejects.toMatchObject({ code: 'INVALID_IDENTITY_TOKEN' });
  });

  it('generates a client secret for each request and rejects a different subject', async () => {
    const validateRefreshToken = jest
      .fn()
      .mockResolvedValue({ idToken: jwt() });
    const generate = jest.fn().mockReturnValue('new-client-secret');
    const service = new AppleTokenService(
      { validateRefreshToken } as never,
      { generate } as never,
      verifier,
      config,
    );
    await service.validateRefreshToken(token, 'subject');
    await expect(
      service.validateRefreshToken(token, 'other'),
    ).rejects.toMatchObject({ code: 'INVALID_IDENTITY_TOKEN' });
    expect(generate).toHaveBeenCalledTimes(2);
    expect(validateRefreshToken).toHaveBeenCalledWith(
      token,
      'client-id',
      'new-client-secret',
    );
  });
});
