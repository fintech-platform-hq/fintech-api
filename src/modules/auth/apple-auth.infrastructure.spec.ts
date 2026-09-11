import { Test } from '@nestjs/testing';
import {
  constants,
  createDecipheriv,
  generateKeyPairSync,
  KeyObject,
  sign,
  verify,
} from 'crypto';
import { AppleApiClient } from './apple-api.client';
import { DatabaseService } from '../../common/database/database.service';
import { AppleAuthError } from './apple-auth.errors';
import { AppleClientSecretService } from './apple-client-secret.service';
import { AppleIdentityTokenVerifier } from './apple-identity-token.verifier';
import { AppleJwksService } from './apple-jwks.service';
import { AppleRefreshTokenCipherService } from './apple-refresh-token-cipher.service';
import { AppleTokenService } from './apple-token.service';
import { AuthConfig } from './auth.config';
import { AuthModule } from './auth.module';

const CLIENT_ID = 'com.example.fintech';
const NOW_SECONDS = 2_000_000_000;
const rsaKeys = generateKeyPairSync('rsa', { modulusLength: 2_048 });
const ecKeys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

describe('Apple authentication infrastructure', () => {
  afterEach(() => jest.restoreAllMocks());

  describe('AuthConfig', () => {
    const names = [
      'JWT_ACCESS_SECRET',
      'JWT_ISSUER',
      'JWT_AUDIENCE',
      'APPLE_CLIENT_ID',
      'APPLE_TEAM_ID',
      'APPLE_KEY_ID',
      'APPLE_PRIVATE_KEY_P8',
      'APPLE_REFRESH_TOKEN_ENCRYPTION_KEY',
    ] as const;
    const original = new Map(names.map((name) => [name, process.env[name]]));

    beforeEach(() => {
      process.env.JWT_ACCESS_SECRET = '01234567890123456789012345678901';
      process.env.JWT_ISSUER = 'fintech-api-test';
      process.env.JWT_AUDIENCE = 'fintech-clients-test';
      for (const name of names.slice(3)) delete process.env[name];
    });

    afterAll(() => {
      for (const [name, value] of original) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    });

    it('keeps Apple configuration lazy', () => {
      const config = new AuthConfig();
      expect(config.jwtIssuer).toBe('fintech-api-test');
      expect(() => config.appleClientId).toThrow(AppleAuthError);
    });

    it('validates identifiers and normalizes escaped private-key newlines', () => {
      process.env.APPLE_CLIENT_ID = CLIENT_ID;
      process.env.APPLE_TEAM_ID = 'TEAMID1234';
      process.env.APPLE_KEY_ID = 'KEYID12345';
      process.env.APPLE_PRIVATE_KEY_P8 =
        '-----BEGIN PRIVATE KEY-----\\nvalue\\n-----END PRIVATE KEY-----\\n';
      const config = new AuthConfig();

      expect(config.appleClientId).toBe(CLIENT_ID);
      expect(config.appleTeamId).toBe('TEAMID1234');
      expect(config.appleKeyId).toBe('KEYID12345');
      expect(config.applePrivateKeyP8).toContain('\nvalue\n');
    });

    it('accepts only a canonical 32-byte Apple refresh-token key', () => {
      process.env.APPLE_REFRESH_TOKEN_ENCRYPTION_KEY = Buffer.alloc(
        32,
        7,
      ).toString('base64url');
      expect(new AuthConfig().appleRefreshTokenEncryptionKey).toEqual(
        Buffer.alloc(32, 7),
      );

      process.env.APPLE_REFRESH_TOKEN_ENCRYPTION_KEY = 'too-short';
      expect(() => new AuthConfig().appleRefreshTokenEncryptionKey).toThrow(
        AppleAuthError,
      );
    });

    it.each([
      ['APPLE_CLIENT_ID', ' surrounding '],
      ['APPLE_TEAM_ID', 'short'],
      ['APPLE_KEY_ID', 'not-valid!'],
    ])('rejects invalid %s', (name, value) => {
      process.env.APPLE_CLIENT_ID = CLIENT_ID;
      process.env.APPLE_TEAM_ID = 'TEAMID1234';
      process.env.APPLE_KEY_ID = 'KEYID12345';
      process.env[name] = value;
      const config = new AuthConfig();

      expect(() => {
        if (name === 'APPLE_CLIENT_ID') void config.appleClientId;
        if (name === 'APPLE_TEAM_ID') void config.appleTeamId;
        if (name === 'APPLE_KEY_ID') void config.appleKeyId;
      }).toThrow(AppleAuthError);
    });
  });

  describe('AppleApiClient', () => {
    it('fetches only the official JWKS endpoint with bounded options', async () => {
      const payload = { keys: [] };
      const fetchMock = jest
        .spyOn(globalThis, 'fetch')
        .mockResolvedValue(new Response(JSON.stringify(payload)));

      await expect(new AppleApiClient().fetchJwks()).resolves.toEqual(payload);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [url, options] = fetchMock.mock.calls[0];
      expect(url).toBe('https://appleid.apple.com/auth/keys');
      expect(options?.headers).toEqual({ Accept: 'application/json' });
      expect(options?.redirect).toBe('error');
      expect(options?.signal).toBeInstanceOf(AbortSignal);
    });

    it.each([
      [
        'non-success response',
        Promise.resolve(new Response('', { status: 503 })),
      ],
      ['invalid JSON', Promise.resolve(new Response('not-json'))],
      ['network failure', Promise.reject(new Error('offline'))],
    ])('maps %s to an unavailable JWKS error', async (_case, result) => {
      jest.spyOn(globalThis, 'fetch').mockReturnValue(result);
      await expect(new AppleApiClient().fetchJwks()).rejects.toMatchObject({
        code: 'APPLE_JWKS_UNAVAILABLE',
      });
    });

    it('exchanges an authorization code once with the exact token contract', async () => {
      const payload = appleTokenResponse();
      const fetchMock = jest
        .spyOn(globalThis, 'fetch')
        .mockResolvedValue(jsonResponse(payload));

      await expect(
        new AppleApiClient().exchangeAuthorizationCode(
          'code + value',
          CLIENT_ID,
          'client.secret',
        ),
      ).resolves.toEqual({
        accessToken: 'apple-access-token',
        expiresIn: 3600,
        idToken: 'header.payload.signature',
        refreshToken: 'apple-refresh-token',
      });

      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [url, options] = fetchMock.mock.calls[0];
      expect(url).toBe('https://appleid.apple.com/auth/token');
      expect(options?.method).toBe('POST');
      expect(options?.headers).toEqual({
        Accept: 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
      });
      expect(options?.redirect).toBe('error');
      expect(options?.signal).toBeInstanceOf(AbortSignal);
      expect(options?.body).toBeInstanceOf(URLSearchParams);
      expect((options?.body as URLSearchParams).toString()).toBe(
        'client_id=com.example.fintech&client_secret=client.secret&code=code+%2B+value&grant_type=authorization_code',
      );
      expect((options?.body as URLSearchParams).has('redirect_uri')).toBe(
        false,
      );
    });

    it.each([
      ['missing access token', { access_token: undefined }],
      ['wrong token type', { token_type: 'mac' }],
      ['non-positive expiry', { expires_in: 0 }],
      ['non-integer expiry', { expires_in: 1.5 }],
      ['missing refresh token', { refresh_token: undefined }],
      ['missing identity token', { id_token: undefined }],
    ])('rejects a token response with %s', async (_case, replacement) => {
      jest
        .spyOn(globalThis, 'fetch')
        .mockResolvedValue(
          jsonResponse({ ...appleTokenResponse(), ...replacement }),
        );

      await expect(
        new AppleApiClient().exchangeAuthorizationCode(
          'code',
          CLIENT_ID,
          'secret',
        ),
      ).rejects.toMatchObject({ code: 'INVALID_APPLE_TOKEN_RESPONSE' });
    });

    it('accepts the documented bearer token type case-insensitively', async () => {
      jest
        .spyOn(globalThis, 'fetch')
        .mockResolvedValue(jsonResponse(appleTokenResponse('bearer')));

      await expect(
        new AppleApiClient().exchangeAuthorizationCode(
          'code',
          CLIENT_ID,
          'secret',
        ),
      ).resolves.toMatchObject({ accessToken: 'apple-access-token' });
    });

    it.each([
      ['invalid_grant', 'APPLE_AUTHORIZATION_CODE_REJECTED'],
      ['invalid_client', 'INVALID_APPLE_CONFIGURATION'],
      ['unauthorized_client', 'INVALID_APPLE_CONFIGURATION'],
      ['invalid_request', 'APPLE_TOKEN_REQUEST_REJECTED'],
      ['unsupported_grant_type', 'APPLE_TOKEN_REQUEST_REJECTED'],
      ['invalid_scope', 'APPLE_TOKEN_REQUEST_REJECTED'],
    ])(
      'maps Apple error %s without exposing its request',
      async (error, code) => {
        jest
          .spyOn(globalThis, 'fetch')
          .mockResolvedValue(jsonResponse({ error }, { status: 400 }));

        await expect(
          new AppleApiClient().exchangeAuthorizationCode(
            'sensitive-code',
            CLIENT_ID,
            'sensitive-secret',
          ),
        ).rejects.toMatchObject({ code });
      },
    );

    it.each([
      [
        'unknown Apple error',
        jsonResponse({ error: 'new_error' }, { status: 400 }),
        'INVALID_APPLE_TOKEN_RESPONSE',
      ],
      [
        'malformed JSON',
        new Response('not-json', {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
        'INVALID_APPLE_TOKEN_RESPONSE',
      ],
      [
        'wrong content type',
        new Response('{}', { status: 200 }),
        'INVALID_APPLE_TOKEN_RESPONSE',
      ],
      [
        'server failure',
        new Response('', { status: 503 }),
        'APPLE_TOKEN_API_UNAVAILABLE',
      ],
      [
        'unexpected status',
        new Response('', { status: 418 }),
        'APPLE_TOKEN_API_UNAVAILABLE',
      ],
    ])('maps %s without retrying', async (_case, response, code) => {
      const fetchMock = jest
        .spyOn(globalThis, 'fetch')
        .mockResolvedValue(response);

      await expect(
        new AppleApiClient().exchangeAuthorizationCode(
          'code',
          CLIENT_ID,
          'secret',
        ),
      ).rejects.toMatchObject({ code });
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it('maps a network failure without retrying', async () => {
      const fetchMock = jest
        .spyOn(globalThis, 'fetch')
        .mockRejectedValue(new Error('offline'));

      await expect(
        new AppleApiClient().exchangeAuthorizationCode(
          'code',
          CLIENT_ID,
          'secret',
        ),
      ).rejects.toMatchObject({ code: 'APPLE_TOKEN_API_UNAVAILABLE' });
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });
  });

  describe('AppleJwksService', () => {
    it('caches an imported key for one hour', async () => {
      const fetchJwks = jest
        .fn()
        .mockResolvedValue({ keys: [rsaJwk('known')] });
      const service = jwksService(fetchJwks);
      const now = jest.spyOn(Date, 'now').mockReturnValue(0);

      const first = await service.getVerificationKey('known');
      now.mockReturnValue(3_599_999);
      const second = await service.getVerificationKey('known');

      expect(first).toBe(second);
      expect(fetchJwks).toHaveBeenCalledTimes(1);
    });

    it('refreshes expired keys', async () => {
      const fetchJwks = jest
        .fn()
        .mockResolvedValue({ keys: [rsaJwk('known')] });
      const service = jwksService(fetchJwks);
      const now = jest.spyOn(Date, 'now').mockReturnValue(0);

      await service.getVerificationKey('known');
      now.mockReturnValue(3_600_000);
      await service.getVerificationKey('known');

      expect(fetchJwks).toHaveBeenCalledTimes(2);
    });

    it('backs off after an expired-cache refresh failure without using stale keys', async () => {
      const unavailable = new AppleAuthError(
        'APPLE_JWKS_UNAVAILABLE',
        'unavailable',
      );
      const fetchJwks = jest
        .fn()
        .mockResolvedValueOnce({ keys: [rsaJwk('known')] })
        .mockRejectedValueOnce(unavailable)
        .mockResolvedValueOnce({ keys: [rsaJwk('known')] });
      const service = jwksService(fetchJwks);
      const now = jest.spyOn(Date, 'now').mockReturnValue(0);

      await service.getVerificationKey('known');
      now.mockReturnValue(3_600_000);
      await expect(service.getVerificationKey('known')).rejects.toBe(
        unavailable,
      );
      now.mockReturnValue(3_659_999);
      await expect(service.getVerificationKey('known')).rejects.toMatchObject({
        code: 'APPLE_JWKS_UNAVAILABLE',
      });
      expect(fetchJwks).toHaveBeenCalledTimes(2);

      now.mockReturnValue(3_660_000);
      await expect(service.getVerificationKey('known')).resolves.toBeInstanceOf(
        KeyObject,
      );
      expect(fetchJwks).toHaveBeenCalledTimes(3);
    });

    it('shares one refresh across concurrent requests', async () => {
      let resolve!: (value: unknown) => void;
      const fetchJwks = jest.fn(
        () => new Promise<unknown>((done) => (resolve = done)),
      );
      const service = jwksService(fetchJwks);

      const first = service.getVerificationKey('known');
      const second = service.getVerificationKey('known');
      expect(fetchJwks).toHaveBeenCalledTimes(1);
      resolve({ keys: [rsaJwk('known')] });

      await expect(Promise.all([first, second])).resolves.toHaveLength(2);
    });

    it('refreshes once for an unknown kid after the cooldown', async () => {
      const fetchJwks = jest
        .fn()
        .mockResolvedValueOnce({ keys: [rsaJwk('known')] })
        .mockResolvedValueOnce({ keys: [rsaJwk('rotated')] });
      const service = jwksService(fetchJwks);
      const now = jest.spyOn(Date, 'now').mockReturnValue(0);

      await service.getVerificationKey('known');
      now.mockReturnValue(60_000);
      await expect(
        service.getVerificationKey('rotated'),
      ).resolves.toBeInstanceOf(KeyObject);
      expect(fetchJwks).toHaveBeenCalledTimes(2);
    });

    it('rejects repeated unknown kids without bypassing the cooldown', async () => {
      const fetchJwks = jest
        .fn()
        .mockResolvedValue({ keys: [rsaJwk('known')] });
      const service = jwksService(fetchJwks);
      jest.spyOn(Date, 'now').mockReturnValue(0);
      await service.getVerificationKey('known');

      await expect(service.getVerificationKey('unknown')).rejects.toMatchObject(
        {
          code: 'UNKNOWN_APPLE_KID',
        },
      );
      await expect(service.getVerificationKey('other')).rejects.toMatchObject({
        code: 'UNKNOWN_APPLE_KID',
      });
      expect(fetchJwks).toHaveBeenCalledTimes(1);
    });

    it('throttles unknown-kid refreshes after a failed attempt', async () => {
      const unavailable = new AppleAuthError(
        'APPLE_JWKS_UNAVAILABLE',
        'unavailable',
      );
      const fetchJwks = jest
        .fn()
        .mockResolvedValueOnce({ keys: [rsaJwk('known')] })
        .mockRejectedValueOnce(unavailable);
      const service = jwksService(fetchJwks);
      const now = jest.spyOn(Date, 'now').mockReturnValue(0);
      await service.getVerificationKey('known');

      now.mockReturnValue(60_000);
      await expect(service.getVerificationKey('unknown')).rejects.toBe(
        unavailable,
      );
      now.mockReturnValue(60_001);
      await expect(service.getVerificationKey('other')).rejects.toMatchObject({
        code: 'UNKNOWN_APPLE_KID',
      });
      expect(fetchJwks).toHaveBeenCalledTimes(2);
    });

    it.each([
      ['missing keys', {}],
      ['empty keys', { keys: [] }],
      ['malformed key', { keys: [{}] }],
      ['duplicate kid', { keys: [rsaJwk('duplicate'), rsaJwk('duplicate')] }],
    ])('rejects a JWKS response with %s', async (_case, response) => {
      const service = jwksService(jest.fn().mockResolvedValue(response));
      await expect(service.getVerificationKey('known')).rejects.toMatchObject({
        code: 'APPLE_JWKS_UNAVAILABLE',
      });
    });

    it.each([
      ['wrong key type', { ...rsaJwk('known'), kty: 'EC' }],
      ['wrong algorithm', { ...rsaJwk('known'), alg: 'PS256' }],
      ['wrong use', { ...rsaJwk('known'), use: 'enc' }],
      ['missing modulus', { ...rsaJwk('known'), n: '' }],
    ])('rejects a selected key with %s', async (_case, key) => {
      const service = jwksService(jest.fn().mockResolvedValue({ keys: [key] }));
      await expect(service.getVerificationKey('known')).rejects.toMatchObject({
        code: 'INVALID_IDENTITY_TOKEN',
      });
    });
  });

  describe('AppleIdentityTokenVerifier', () => {
    beforeEach(() =>
      jest.spyOn(Date, 'now').mockReturnValue(NOW_SECONDS * 1_000),
    );

    it('verifies a valid RS256 token and returns only its subject', async () => {
      const { verifier, getVerificationKey } = identityVerifier();
      await expect(
        verifier.verify(identityToken(), 'expected-nonce'),
      ).resolves.toEqual({ subject: 'apple-subject' });
      expect(getVerificationKey).toHaveBeenCalledWith('apple-key');
    });

    it('returns only verified normalized Apple email metadata', async () => {
      const { verifier } = identityVerifier();
      await expect(
        verifier.verify(
          identityToken({
            email: ' Relay@PrivateRelay.AppleID.com ',
            email_verified: 'true',
            is_private_email: 'true',
          }),
          'expected-nonce',
        ),
      ).resolves.toEqual({
        subject: 'apple-subject',
        email: 'relay@privaterelay.appleid.com',
        isPrivateEmail: true,
      });
      await expect(
        verifier.verify(
          identityToken({
            email: 'ignored@example.com',
            email_verified: false,
          }),
          'expected-nonce',
        ),
      ).resolves.toEqual({ subject: 'apple-subject' });
    });

    it.each(['none', 'HS256', 'ES256'])(
      'rejects %s before requesting a verification key',
      async (algorithm) => {
        const { verifier, getVerificationKey } = identityVerifier();
        await expect(
          verifier.verify(
            identityToken({}, { alg: algorithm }),
            'expected-nonce',
          ),
        ).rejects.toMatchObject({ code: 'INVALID_IDENTITY_TOKEN' });
        expect(getVerificationKey).not.toHaveBeenCalled();
      },
    );

    it('rejects an unknown kid', async () => {
      const error = new AppleAuthError('UNKNOWN_APPLE_KID', 'unknown');
      const { verifier } = identityVerifier(Promise.reject(error));
      await expect(
        verifier.verify(identityToken(), 'expected-nonce'),
      ).rejects.toBe(error);
    });

    it('rejects a tampered signature', async () => {
      const { verifier } = identityVerifier();
      const [header, payload] = identityToken().split('.');
      const invalidSignature = Buffer.alloc(256).toString('base64url');
      await expect(
        verifier.verify(
          `${header}.${payload}.${invalidSignature}`,
          'expected-nonce',
        ),
      ).rejects.toMatchObject({ code: 'INVALID_IDENTITY_TOKEN' });
    });

    it.each([
      ['issuer', { iss: 'https://example.com' }],
      ['audience', { aud: 'other-client' }],
      ['expired timestamp', { exp: NOW_SECONDS - 60 }],
      ['future issued-at timestamp', { iat: NOW_SECONDS + 61 }],
      ['inverted timestamps', { iat: NOW_SECONDS + 10, exp: NOW_SECONDS + 10 }],
      ['empty subject', { sub: '' }],
      ['blank subject', { sub: ' ' }],
      ['missing nonce', { nonce: undefined }],
      ['mismatched nonce', { nonce: 'different' }],
    ])('rejects an invalid %s claim', async (_case, claims) => {
      const { verifier } = identityVerifier();
      await expect(
        verifier.verify(identityToken(claims), 'expected-nonce'),
      ).rejects.toMatchObject({ code: 'INVALID_IDENTITY_TOKEN' });
    });

    it('accepts timestamps at the approved 60-second skew boundary', async () => {
      const { verifier } = identityVerifier();
      await expect(
        verifier.verify(
          identityToken({
            iat: NOW_SECONDS + 60,
            exp: NOW_SECONDS + 120,
          }),
          'expected-nonce',
        ),
      ).resolves.toEqual({ subject: 'apple-subject' });

      await expect(
        verifier.verify(
          identityToken({
            iat: NOW_SECONDS - 120,
            exp: NOW_SECONDS - 59,
          }),
          'expected-nonce',
        ),
      ).resolves.toEqual({ subject: 'apple-subject' });
    });

    it.each([
      ['two segments', 'header.payload'],
      ['invalid base64url', '%%%.payload.signature'],
      [
        'invalid JSON',
        `${Buffer.from('no').toString('base64url')}.e30.signature`,
      ],
    ])('rejects malformed compact JWS with %s', async (_case, token) => {
      const { verifier } = identityVerifier();
      await expect(
        verifier.verify(token, 'expected-nonce'),
      ).rejects.toMatchObject({ code: 'INVALID_IDENTITY_TOKEN' });
    });

    it('rejects unsupported critical headers and an empty expected nonce', async () => {
      const { verifier } = identityVerifier();
      await expect(
        verifier.verify(
          identityToken({}, { crit: ['example'] }),
          'expected-nonce',
        ),
      ).rejects.toMatchObject({ code: 'INVALID_IDENTITY_TOKEN' });
      await expect(verifier.verify(identityToken(), '')).rejects.toMatchObject({
        code: 'INVALID_IDENTITY_TOKEN',
      });
    });

    it('validates a token-endpoint identity with an optional matching nonce', async () => {
      const { verifier } = identityVerifier();
      await expect(
        verifier.verifyTokenResponse(identityToken(), 'expected-nonce'),
      ).resolves.toEqual({ subject: 'apple-subject' });
      await expect(
        verifier.verifyTokenResponse(
          identityToken({ nonce: undefined }),
          'expected-nonce',
        ),
      ).resolves.toEqual({ subject: 'apple-subject' });
      await expect(
        verifier.verifyTokenResponse(
          identityToken({ nonce: 'different' }),
          'expected-nonce',
        ),
      ).rejects.toMatchObject({ code: 'INVALID_IDENTITY_TOKEN' });
    });
  });

  describe('AppleClientSecretService', () => {
    beforeEach(() =>
      jest.spyOn(Date, 'now').mockReturnValue(NOW_SECONDS * 1_000),
    );

    it('generates a five-minute ES256 client secret with a JOSE signature', () => {
      const service = new AppleClientSecretService(clientSecretConfig());
      const token = service.generate();
      const [header, payload, signature] = token.split('.');

      expect(decodeJson(header)).toEqual({ alg: 'ES256', kid: 'KEYID12345' });
      expect(decodeJson(payload)).toEqual({
        iss: 'TEAMID1234',
        iat: NOW_SECONDS,
        exp: NOW_SECONDS + 300,
        aud: 'https://appleid.apple.com',
        sub: CLIENT_ID,
      });
      const signatureBytes = Buffer.from(signature, 'base64url');
      expect(signatureBytes).toHaveLength(64);
      expect(
        verify(
          'sha256',
          Buffer.from(`${header}.${payload}`, 'ascii'),
          { key: ecKeys.publicKey, dsaEncoding: 'ieee-p1363' },
          signatureBytes,
        ),
      ).toBe(true);
    });

    it.each([
      [
        'RSA key',
        rsaKeys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
      ],
      [
        'non-P-256 key',
        generateKeyPairSync('ec', { namedCurve: 'secp384r1' })
          .privateKey.export({ format: 'pem', type: 'pkcs8' })
          .toString(),
      ],
      ['malformed key', 'not-a-private-key'],
    ])('rejects a %s', (_case, privateKey) => {
      const service = new AppleClientSecretService(
        clientSecretConfig(privateKey),
      );
      expect(() => service.generate()).toThrow(AppleAuthError);
    });

    it('uses normalized escaped PEM configuration', () => {
      const pem = ecKeys.privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString();
      process.env.JWT_ACCESS_SECRET = '01234567890123456789012345678901';
      process.env.JWT_ISSUER = 'fintech-api-test';
      process.env.JWT_AUDIENCE = 'fintech-clients-test';
      process.env.APPLE_CLIENT_ID = CLIENT_ID;
      process.env.APPLE_TEAM_ID = 'TEAMID1234';
      process.env.APPLE_KEY_ID = 'KEYID12345';
      process.env.APPLE_PRIVATE_KEY_P8 = pem.replace(/\n/g, '\\n');

      expect(
        new AppleClientSecretService(new AuthConfig()).generate().split('.'),
      ).toHaveLength(3);
    });
  });

  describe('AppleRefreshTokenCipherService', () => {
    it('encrypts with a versioned AES-256-GCM envelope bound to the identity', () => {
      const key = Buffer.alloc(32, 9);
      const service = new AppleRefreshTokenCipherService({
        appleRefreshTokenEncryptionKey: key,
      } as AuthConfig);
      const identityId = '30000000-0000-4000-8000-000000000001';

      const encrypted = service.encrypt('sensitive-refresh-token', identityId);
      const [version, encodedIv, encodedCiphertext, encodedTag] =
        encrypted.split('.');
      expect(version).toBe('v1');
      expect(encrypted).not.toContain('sensitive-refresh-token');

      const decipher = createDecipheriv(
        'aes-256-gcm',
        key,
        Buffer.from(encodedIv, 'base64url'),
      );
      decipher.setAAD(
        Buffer.from(`apple-refresh-token:v1:${identityId}`, 'utf8'),
      );
      decipher.setAuthTag(Buffer.from(encodedTag, 'base64url'));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(encodedCiphertext, 'base64url')),
        decipher.final(),
      ]).toString('utf8');
      expect(plaintext).toBe('sensitive-refresh-token');
      expect(service.encrypt('sensitive-refresh-token', identityId)).not.toBe(
        encrypted,
      );
    });
  });

  describe('AppleTokenService', () => {
    it('validates both identities and returns subject, refresh token, and verified metadata', async () => {
      const verify = jest.fn().mockResolvedValue({
        subject: 'apple-subject',
        email: 'relay@privaterelay.appleid.com',
        isPrivateEmail: true,
      });
      const verifyTokenResponse = jest
        .fn()
        .mockResolvedValue({ subject: 'apple-subject' });
      const exchangeAuthorizationCode = jest.fn().mockResolvedValue({
        ...parsedAppleTokenResponse(),
        idToken: 'exchanged-identity-token',
      });
      const generate = jest.fn().mockReturnValue('new-client-secret');
      const service = appleTokenService({
        verify,
        verifyTokenResponse,
        exchangeAuthorizationCode,
        generate,
      });

      await expect(
        service.exchangeAuthorizationCode(
          'original-identity-token',
          'authorization-code',
          'expected-nonce',
        ),
      ).resolves.toEqual({
        subject: 'apple-subject',
        refreshToken: 'apple-refresh-token',
        email: 'relay@privaterelay.appleid.com',
        isPrivateEmail: true,
      });
      expect(verify).toHaveBeenCalledWith(
        'original-identity-token',
        'expected-nonce',
      );
      expect(generate).toHaveBeenCalledTimes(1);
      expect(exchangeAuthorizationCode).toHaveBeenCalledWith(
        'authorization-code',
        CLIENT_ID,
        'new-client-secret',
      );
      expect(verifyTokenResponse).toHaveBeenCalledWith(
        'exchanged-identity-token',
        'expected-nonce',
      );
    });

    it('rejects conflicting verified emails between the two identity tokens', async () => {
      const service = appleTokenService({
        verify: jest.fn().mockResolvedValue({
          subject: 'apple-subject',
          email: 'first@example.com',
        }),
        verifyTokenResponse: jest.fn().mockResolvedValue({
          subject: 'apple-subject',
          email: 'second@example.com',
        }),
      });

      await expect(
        service.exchangeAuthorizationCode('identity', 'code', 'nonce'),
      ).rejects.toMatchObject({ code: 'INVALID_IDENTITY_TOKEN' });
    });

    it('does not contact Apple when the original identity is invalid', async () => {
      const invalid = new AppleAuthError('INVALID_IDENTITY_TOKEN', 'invalid');
      const verify = jest.fn().mockRejectedValue(invalid);
      const exchangeAuthorizationCode = jest.fn();
      const service = appleTokenService({
        verify,
        exchangeAuthorizationCode,
      });

      await expect(
        service.exchangeAuthorizationCode('identity', 'code', 'nonce'),
      ).rejects.toBe(invalid);
      expect(exchangeAuthorizationCode).not.toHaveBeenCalled();
    });

    it('rejects a different subject from the exchanged identity token', async () => {
      const service = appleTokenService({
        verify: jest.fn().mockResolvedValue({ subject: 'original-subject' }),
        verifyTokenResponse: jest
          .fn()
          .mockResolvedValue({ subject: 'different-subject' }),
      });

      await expect(
        service.exchangeAuthorizationCode('identity', 'code', 'nonce'),
      ).rejects.toMatchObject({ code: 'INVALID_IDENTITY_TOKEN' });
    });

    it('rejects an empty code without generating a secret or making a request', async () => {
      const generate = jest.fn();
      const exchangeAuthorizationCode = jest.fn();
      const service = appleTokenService({
        generate,
        exchangeAuthorizationCode,
      });

      await expect(
        service.exchangeAuthorizationCode('identity', '', 'nonce'),
      ).rejects.toMatchObject({
        code: 'APPLE_AUTHORIZATION_CODE_REJECTED',
      });
      expect(generate).not.toHaveBeenCalled();
      expect(exchangeAuthorizationCode).not.toHaveBeenCalled();
    });

    it('propagates an ambiguous exchange failure without retrying', async () => {
      const unavailable = new AppleAuthError(
        'APPLE_TOKEN_API_UNAVAILABLE',
        'unavailable',
      );
      const exchangeAuthorizationCode = jest
        .fn()
        .mockRejectedValue(unavailable);
      const service = appleTokenService({ exchangeAuthorizationCode });

      await expect(
        service.exchangeAuthorizationCode('identity', 'code', 'nonce'),
      ).rejects.toBe(unavailable);
      expect(exchangeAuthorizationCode).toHaveBeenCalledTimes(1);
    });
  });

  it('registers dormant Apple providers without requiring Apple environment', async () => {
    process.env.JWT_ACCESS_SECRET = '01234567890123456789012345678901';
    process.env.JWT_ISSUER = 'fintech-api-test';
    process.env.JWT_AUDIENCE = 'fintech-clients-test';
    delete process.env.APPLE_CLIENT_ID;
    delete process.env.APPLE_TEAM_ID;
    delete process.env.APPLE_KEY_ID;
    delete process.env.APPLE_PRIVATE_KEY_P8;
    delete process.env.APPLE_REFRESH_TOKEN_ENCRYPTION_KEY;

    const module = await Test.createTestingModule({ imports: [AuthModule] })
      .overrideProvider(DatabaseService)
      .useValue({ query: jest.fn(), getClient: jest.fn() })
      .compile();
    expect(module.get(AppleIdentityTokenVerifier)).toBeDefined();
    expect(module.get(AppleClientSecretService)).toBeDefined();
    expect(module.get(AppleTokenService)).toBeDefined();
    expect(module.get(AppleRefreshTokenCipherService)).toBeDefined();
    await module.close();
  });
});

function jwksService(fetchJwks: jest.Mock): AppleJwksService {
  return new AppleJwksService({ fetchJwks });
}

function rsaJwk(kid: string): Record<string, unknown> {
  const key = rsaKeys.publicKey.export({ format: 'jwk' });
  return { ...key, alg: 'RS256', kid, use: 'sig' };
}

function identityVerifier(
  key: Promise<KeyObject> = Promise.resolve(rsaKeys.publicKey),
) {
  const getVerificationKey = jest.fn().mockReturnValue(key);
  const verifier = new AppleIdentityTokenVerifier(
    { appleClientId: CLIENT_ID } as AuthConfig,
    { getVerificationKey } as unknown as AppleJwksService,
  );
  return { verifier, getVerificationKey };
}

function identityToken(
  claims: Record<string, unknown> = {},
  headerClaims: Record<string, unknown> = {},
): string {
  const header = encodeJson({
    alg: 'RS256',
    kid: 'apple-key',
    ...headerClaims,
  });
  const payload = encodeJson({
    iss: 'https://appleid.apple.com',
    aud: CLIENT_ID,
    iat: NOW_SECONDS,
    exp: NOW_SECONDS + 300,
    sub: 'apple-subject',
    nonce: 'expected-nonce',
    ...claims,
  });
  const signature = sign(
    'RSA-SHA256',
    Buffer.from(`${header}.${payload}`, 'ascii'),
    { key: rsaKeys.privateKey, padding: constants.RSA_PKCS1_PADDING },
  );
  return `${header}.${payload}.${signature.toString('base64url')}`;
}

function clientSecretConfig(privateKey?: string): AuthConfig {
  return {
    appleClientId: CLIENT_ID,
    appleTeamId: 'TEAMID1234',
    appleKeyId: 'KEYID12345',
    applePrivateKeyP8:
      privateKey ??
      ecKeys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  } as AuthConfig;
}

function appleTokenResponse(tokenType = 'Bearer'): Record<string, unknown> {
  return {
    access_token: 'apple-access-token',
    token_type: tokenType,
    expires_in: 3600,
    refresh_token: 'apple-refresh-token',
    id_token: 'header.payload.signature',
  };
}

function parsedAppleTokenResponse() {
  return {
    accessToken: 'apple-access-token',
    expiresIn: 3600,
    refreshToken: 'apple-refresh-token',
    idToken: 'header.payload.signature',
  };
}

function jsonResponse(value: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(value), {
    ...init,
    headers: { 'Content-Type': 'application/json', ...init?.headers },
  });
}

function appleTokenService(
  overrides: {
    verify?: jest.Mock;
    verifyTokenResponse?: jest.Mock;
    exchangeAuthorizationCode?: jest.Mock;
    generate?: jest.Mock;
  } = {},
): AppleTokenService {
  return new AppleTokenService(
    {
      exchangeAuthorizationCode:
        overrides.exchangeAuthorizationCode ??
        jest.fn().mockResolvedValue(parsedAppleTokenResponse()),
    } as unknown as AppleApiClient,
    {
      generate: overrides.generate ?? jest.fn().mockReturnValue('secret'),
    } as unknown as AppleClientSecretService,
    {
      verify:
        overrides.verify ??
        jest.fn().mockResolvedValue({ subject: 'apple-subject' }),
      verifyTokenResponse:
        overrides.verifyTokenResponse ??
        jest.fn().mockResolvedValue({ subject: 'apple-subject' }),
    } as unknown as AppleIdentityTokenVerifier,
    { appleClientId: CLIENT_ID } as AuthConfig,
  );
}

function encodeJson(value: object): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function decodeJson(value: string): unknown {
  return JSON.parse(
    Buffer.from(value, 'base64url').toString('utf8'),
  ) as unknown;
}
