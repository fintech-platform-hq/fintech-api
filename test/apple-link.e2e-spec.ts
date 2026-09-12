import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { createHmac } from 'crypto';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from '../src/app.module';
import { AppleAuthError } from '../src/modules/auth/apple-auth.errors';
import { AppleTokenService } from '../src/modules/auth/apple-token.service';
import { DatabaseService } from '../src/common/database/database.service';

const secret = '01234567890123456789012345678901';
const nonce = 'n'.repeat(43);
const userId = '10000000-0000-4000-8000-000000000001';
let testApp: INestApplication<App>;

describe('Apple linking API (e2e)', () => {
  const exchangeAuthorizationCode = jest.fn();
  const query = jest.fn((text: string) => {
    if (text.includes('FROM auth_identities')) return { rows: [] };
    return { rows: [] };
  });
  const client = { query, release: jest.fn() };

  beforeAll(async () => {
    process.env.JWT_ACCESS_SECRET = secret;
    process.env.JWT_ISSUER = 'fintech-api-test';
    process.env.JWT_AUDIENCE = 'fintech-clients-test';
    process.env.APPLE_REFRESH_TOKEN_ENCRYPTION_KEY = Buffer.alloc(
      32,
      7,
    ).toString('base64url');

    const module = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(DatabaseService)
      .useValue({ getClient: jest.fn().mockResolvedValue(client) })
      .overrideProvider(AppleTokenService)
      .useValue({ exchangeAuthorizationCode })
      .compile();
    testApp = module.createNestApplication();
    const express = testApp.getHttpAdapter().getInstance() as {
      set(setting: string, value: unknown): void;
    };
    express.set('trust proxy', 1);
    testApp.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
        validationError: { target: false, value: false },
      }),
    );
    await testApp.init();
  });

  beforeEach(() => {
    exchangeAuthorizationCode.mockReset().mockResolvedValue({
      subject: 'apple-link-subject',
      refreshToken: 'apple-refresh-token',
      isPrivateEmail: false,
    });
    query.mockClear();
    client.release.mockClear();
  });

  afterAll(async () => testApp.close());

  it('returns 401 without a Bearer credential', async () => {
    await request(testApp.getHttpServer())
      .post('/auth/apple/link')
      .set('X-Forwarded-For', '198.51.100.1')
      .send({
        identityToken: 'identity-token',
        authorizationCode: 'authorization-code',
        nonce,
      })
      .expect(401);
    expect(exchangeAuthorizationCode).not.toHaveBeenCalled();
  });

  it('rejects invalid and expired Bearer credentials before Apple exchange', async () => {
    await postLink('198.51.100.7', 'not-a-token').expect(401);
    await postLink(
      '198.51.100.8',
      makeAccessToken(userId, 'password', -1),
    ).expect(401);
    expect(exchangeAuthorizationCode).not.toHaveBeenCalled();
  });

  it('rejects client-supplied ownership fields', async () => {
    await request(testApp.getHttpServer())
      .post('/auth/apple/link')
      .set('Authorization', `Bearer ${makeAccessToken(userId, 'password')}`)
      .set('X-Forwarded-For', '198.51.100.9')
      .send({
        identityToken: 'identity-token',
        authorizationCode: 'authorization-code',
        nonce,
        userId,
        authMethod: 'apple',
      })
      .expect(400);
    expect(exchangeAuthorizationCode).not.toHaveBeenCalled();
  });

  it.each([
    ['apple', makeAccessToken(userId, 'apple')],
    ['legacy', makeAccessToken(userId)],
  ])(
    'returns 403 for a %s-origin token before consuming Apple credentials',
    async (_label, token) => {
      await postLink('198.51.100.2', token).expect(403);
      expect(exchangeAuthorizationCode).not.toHaveBeenCalled();
    },
  );

  it('returns 400 for invalid input before consuming an authorization code', async () => {
    await request(testApp.getHttpServer())
      .post('/auth/apple/link')
      .set('Authorization', `Bearer ${makeAccessToken(userId, 'password')}`)
      .set('X-Forwarded-For', '198.51.100.3')
      .send({
        identityToken: 'identity',
        authorizationCode: 'code',
        nonce: 'invalid',
      })
      .expect(400);
    expect(exchangeAuthorizationCode).not.toHaveBeenCalled();
  });

  it('returns 204 with an empty body for a password-origin token', async () => {
    const response = await postLink(
      '198.51.100.4',
      makeAccessToken(userId, 'password'),
    ).expect(204);

    expect(response.text).toBe('');
    expect(exchangeAuthorizationCode).toHaveBeenCalledTimes(1);
  });

  it('maps Apple errors to sanitized public responses', async () => {
    exchangeAuthorizationCode.mockRejectedValueOnce(
      new AppleAuthError('APPLE_TOKEN_API_UNAVAILABLE', 'provider detail'),
    );

    const response = await postLink(
      '198.51.100.5',
      makeAccessToken(userId, 'password'),
    ).expect(503);
    expect(JSON.stringify(response.body)).not.toContain('provider detail');
  });

  it('rate-limits the sixth request for one IP', async () => {
    const token = makeAccessToken(userId, 'password');
    for (let attempt = 0; attempt < 5; attempt += 1) {
      await request(testApp.getHttpServer())
        .post('/auth/apple/link')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Forwarded-For', '198.51.100.6')
        .send({ identityToken: 'bad', authorizationCode: 'bad', nonce: 'bad' })
        .expect(400);
    }
    await request(testApp.getHttpServer())
      .post('/auth/apple/link')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Forwarded-For', '198.51.100.6')
      .send({ identityToken: 'bad', authorizationCode: 'bad', nonce: 'bad' })
      .expect(429);
  });

  it('shares the rate-limit bucket across equivalent route variants', async () => {
    const token = makeAccessToken(userId, 'password');
    for (let attempt = 0; attempt < 5; attempt += 1) {
      await request(testApp.getHttpServer())
        .post(attempt % 2 === 0 ? '/auth/apple/link/' : '/AUTH/APPLE/LINK')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Forwarded-For', '198.51.100.10')
        .send({ identityToken: 'bad', authorizationCode: 'bad', nonce: 'bad' })
        .expect(400);
    }
    await request(testApp.getHttpServer())
      .post('/auth/apple/link/')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Forwarded-For', '198.51.100.10')
      .send({ identityToken: 'bad', authorizationCode: 'bad', nonce: 'bad' })
      .expect(429);
  });
});

function postLink(
  ip: string,
  token = makeAccessToken(userId, 'password'),
): request.Test {
  return request(testApp.getHttpServer())
    .post('/auth/apple/link')
    .set('Authorization', `Bearer ${token}`)
    .set('X-Forwarded-For', ip)
    .send({
      identityToken: 'identity-token',
      authorizationCode: 'authorization-code',
      nonce,
    });
}

function makeAccessToken(
  subject: string,
  authMethod?: 'password' | 'apple',
  expiresIn = 900,
): string {
  const encode = (value: object) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  const header = encode({ alg: 'HS256', typ: 'JWT' });
  const payload = encode({
    sub: subject,
    iss: 'fintech-api-test',
    aud: 'fintech-clients-test',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + expiresIn,
    jti: '10000000-0000-4000-8000-000000000011',
    ...(authMethod ? { auth_method: authMethod } : {}),
  });
  const signature = createHmac('sha256', secret)
    .update(`${header}.${payload}`)
    .digest('base64url');
  return `${header}.${payload}.${signature}`;
}
