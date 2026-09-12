import { ForbiddenException } from '@nestjs/common';
import { AppleAuthError } from './apple-auth.errors';
import { AuthConfig } from './auth.config';
import { AuthPrincipal } from './auth.types';
import { AuthService } from './auth.service';
import { AppleAuthenticationDto } from './dto/apple-authentication.dto';

const dto: AppleAuthenticationDto = {
  identityToken: 'identity-token',
  authorizationCode: 'authorization-code',
  nonce: 'n'.repeat(43),
};
const exchange = {
  subject: 'apple-subject',
  refreshToken: 'apple-refresh-token',
  isPrivateEmail: false,
};

describe('AuthService Apple linking', () => {
  it.each<AuthPrincipal>([
    { userId: '10000000-0000-4000-8000-000000000001', authMethod: 'apple' },
    { userId: '10000000-0000-4000-8000-000000000001' },
  ])(
    'rejects non-password origin before consuming Apple credentials',
    async (principal) => {
      const appleTokens = { exchangeAuthorizationCode: jest.fn() };
      const cipher = {
        assertConfigured: jest.fn(),
        encrypt: jest.fn(),
      };
      const db = { getClient: jest.fn() };
      const service = new AuthService(
        db as never,
        {} as AuthConfig,
        appleTokens as never,
        cipher as never,
      );

      await expect(service.linkApple(principal, dto)).rejects.toBeInstanceOf(
        ForbiddenException,
      );
      expect(appleTokens.exchangeAuthorizationCode).not.toHaveBeenCalled();
      expect(cipher.assertConfigured).not.toHaveBeenCalled();
      expect(db.getClient).not.toHaveBeenCalled();
    },
  );

  it('exchanges once and does not create a Fintech session', async () => {
    const queries: string[] = [];
    const client = {
      query: jest.fn((text: string) => {
        queries.push(text);
        if (text.includes('FROM auth_identities')) return { rows: [] };
        return { rows: [] };
      }),
      release: jest.fn(),
    };
    const appleTokens = {
      exchangeAuthorizationCode: jest.fn().mockResolvedValue(exchange),
    };
    const cipher = {
      assertConfigured: jest.fn(),
      encrypt: jest.fn().mockReturnValue('v1.iv.ciphertext.tag'),
    };
    const service = new AuthService(
      { getClient: jest.fn().mockResolvedValue(client) } as never,
      {} as AuthConfig,
      appleTokens as never,
      cipher as never,
    );

    await expect(
      service.linkApple(
        {
          userId: '10000000-0000-4000-8000-000000000001',
          authMethod: 'password',
        },
        dto,
      ),
    ).resolves.toBeUndefined();

    expect(appleTokens.exchangeAuthorizationCode).toHaveBeenCalledTimes(1);
    expect(appleTokens.exchangeAuthorizationCode).toHaveBeenCalledWith(
      dto.identityToken,
      dto.authorizationCode,
      dto.nonce,
    );
    expect(queries.some((query) => query.includes('refresh_sessions'))).toBe(
      false,
    );
    expect(client.query).toHaveBeenCalledWith('COMMIT');
  });

  it.each([
    'auth_identities_provider_provider_subject_key',
    'auth_identities_user_id_provider_key',
  ])('maps only expected identity constraint %s to 409', async (constraint) => {
    const client = {
      query: jest.fn((text: string) => {
        if (text.includes('FROM auth_identities')) return { rows: [] };
        if (text.includes('INSERT INTO auth_identities')) {
          const error = new Error('unique violation') as Error & {
            code: string;
            constraint: string;
          };
          error.code = '23505';
          error.constraint = constraint;
          throw error;
        }
        return { rows: [] };
      }),
      release: jest.fn(),
    };
    const service = new AuthService(
      { getClient: jest.fn().mockResolvedValue(client) } as never,
      {} as AuthConfig,
      {
        exchangeAuthorizationCode: jest.fn().mockResolvedValue(exchange),
      } as never,
      {
        assertConfigured: jest.fn(),
        encrypt: jest.fn().mockReturnValue('ciphertext'),
      } as never,
    );

    await expect(
      service.linkApple(
        {
          userId: '10000000-0000-4000-8000-000000000001',
          authMethod: 'password',
        },
        dto,
      ),
    ).rejects.toMatchObject({
      status: 409,
      message: 'Apple identity cannot be linked',
    });
    expect(client.query).toHaveBeenCalledWith('ROLLBACK');
  });

  it('keeps unexpected unique violations internal', async () => {
    const client = {
      query: jest.fn((text: string) => {
        if (text.includes('FROM auth_identities')) return { rows: [] };
        if (text.includes('INSERT INTO auth_identities')) {
          const error = new Error('unique violation') as Error & {
            code: string;
            constraint: string;
          };
          error.code = '23505';
          error.constraint = 'auth_identities_pkey';
          throw error;
        }
        return { rows: [] };
      }),
      release: jest.fn(),
    };
    const service = new AuthService(
      { getClient: jest.fn().mockResolvedValue(client) } as never,
      {} as AuthConfig,
      {
        exchangeAuthorizationCode: jest.fn().mockResolvedValue(exchange),
      } as never,
      {
        assertConfigured: jest.fn(),
        encrypt: jest.fn().mockReturnValue('ciphertext'),
      } as never,
    );

    await expect(
      service.linkApple(
        {
          userId: '10000000-0000-4000-8000-000000000001',
          authMethod: 'password',
        },
        dto,
      ),
    ).rejects.toMatchObject({
      code: '23505',
      constraint: 'auth_identities_pkey',
    });
  });

  it('sanitizes Apple failures without retrying', async () => {
    const exchangeAuthorizationCode = jest
      .fn()
      .mockRejectedValue(
        new AppleAuthError('INVALID_IDENTITY_TOKEN', 'provider detail'),
      );
    const service = new AuthService(
      {} as never,
      {} as AuthConfig,
      { exchangeAuthorizationCode } as never,
      { assertConfigured: jest.fn() } as never,
    );

    await expect(
      service.linkApple(
        {
          userId: '10000000-0000-4000-8000-000000000001',
          authMethod: 'password',
        },
        dto,
      ),
    ).rejects.toMatchObject({
      status: 401,
      message: 'Invalid Apple authentication',
    });
    expect(exchangeAuthorizationCode).toHaveBeenCalledTimes(1);
  });
});
