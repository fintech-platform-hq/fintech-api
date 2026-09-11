import {
  ConflictException,
  Injectable,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import {
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
  scrypt as nodeScrypt,
  timingSafeEqual,
} from 'crypto';
import { promisify } from 'util';
import { isUUID } from 'class-validator';
import { DatabaseService } from '../../common/database/database.service';
import { AuthConfig } from './auth.config';
import { AuthMethod, AuthPrincipal, AuthResponse } from './auth.types';
import { AppleAuthError } from './apple-auth.errors';
import { AppleRefreshTokenCipherService } from './apple-refresh-token-cipher.service';
import {
  AppleAuthorizationExchange,
  AppleTokenService,
} from './apple-token.service';
import { AppleAuthenticationDto } from './dto/apple-authentication.dto';
import { CredentialsDto } from './dto/credentials.dto';

const scrypt = promisify(nodeScrypt);

interface UserRow {
  id: string;
  password_hash: string | null;
}

interface RefreshSessionRow {
  user_id: string;
  auth_identity_id: string | null;
  family_id: string;
  expires_at: Date;
  revoked_at: Date | null;
}

interface JwtPayload {
  sub: unknown;
  iss: unknown;
  aud: unknown;
  iat: unknown;
  exp: unknown;
  jti: unknown;
  auth_method?: unknown;
}

interface AuthIdentityRow {
  id: string;
  user_id: string;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly db: DatabaseService,
    private readonly config: AuthConfig,
    private readonly appleTokens: AppleTokenService,
    private readonly appleRefreshTokens: AppleRefreshTokenCipherService,
  ) {}

  async register(dto: CredentialsDto): Promise<AuthResponse> {
    const userId = randomUUID();
    const passwordHash = await this.hashPassword(dto.password);
    const refresh = this.newRefreshToken();
    const client = await this.db.getClient();

    try {
      await client.query('BEGIN');
      await client.query(
        `INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)`,
        [userId, dto.email, passwordHash],
      );
      await this.insertRefreshSession(
        client,
        userId,
        randomUUID(),
        refresh.hash,
        null,
      );
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      if ((error as { code?: string }).code === '23505') {
        throw new ConflictException('Email already registered');
      }
      throw error;
    } finally {
      client.release();
    }

    return this.authResponse(userId, refresh.token, 'password');
  }

  async login(dto: CredentialsDto): Promise<AuthResponse> {
    const result = await this.db.query<UserRow>(
      `SELECT id, password_hash FROM users WHERE email = $1`,
      [dto.email],
    );
    const user = result.rows[0];
    const passwordMatches = user?.password_hash
      ? await this.verifyPassword(dto.password, user.password_hash)
      : await this.consumeScrypt(dto.password);

    if (!user || !passwordMatches) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const refresh = this.newRefreshToken();
    await this.db.query(
      `
        INSERT INTO refresh_sessions (
          id, user_id, family_id, token_hash, expires_at
        ) VALUES ($1, $2, $3, $4, now() + interval '30 days')
      `,
      [randomUUID(), user.id, randomUUID(), refresh.hash],
    );

    return this.authResponse(user.id, refresh.token, 'password');
  }

  async apple(dto: AppleAuthenticationDto): Promise<AuthResponse> {
    try {
      this.appleRefreshTokens.assertConfigured();
      const authorization = await this.appleTokens.exchangeAuthorizationCode(
        dto.identityToken,
        dto.authorizationCode,
        dto.nonce,
      );
      return await this.createAppleSession(authorization);
    } catch (error) {
      if (error instanceof AppleAuthError) this.throwPublicAppleError(error);
      throw error;
    }
  }

  async refresh(refreshToken: string): Promise<AuthResponse> {
    const tokenHash = this.hashToken(refreshToken);
    const client = await this.db.getClient();
    let transactionOpen = false;

    try {
      await client.query('BEGIN');
      transactionOpen = true;
      const result = await client.query<RefreshSessionRow>(
        `
          SELECT user_id, auth_identity_id, family_id, expires_at, revoked_at
          FROM refresh_sessions
          WHERE token_hash = $1
        `,
        [tokenHash],
      );
      const initialSession = result.rows[0];

      if (!initialSession) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [
        initialSession.family_id,
      ]);

      const lockedResult = await client.query<RefreshSessionRow>(
        `
          SELECT user_id, auth_identity_id, family_id, expires_at, revoked_at
          FROM refresh_sessions
          WHERE token_hash = $1
          FOR UPDATE
        `,
        [tokenHash],
      );
      const session = lockedResult.rows[0];

      if (!session) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      if (session.revoked_at) {
        await client.query(
          `UPDATE refresh_sessions SET revoked_at = COALESCE(revoked_at, now()) WHERE family_id = $1`,
          [session.family_id],
        );
        await client.query('COMMIT');
        transactionOpen = false;
        throw new UnauthorizedException('Invalid refresh token');
      }

      if (session.expires_at.getTime() <= Date.now()) {
        await client.query(
          `UPDATE refresh_sessions SET revoked_at = now() WHERE token_hash = $1`,
          [tokenHash],
        );
        await client.query('COMMIT');
        transactionOpen = false;
        throw new UnauthorizedException('Invalid refresh token');
      }

      await client.query(
        `UPDATE refresh_sessions SET revoked_at = now() WHERE token_hash = $1`,
        [tokenHash],
      );
      const nextRefresh = this.newRefreshToken();
      await this.insertRefreshSession(
        client,
        session.user_id,
        session.family_id,
        nextRefresh.hash,
        session.auth_identity_id,
      );
      await client.query('COMMIT');
      transactionOpen = false;

      return this.authResponse(
        session.user_id,
        nextRefresh.token,
        session.auth_identity_id ? 'apple' : 'password',
      );
    } catch (error) {
      if (transactionOpen) {
        await client.query('ROLLBACK');
      }
      throw error;
    } finally {
      client.release();
    }
  }

  async logout(refreshToken: string): Promise<void> {
    await this.db.query(
      `UPDATE refresh_sessions SET revoked_at = COALESCE(revoked_at, now()) WHERE token_hash = $1`,
      [this.hashToken(refreshToken)],
    );
  }

  verifyAccessToken(token: string): AuthPrincipal {
    try {
      const segments = token.split('.');
      if (segments.length !== 3) {
        throw new Error('Invalid JWT structure');
      }

      const [encodedHeader, encodedPayload, encodedSignature] = segments;
      const header = this.decodeJson(encodedHeader) as {
        alg?: unknown;
        typ?: unknown;
      };
      if (header.alg !== 'HS256' || header.typ !== 'JWT') {
        throw new Error('Invalid JWT header');
      }

      const expectedSignature = createHmac('sha256', this.config.jwtSecret)
        .update(`${encodedHeader}.${encodedPayload}`)
        .digest();
      const signature = Buffer.from(encodedSignature, 'base64url');
      if (
        signature.length !== expectedSignature.length ||
        !timingSafeEqual(signature, expectedSignature)
      ) {
        throw new Error('Invalid JWT signature');
      }

      const payload = this.decodeJson(encodedPayload) as JwtPayload;
      const now = Math.floor(Date.now() / 1000);
      if (
        payload.iss !== this.config.jwtIssuer ||
        payload.aud !== this.config.jwtAudience ||
        typeof payload.exp !== 'number' ||
        payload.exp <= now ||
        typeof payload.iat !== 'number' ||
        typeof payload.jti !== 'string' ||
        !isUUID(payload.jti) ||
        typeof payload.sub !== 'string' ||
        !isUUID(payload.sub)
      ) {
        throw new Error('Invalid JWT claims');
      }

      if (
        payload.auth_method !== undefined &&
        payload.auth_method !== 'password' &&
        payload.auth_method !== 'apple'
      ) {
        throw new Error('Invalid authentication method');
      }

      return {
        userId: payload.sub,
        authMethod: payload.auth_method,
      };
    } catch {
      throw new UnauthorizedException();
    }
  }

  private async createAppleSession(
    authorization: AppleAuthorizationExchange,
  ): Promise<AuthResponse> {
    const client = await this.db.getClient();
    const refresh = this.newRefreshToken();
    let transactionOpen = false;

    try {
      await client.query('BEGIN');
      transactionOpen = true;
      await client.query(
        'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
        [`apple:${authorization.subject}`],
      );

      const existing = await client.query<AuthIdentityRow>(
        `
          SELECT id, user_id
          FROM auth_identities
          WHERE provider = 'apple' AND provider_subject = $1
        `,
        [authorization.subject],
      );
      let identityId = existing.rows[0]?.id;
      let userId = existing.rows[0]?.user_id;

      if (identityId && userId) {
        const ciphertext = this.appleRefreshTokens.encrypt(
          authorization.refreshToken,
          identityId,
        );
        await client.query(
          `
            UPDATE auth_identities
            SET provider_email = COALESCE($1, provider_email),
                is_private_email = CASE
                  WHEN $1 IS NULL THEN is_private_email
                  ELSE $2
                END,
                provider_refresh_token_ciphertext = $3,
                last_provider_validation_at = now(),
                revoked_at = NULL
            WHERE id = $4
          `,
          [
            authorization.email ?? null,
            authorization.isPrivateEmail,
            ciphertext,
            identityId,
          ],
        );
      } else {
        if (authorization.email) {
          const collision = await client.query(
            'SELECT 1 FROM users WHERE email = $1',
            [authorization.email],
          );
          if (collision.rowCount) throw accountLinkRequired();
        }

        userId = randomUUID();
        identityId = randomUUID();
        const ciphertext = this.appleRefreshTokens.encrypt(
          authorization.refreshToken,
          identityId,
        );
        await client.query(
          'INSERT INTO users (id, email, password_hash) VALUES ($1, $2, NULL)',
          [userId, authorization.email ?? null],
        );
        await client.query(
          `
            INSERT INTO auth_identities (
              id, user_id, provider, provider_subject, provider_email,
              is_private_email, provider_refresh_token_ciphertext,
              last_provider_validation_at
            ) VALUES ($1, $2, 'apple', $3, $4, $5, $6, now())
          `,
          [
            identityId,
            userId,
            authorization.subject,
            authorization.email ?? null,
            authorization.isPrivateEmail,
            ciphertext,
          ],
        );
      }

      await this.insertRefreshSession(
        client,
        userId,
        randomUUID(),
        refresh.hash,
        identityId,
      );
      await client.query('COMMIT');
      transactionOpen = false;
      return this.authResponse(userId, refresh.token, 'apple');
    } catch (error) {
      if (transactionOpen) await client.query('ROLLBACK');
      if (isUsersEmailConflict(error)) throw accountLinkRequired();
      throw error;
    } finally {
      client.release();
    }
  }

  private authResponse(
    userId: string,
    refreshToken: string,
    authMethod: AuthMethod,
  ): AuthResponse {
    return {
      accessToken: this.signAccessToken(userId, authMethod),
      refreshToken,
      tokenType: 'Bearer',
      expiresIn: 900,
    };
  }

  private signAccessToken(userId: string, authMethod: AuthMethod): string {
    const now = Math.floor(Date.now() / 1000);
    const header = this.encodeJson({ alg: 'HS256', typ: 'JWT' });
    const payload = this.encodeJson({
      sub: userId,
      iss: this.config.jwtIssuer,
      aud: this.config.jwtAudience,
      iat: now,
      exp: now + this.config.accessTokenSeconds,
      jti: randomUUID(),
      auth_method: authMethod,
    });
    const signature = createHmac('sha256', this.config.jwtSecret)
      .update(`${header}.${payload}`)
      .digest('base64url');
    return `${header}.${payload}.${signature}`;
  }

  private encodeJson(value: object): string {
    return Buffer.from(JSON.stringify(value)).toString('base64url');
  }

  private decodeJson(value: string): unknown {
    return JSON.parse(
      Buffer.from(value, 'base64url').toString('utf8'),
    ) as unknown;
  }

  private newRefreshToken(): { token: string; hash: string } {
    const token = randomBytes(32).toString('base64url');
    return { token, hash: this.hashToken(token) };
  }

  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  private async hashPassword(password: string): Promise<string> {
    const salt = randomBytes(16);
    const derived = (await scrypt(password, salt, 64)) as Buffer;
    return `scrypt$${salt.toString('base64url')}$${derived.toString('base64url')}`;
  }

  private async verifyPassword(
    password: string,
    encodedHash: string,
  ): Promise<boolean> {
    const [algorithm, saltValue, hashValue] = encodedHash.split('$');
    if (algorithm !== 'scrypt' || !saltValue || !hashValue) {
      return false;
    }

    const expected = Buffer.from(hashValue, 'base64url');
    const actual = (await scrypt(
      password,
      Buffer.from(saltValue, 'base64url'),
      expected.length,
    )) as Buffer;
    return (
      actual.length === expected.length && timingSafeEqual(actual, expected)
    );
  }

  private async consumeScrypt(password: string): Promise<false> {
    await scrypt(password, Buffer.alloc(16), 64);
    return false;
  }

  private async insertRefreshSession(
    client: { query: (text: string, values?: unknown[]) => Promise<unknown> },
    userId: string,
    familyId: string,
    tokenHash: string,
    authIdentityId: string | null,
  ): Promise<void> {
    await client.query(
      `
        INSERT INTO refresh_sessions (
          id, user_id, auth_identity_id, family_id, token_hash, expires_at
        ) VALUES ($1, $2, $3, $4, $5, now() + interval '30 days')
      `,
      [randomUUID(), userId, authIdentityId, familyId, tokenHash],
    );
  }

  private throwPublicAppleError(error: AppleAuthError): never {
    if (
      error.code === 'INVALID_IDENTITY_TOKEN' ||
      error.code === 'UNKNOWN_APPLE_KID' ||
      error.code === 'APPLE_AUTHORIZATION_CODE_REJECTED' ||
      error.code === 'APPLE_TOKEN_REQUEST_REJECTED'
    ) {
      throw new UnauthorizedException('Invalid Apple authentication');
    }
    throw new ServiceUnavailableException(
      'Apple authentication is temporarily unavailable',
    );
  }
}

function accountLinkRequired(): ConflictException {
  return new ConflictException({
    statusCode: 409,
    message: 'Account linking required',
    code: 'ACCOUNT_LINK_REQUIRED',
  });
}

function isUsersEmailConflict(error: unknown): boolean {
  const databaseError = error as { code?: unknown; constraint?: unknown };
  return (
    databaseError.code === '23505' &&
    databaseError.constraint === 'users_email_key'
  );
}
