import {
  ConflictException,
  ForbiddenException,
  HttpException,
  InternalServerErrorException,
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
import type { PoolClient } from 'pg';
import { isUUID } from 'class-validator';
import { DatabaseService } from '../../common/database/database.service';
import { IdentityMethodReceipt } from './identity-method-receipt';
import { lockHolder, sessionAuthority } from './session-authority';
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
  family_expires_at: Date | null;
  expired: boolean;
  revoked_at: Date | null;
}

interface AppleIdentityRefreshRow {
  id: string;
  provider_subject: string;
  provider_refresh_token_ciphertext: string | null;
  validation_due: boolean;
  unlinked_at: Date | null;
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
  sid?: unknown;
}

interface AuthIdentityRow {
  unlinked_at: Date | null;
  id: string;
  user_id: string;
}

@Injectable()
export class AuthService {
  // ponytail: backoff is process-local; shared attempt state is needed before scale-out.
  private readonly appleValidationBackoff = new Map<string, number>();
  private readonly appleValidations = new Map<string, Promise<boolean>>();
  constructor(
    private readonly db: DatabaseService,
    private readonly config: AuthConfig,
    private readonly appleTokens: AppleTokenService,
    private readonly appleRefreshTokens: AppleRefreshTokenCipherService,
  ) {}

  async register(dto: CredentialsDto): Promise<AuthResponse> {
    const userId = randomUUID();
    const familyId = randomUUID();
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
        familyId,
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

    return this.authResponse(userId, refresh.token, 'password', familyId);
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

    return this.holderTransaction(user.id, async (client) => {
      const current = await client.query<UserRow>(
        'SELECT id, password_hash FROM users WHERE id = $1 AND email = $2',
        [user.id, dto.email],
      );
      if (current.rows[0]?.password_hash !== user.password_hash) {
        throw new UnauthorizedException('Invalid email or password');
      }
      const refresh = this.newRefreshToken();
      const familyId = randomUUID();
      await this.insertRefreshSession(
        client,
        user.id,
        familyId,
        refresh.hash,
        null,
      );
      return this.authResponse(user.id, refresh.token, 'password', familyId);
    });
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

  async linkApple(
    principal: AuthPrincipal,
    dto: AppleAuthenticationDto,
    password?: string,
    operationId?: string,
  ): Promise<void> {
    if (principal.authMethod !== 'password') {
      throw new ForbiddenException('Password authentication required');
    }

    const receipt = operationId
      ? new IdentityMethodReceipt(principal, operationId, 'apple_link')
      : undefined;
    if (await this.replayIdentityMethod(principal, receipt)) return;

    const passwordHash = await this.provePassword(principal.userId, password);
    const authorization = await this.exchangeIdentityMethod(
      principal,
      dto,
      receipt,
    );
    if (authorization) {
      await this.linkAppleIdentity(
        principal,
        authorization,
        passwordHash,
        receipt,
      );
    }
  }

  async withAppleProof<T>(
    principal: AuthPrincipal,
    dto: AppleAuthenticationDto,
    work: (client: PoolClient) => Promise<T>,
    receipt?: IdentityMethodReceipt,
  ): Promise<T | undefined> {
    if (principal.authMethod !== 'apple') throw new ForbiddenException();
    if (await this.replayIdentityMethod(principal, receipt)) return;
    const authorization = await this.exchangeIdentityMethod(
      principal,
      dto,
      receipt,
    );
    if (!authorization) return;
    return this.holderTransaction(principal.userId, async (client) => {
      await sessionAuthority(client, principal);
      if (await receipt?.exists(client)) return;
      const result = await client.query(
        `SELECT 1 FROM refresh_sessions s
         JOIN auth_identities i ON i.id = s.auth_identity_id
         WHERE s.user_id = $1 AND s.family_id = $2 AND s.revoked_at IS NULL
           AND i.provider = 'apple' AND i.provider_subject = $3`,
        [principal.userId, principal.familyId, authorization.subject],
      );
      if (!result.rowCount)
        throw new ForbiddenException('Invalid method proof');
      return work(client);
    });
  }

  private async exchangeIdentityMethod(
    principal: AuthPrincipal,
    dto: AppleAuthenticationDto,
    receipt?: IdentityMethodReceipt,
  ): Promise<AppleAuthorizationExchange | undefined> {
    try {
      return await this.exchangeApple(dto);
    } catch (error) {
      if (await this.replayIdentityMethod(principal, receipt)) return;
      throw error;
    }
  }

  async replayIdentityMethod(
    principal: AuthPrincipal,
    receipt?: IdentityMethodReceipt,
  ): Promise<boolean> {
    if (!receipt) return false;
    await sessionAuthority(this.db, principal, true);
    return receipt.exists(this.db);
  }

  private async exchangeApple(
    dto: AppleAuthenticationDto,
  ): Promise<AppleAuthorizationExchange> {
    try {
      this.appleRefreshTokens.assertConfigured();
      return await this.appleTokens.exchangeAuthorizationCode(
        dto.identityToken,
        dto.authorizationCode,
        dto.nonce,
      );
    } catch (error) {
      if (error instanceof AppleAuthError) this.throwPublicAppleError(error);
      throw error;
    }
  }

  async refresh(refreshToken: string): Promise<AuthResponse> {
    const hash = this.hashToken(refreshToken);
    const initial = await this.findRefresh(this.db, hash);
    if (!initial?.family_expires_at) throw new UnauthorizedException();

    let providerResult:
      { ciphertext: string | null; accepted: boolean } | undefined;
    if (initial.auth_identity_id && !initial.revoked_at && !initial.expired) {
      const identity = await this.findAppleRefresh(
        this.db,
        initial.auth_identity_id,
      );
      if (
        identity?.validation_due &&
        !identity.revoked_at &&
        !identity.unlinked_at
      ) {
        providerResult = {
          ciphertext: identity.provider_refresh_token_ciphertext,
          accepted: await this.validateAppleRefresh(identity),
        };
      }
    }

    const response = await this.holderTransaction(
      initial.user_id,
      async (client) => {
        const session = await this.findRefresh(client, hash);
        if (!session?.family_expires_at) return;
        const identity = session.auth_identity_id
          ? await this.findAppleRefresh(client, session.auth_identity_id)
          : undefined;
        const matchingProviderResult =
          providerResult &&
          providerResult.ciphertext ===
            identity?.provider_refresh_token_ciphertext
            ? providerResult
            : undefined;
        if (
          identity &&
          matchingProviderResult?.accepted === false &&
          !identity.revoked_at &&
          !identity.unlinked_at
        ) {
          await client.query(
            'UPDATE auth_identities SET revoked_at = clock_timestamp() WHERE id = $1',
            [identity.id],
          );
          await this.revokeAppleSessions(client, identity.id);
          return;
        }
        if (session.revoked_at || session.expired) {
          await this.revokeFamily(client, session.user_id, session.family_id);
          return;
        }

        if (session.auth_identity_id) {
          if (!identity || identity.revoked_at || identity.unlinked_at) {
            await this.revokeFamily(client, session.user_id, session.family_id);
            return;
          }
          if (identity.validation_due) {
            if (!matchingProviderResult?.accepted) {
              throw new ServiceUnavailableException(
                'Apple authentication is temporarily unavailable',
              );
            }
            await client.query(
              'UPDATE auth_identities SET last_provider_validation_at = clock_timestamp() WHERE id = $1',
              [identity.id],
            );
          }
        } else {
          const password = await client.query(
            'SELECT 1 FROM users WHERE id = $1 AND password_hash IS NOT NULL',
            [session.user_id],
          );
          if (!password.rowCount) return;
        }

        await client.query(
          'UPDATE refresh_sessions SET revoked_at = clock_timestamp() WHERE token_hash = $1',
          [hash],
        );
        const next = this.newRefreshToken();
        await this.insertRefreshSession(
          client,
          session.user_id,
          session.family_id,
          next.hash,
          session.auth_identity_id,
          session.family_expires_at,
        );
        return this.authResponse(
          session.user_id,
          next.token,
          session.auth_identity_id ? 'apple' : 'password',
          session.family_id,
        );
      },
    ).catch((error: unknown) => {
      if (initial.auth_identity_id && !(error instanceof HttpException)) {
        throw new InternalServerErrorException();
      }
      throw error;
    });
    if (!response) throw new UnauthorizedException('Invalid refresh token');
    return response;
  }

  private async findRefresh(db: Pick<DatabaseService, 'query'>, hash: string) {
    const result = await db.query<RefreshSessionRow>(
      `SELECT user_id, auth_identity_id, family_id, family_expires_at, revoked_at,
              clock_timestamp() >= LEAST(expires_at, family_expires_at) AS expired
       FROM refresh_sessions WHERE token_hash = $1`,
      [hash],
    );
    return result.rows[0];
  }

  private async findAppleRefresh(
    db: Pick<DatabaseService, 'query'>,
    id: string,
  ) {
    const result = await db.query<AppleIdentityRefreshRow>(
      `SELECT id, provider_subject, provider_refresh_token_ciphertext, revoked_at, unlinked_at,
              COALESCE(last_provider_validation_at <= clock_timestamp() - interval '24 hours', true) AS validation_due
       FROM auth_identities WHERE id = $1 AND provider = 'apple'`,
      [id],
    );
    return result.rows[0];
  }

  private async validateAppleRefresh(
    identity: AppleIdentityRefreshRow,
  ): Promise<boolean> {
    const unavailable = new ServiceUnavailableException(
      'Apple authentication is temporarily unavailable',
    );
    const ciphertext = identity.provider_refresh_token_ciphertext;
    if (!ciphertext) throw unavailable;
    const backoffKey = `${identity.id}:${createHash('sha256').update(ciphertext).digest('hex')}`;
    const existing = this.appleValidations.get(backoffKey);
    if (existing) return existing;
    const validating = this.validateAppleCiphertext(
      identity,
      ciphertext,
      backoffKey,
    ).finally(() => this.appleValidations.delete(backoffKey));
    this.appleValidations.set(backoffKey, validating);
    return validating;
  }

  private async validateAppleCiphertext(
    identity: AppleIdentityRefreshRow,
    ciphertext: string,
    backoffKey: string,
  ): Promise<boolean> {
    const unavailable = new ServiceUnavailableException(
      'Apple authentication is temporarily unavailable',
    );
    this.pruneAppleValidationBackoff();
    if ((this.appleValidationBackoff.get(backoffKey) ?? 0) > Date.now())
      throw unavailable;
    try {
      await this.appleTokens.validateRefreshToken(
        this.appleRefreshTokens.decrypt(ciphertext, identity.id),
        identity.provider_subject,
      );
      this.appleValidationBackoff.delete(backoffKey);
      return true;
    } catch (error) {
      if (
        error instanceof AppleAuthError &&
        error.code === 'APPLE_REFRESH_TOKEN_REJECTED'
      )
        return false;
      if (this.appleValidationBackoff.size >= 10_000) {
        const [oldest] = this.appleValidationBackoff.keys();
        if (oldest) this.appleValidationBackoff.delete(oldest);
      }
      this.appleValidationBackoff.set(backoffKey, Date.now() + 60_000);
      throw unavailable;
    }
  }

  private pruneAppleValidationBackoff(): void {
    const now = Date.now();
    for (const [key, expiresAt] of this.appleValidationBackoff) {
      if (expiresAt <= now) this.appleValidationBackoff.delete(key);
    }
  }

  private async revokeAppleSessions(
    client: PoolClient,
    identityId: string,
  ): Promise<void> {
    await client.query(
      `UPDATE refresh_sessions SET revoked_at = COALESCE(revoked_at, now())
       WHERE auth_identity_id = $1`,
      [identityId],
    );
  }

  async logout(refreshToken: string): Promise<void> {
    const session = await this.findRefresh(
      this.db,
      this.hashToken(refreshToken),
    );
    if (session)
      await this.holderTransaction(session.user_id, (client) =>
        this.revokeFamily(client, session.user_id, session.family_id),
      );
  }

  private async revokeFamily(
    client: PoolClient,
    userId: string,
    familyId: string,
  ): Promise<void> {
    await client.query(
      `UPDATE refresh_sessions SET revoked_at = clock_timestamp()
       WHERE user_id = $1 AND family_id = $2 AND revoked_at IS NULL`,
      [userId, familyId],
    );
  }

  async holderTransaction<T>(
    userId: string,
    work: (client: PoolClient) => Promise<T>,
  ): Promise<T> {
    const client = await this.db.getClient();
    let discard = false;
    try {
      await client.query('BEGIN');
      await lockHolder(client, userId);
      const result = await work(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {
        discard = true;
      });
      throw error;
    } finally {
      client.release(discard || undefined);
    }
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
        (payload.auth_method !== 'password' &&
          payload.auth_method !== 'apple') ||
        typeof payload.sid !== 'string' ||
        !isUUID(payload.sid)
      ) {
        throw new Error('Invalid authentication method');
      }

      return {
        userId: payload.sub,
        authMethod: payload.auth_method,
        familyId: payload.sid,
        expiresAt: payload.exp * 1_000,
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
    const familyId = randomUUID();
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
          SELECT id, user_id, unlinked_at
          FROM auth_identities
          WHERE provider = 'apple' AND provider_subject = $1
        `,
        [authorization.subject],
      );
      let identityId = existing.rows[0]?.id;
      let userId = existing.rows[0]?.user_id;

      if (identityId && userId) {
        await lockHolder(client, userId);
        const current = await this.findAppleRefresh(client, identityId);
        if (!current || current.unlinked_at) throw accountLinkRequired();
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
        familyId,
        refresh.hash,
        identityId,
      );
      await client.query('COMMIT');
      transactionOpen = false;
      return this.authResponse(userId, refresh.token, 'apple', familyId);
    } catch (error) {
      if (transactionOpen) await client.query('ROLLBACK');
      if (isUsersEmailConflict(error)) throw accountLinkRequired();
      throw error;
    } finally {
      client.release();
    }
  }

  private async linkAppleIdentity(
    principal: AuthPrincipal,
    authorization: AppleAuthorizationExchange,
    passwordHash: string,
    receipt?: IdentityMethodReceipt,
  ): Promise<void> {
    const { userId } = principal;
    const client = await this.db.getClient();
    let transactionOpen = false;

    try {
      await client.query('BEGIN');
      transactionOpen = true;
      await client.query(
        'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
        [`apple:${authorization.subject}`],
      );
      await lockHolder(client, userId);
      await sessionAuthority(client, principal, true);
      if (await receipt?.exists(client)) {
        await client.query('COMMIT');
        transactionOpen = false;
        return;
      }
      await this.assertPasswordUnchanged(client, userId, passwordHash);

      const existing = await client.query<AuthIdentityRow>(
        `
          SELECT id, user_id, unlinked_at
          FROM auth_identities
          WHERE provider = 'apple' AND provider_subject = $1
        `,
        [authorization.subject],
      );
      const identity = existing.rows[0];

      if (identity && identity.user_id !== userId) {
        throw appleIdentityLinkConflict();
      }

      const identityId = identity?.id ?? randomUUID();
      const ciphertext = this.appleRefreshTokens.encrypt(
        authorization.refreshToken,
        identityId,
      );

      if (identity) {
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
                revoked_at = NULL,
                unlinked_at = NULL
            WHERE id = $4 AND user_id = $5
          `,
          [
            authorization.email ?? null,
            authorization.isPrivateEmail,
            ciphertext,
            identityId,
            userId,
          ],
        );
      } else {
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

      await receipt?.record(client);
      await client.query('COMMIT');
      transactionOpen = false;
    } catch (error) {
      if (transactionOpen) await client.query('ROLLBACK');
      if (isAppleIdentityConflict(error)) throw appleIdentityLinkConflict();
      throw error;
    } finally {
      client.release();
    }
  }

  private authResponse(
    userId: string,
    refreshToken: string,
    authMethod: AuthMethod,
    familyId: string,
  ): AuthResponse {
    return {
      accessToken: this.signAccessToken(userId, authMethod, familyId),
      refreshToken,
      tokenType: 'Bearer',
      expiresIn: 900,
    };
  }

  private signAccessToken(
    userId: string,
    authMethod: AuthMethod,
    familyId: string,
  ): string {
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
      sid: familyId,
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

  async provePassword(
    userId: string,
    password?: string,
    verified = true,
  ): Promise<string> {
    const result = await this.db.query<UserRow>(
      'SELECT password_hash FROM users WHERE id = $1 AND ($2 = false OR email_verified_at IS NOT NULL)',
      [userId, verified],
    );
    const hash = result.rows[0]?.password_hash;
    if (!hash || !password || !(await this.verifyPassword(password, hash))) {
      throw new ForbiddenException('Invalid method proof');
    }
    return hash;
  }

  async assertPasswordUnchanged(
    client: PoolClient,
    userId: string,
    hash: string,
  ): Promise<void> {
    const result = await client.query(
      'SELECT 1 FROM users WHERE id = $1 AND password_hash = $2 AND email_verified_at IS NOT NULL',
      [userId, hash],
    );
    if (!result.rowCount) throw new ForbiddenException('Invalid method proof');
  }

  async unlinkApple(
    principal: AuthPrincipal,
    password: string,
    operationId?: string,
  ): Promise<void> {
    if (operationId && principal.authMethod !== 'password') {
      throw new ForbiddenException(
        'Password session required for a reconcilable Apple unlink',
      );
    }
    const receipt = operationId
      ? new IdentityMethodReceipt(principal, operationId, 'apple_unlink')
      : undefined;
    if (await this.replayIdentityMethod(principal, receipt)) return;
    const hash = await this.provePassword(principal.userId, password);
    await this.holderTransaction(principal.userId, async (client) => {
      await sessionAuthority(client, principal);
      if (await receipt?.exists(client)) return;
      await this.assertPasswordUnchanged(client, principal.userId, hash);
      const result = await client.query<{ id: string }>(
        `UPDATE auth_identities SET unlinked_at = clock_timestamp(),
                revoked_at = COALESCE(revoked_at, clock_timestamp()),
                provider_refresh_token_ciphertext = NULL
         WHERE user_id = $1 AND provider = 'apple' AND unlinked_at IS NULL
         RETURNING id`,
        [principal.userId],
      );
      if (result.rows[0])
        await this.revokeAppleSessions(client, result.rows[0].id);
      await receipt?.record(client);
    });
  }

  async hashPassword(password: string): Promise<string> {
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
    familyExpiresAt?: Date,
  ): Promise<void> {
    await client.query(
      `
        INSERT INTO refresh_sessions (
          id, user_id, auth_identity_id, family_id, token_hash, expires_at, family_expires_at
        ) VALUES ($1, $2, $3, $4, $5, clock_timestamp() + interval '720 hours',
                  COALESCE($6, clock_timestamp() + interval '2160 hours'))
      `,
      [
        randomUUID(),
        userId,
        authIdentityId,
        familyId,
        tokenHash,
        familyExpiresAt,
      ],
    );
  }

  private throwPublicAppleError(error: AppleAuthError): never {
    if (
      error.code === 'INVALID_IDENTITY_TOKEN' ||
      error.code === 'UNKNOWN_APPLE_KID' ||
      error.code === 'APPLE_AUTHORIZATION_CODE_REJECTED' ||
      error.code === 'APPLE_TOKEN_REQUEST_REJECTED' ||
      error.code === 'APPLE_REFRESH_TOKEN_REJECTED'
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

function appleIdentityLinkConflict(): ConflictException {
  return new ConflictException('Apple identity cannot be linked');
}

function isAppleIdentityConflict(error: unknown): boolean {
  const databaseError = error as { code?: unknown; constraint?: unknown };
  return (
    databaseError.code === '23505' &&
    (databaseError.constraint ===
      'auth_identities_provider_provider_subject_key' ||
      databaseError.constraint === 'auth_identities_user_id_provider_key')
  );
}
