import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { createHmac, randomBytes, randomInt } from 'crypto';
import type { PoolClient } from 'pg';
import { setTimeout as delay } from 'timers/promises';
import { DatabaseService } from '../../common/database/database.service';
import { AuthConfig } from './auth.config';
import type { AppleAuthenticationDto } from './dto/apple-authentication.dto';
import { IdentityMethodReceipt } from './identity-method-receipt';
import { AuthService } from './auth.service';
import type { AuthPrincipal } from './auth.types';
import {
  IdentityEmailDelivery,
  type EmailPurpose,
} from './identity-email-delivery';
import { sessionAuthority } from './session-authority';

@Injectable()
export class IdentityService {
  constructor(
    private readonly db: DatabaseService,
    private readonly auth: AuthService,
    private readonly config: AuthConfig,
    private readonly mail: IdentityEmailDelivery,
  ) {}

  status(principal: AuthPrincipal) {
    return sessionAuthority(this.db, principal);
  }

  async requestVerification(principal: AuthPrincipal): Promise<void> {
    this.mail.assertAvailable();
    if (principal.authMethod !== 'password') throw new ForbiddenException();
    const delivery = await this.auth.holderTransaction(
      principal.userId,
      async (client) => {
        const state = await sessionAuthority(client, principal);
        if (state.email && !state.passwordVerified) {
          return this.issueEmailProof(
            client,
            principal.userId,
            state.email,
            'verify',
          );
        }
      },
    );
    if (delivery) await this.deliver(delivery);
  }

  async verifyEmail(principal: AuthPrincipal, code: string): Promise<void> {
    if (principal.authMethod !== 'password') throw new ForbiddenException();
    const valid = await this.auth.holderTransaction(
      principal.userId,
      async (client) => {
        const { email, passwordVerified } = await sessionAuthority(
          client,
          principal,
        );
        if (
          !email ||
          passwordVerified ||
          !(await this.consumeEmailProof(
            client,
            principal.userId,
            email,
            'verify',
            code,
          ))
        )
          return false;
        await client.query(
          'UPDATE users SET email_verified_at = clock_timestamp() WHERE id = $1',
          [principal.userId],
        );
        return true;
      },
    );
    if (!valid) throw new BadRequestException('Invalid or expired proof');
  }

  async requestRecovery(email: string): Promise<void> {
    this.mail.assertAvailable();
    const minimumResponseTime = delay(150);
    const userId = await this.recoveryHolder(email);
    if (userId) {
      const delivery = await this.auth.holderTransaction(
        userId,
        async (client) => {
          if ((await this.recoveryHolder(email, client)) === userId) {
            return this.issueEmailProof(client, userId, email, 'recover');
          }
        },
      );
      if (delivery) void this.deliver(delivery).catch(() => undefined);
    }
    await minimumResponseTime;
  }

  async resetPassword(
    email: string,
    code: string,
    newPassword: string,
  ): Promise<void> {
    const passwordHash = await this.auth.hashPassword(newPassword);
    const userId = await this.recoveryHolder(email);
    if (!userId) throw new BadRequestException('Invalid or expired proof');
    const valid = await this.auth.holderTransaction(userId, async (client) => {
      if (
        (await this.recoveryHolder(email, client)) !== userId ||
        !(await this.consumeEmailProof(client, userId, email, 'recover', code))
      )
        return false;
      await this.replacePassword(client, userId, passwordHash, null);
      return true;
    });
    if (!valid) throw new BadRequestException('Invalid or expired proof');
  }

  async changePendingEmail(
    principal: AuthPrincipal,
    email: string,
    password: string,
  ): Promise<void> {
    if (principal.authMethod !== 'password') throw new ForbiddenException();
    const hash = await this.auth.provePassword(
      principal.userId,
      password,
      false,
    );
    await this.auth.holderTransaction(principal.userId, async (client) => {
      const status = await sessionAuthority(client, principal);
      if (status.passwordVerified) throw new ForbiddenException();
      await this.updateEmailCredential(
        client,
        principal.userId,
        email,
        hash,
        false,
      );
      if (status.email !== email) {
        await client.query(
          `UPDATE identity_email_proofs SET consumed_at = clock_timestamp()
           WHERE user_id = $1 AND purpose = 'verify' AND consumed_at IS NULL`,
          [principal.userId],
        );
      }
    });
  }

  async requestPasswordLink(
    principal: AuthPrincipal,
    email: string,
    proof: AppleAuthenticationDto,
  ): Promise<void> {
    this.mail.assertAvailable();
    const delivery = await this.auth.withAppleProof(
      principal,
      proof,
      async (client) => {
        const status = await sessionAuthority(client, principal);
        if (status.hasPassword)
          throw new ConflictException('Password already configured');
        return this.issueEmailProof(
          client,
          principal.userId,
          email,
          'add_password',
          principal.familyId,
        );
      },
    );
    if (delivery) await this.deliver(delivery);
  }

  async linkPassword(
    principal: AuthPrincipal,
    email: string,
    code: string,
    password: string,
    operationId?: string,
  ): Promise<void> {
    if (principal.authMethod !== 'apple') throw new ForbiddenException();
    const receipt = operationId
      ? new IdentityMethodReceipt(principal, operationId, 'password_link')
      : undefined;
    if (await this.auth.replayIdentityMethod(principal, receipt)) return;
    const hash = await this.auth.hashPassword(password);
    const valid = await this.auth.holderTransaction(
      principal.userId,
      async (client) => {
        const status = await sessionAuthority(client, principal);
        if (await receipt?.exists(client)) return true;
        if (
          status.hasPassword ||
          !(await this.consumeEmailProof(
            client,
            principal.userId,
            email,
            'add_password',
            code,
            principal.familyId,
          ))
        )
          return false;
        await this.updateEmailCredential(
          client,
          principal.userId,
          email,
          hash,
          true,
        );
        await receipt?.record(client);
        return true;
      },
    );
    if (!valid) throw new BadRequestException('Invalid or expired proof');
  }

  async unlinkPassword(
    principal: AuthPrincipal,
    proof: AppleAuthenticationDto,
    operationId?: string,
  ): Promise<void> {
    const receipt = operationId
      ? new IdentityMethodReceipt(principal, operationId, 'password_unlink')
      : undefined;
    await this.auth.withAppleProof(
      principal,
      proof,
      async (client) => {
        await client.query(
          'UPDATE users SET password_hash = NULL, email_verified_at = NULL WHERE id = $1',
          [principal.userId],
        );
        await client.query(
          `UPDATE refresh_sessions SET revoked_at = clock_timestamp()
         WHERE user_id = $1 AND auth_identity_id IS NULL AND revoked_at IS NULL`,
          [principal.userId],
        );
        await client.query(
          'DELETE FROM identity_email_proofs WHERE user_id = $1',
          [principal.userId],
        );
        await client.query(
          'DELETE FROM identity_password_changes WHERE user_id = $1 AND committed_at IS NULL',
          [principal.userId],
        );
        await receipt?.record(client);
      },
      receipt,
    );
  }

  async methodOutcome(principal: AuthPrincipal, operationId: string) {
    const {
      rows: [receipt],
    } = await this.db.query<{ action: string }>(
      `SELECT action FROM identity_method_receipts
       WHERE user_id = $1 AND family_id = $2 AND operation_id = $3`,
      [principal.userId, principal.familyId, operationId],
    );
    return receipt
      ? { status: 'committed', action: receipt.action }
      : { status: 'unknown' };
  }

  private async updateEmailCredential(
    client: PoolClient,
    userId: string,
    email: string,
    hash: string,
    verified: boolean,
  ) {
    try {
      const result = await client.query(
        `UPDATE users SET email = $2, password_hash = $3,
                          email_verified_at = CASE WHEN $4 THEN clock_timestamp() ELSE NULL END
         WHERE id = $1 AND (CASE WHEN $4 THEN password_hash IS NULL ELSE password_hash = $3 END)
         RETURNING id`,
        [userId, email, hash, verified],
      );
      if (!result.rowCount)
        throw new ForbiddenException('Invalid method proof');
    } catch (error) {
      if ((error as { constraint?: string }).constraint === 'users_email_key') {
        throw new ConflictException('Email unavailable');
      }
      throw error;
    }
  }

  async prepareChange(
    principal: AuthPrincipal,
    operationId: string,
    password: string,
  ) {
    const hash = await this.auth.provePassword(principal.userId, password);
    const proof = randomBytes(32).toString('base64url');
    await this.auth.holderTransaction(principal.userId, async (client) => {
      await sessionAuthority(client, principal, true);
      await this.auth.assertPasswordUnchanged(client, principal.userId, hash);
      await client.query(
        `DELETE FROM identity_password_changes
         WHERE user_id = $1 AND committed_at IS NULL AND expires_at <= clock_timestamp()`,
        [principal.userId],
      );
      const result = await client.query(
        `INSERT INTO identity_password_changes (user_id, family_id, operation_id, proof_hash, expires_at)
         VALUES ($1, $2, $3, $4, clock_timestamp() + interval '5 minutes')
         ON CONFLICT DO NOTHING`,
        [
          principal.userId,
          principal.familyId,
          operationId,
          this.digest('change', proof),
        ],
      );
      if (!result.rowCount)
        throw new ConflictException('Operation already exists');
    });
    return { proof };
  }

  async changePassword(
    principal: AuthPrincipal,
    operationId: string,
    proof: string,
    password: string,
  ): Promise<void> {
    const hash = await this.auth.hashPassword(password);
    await this.auth.holderTransaction(principal.userId, async (client) => {
      await sessionAuthority(client, principal, true);
      const receipt = await client.query(
        `UPDATE identity_password_changes SET committed_at = clock_timestamp()
         WHERE user_id = $1 AND family_id = $2 AND operation_id = $3 AND proof_hash = $4
           AND committed_at IS NULL AND clock_timestamp() < expires_at RETURNING operation_id`,
        [
          principal.userId,
          principal.familyId,
          operationId,
          this.digest('change', proof),
        ],
      );
      if (!receipt.rowCount)
        throw new BadRequestException('Invalid or expired proof');
      await this.replacePassword(
        client,
        principal.userId,
        hash,
        principal.familyId ?? null,
      );
    });
  }

  async changeOutcome(principal: AuthPrincipal, operationId: string) {
    await sessionAuthority(this.db, principal, true);
    const result = await this.db.query(
      `SELECT 1 FROM identity_password_changes
       WHERE user_id = $1 AND family_id = $2 AND operation_id = $3 AND committed_at IS NOT NULL`,
      [principal.userId, principal.familyId, operationId],
    );
    return { status: result.rowCount ? 'committed' : 'unknown' };
  }

  private async recoveryHolder(
    email: string,
    db: Pick<DatabaseService, 'query'> = this.db,
  ) {
    const result = await db.query<{ id: string }>(
      'SELECT id FROM users WHERE email = $1 AND password_hash IS NOT NULL AND email_verified_at IS NOT NULL',
      [email],
    );
    return result.rows[0]?.id;
  }

  private async issueEmailProof(
    client: PoolClient,
    userId: string,
    email: string,
    purpose: EmailPurpose,
    familyId?: string,
  ) {
    const code = String(randomInt(1_000_000)).padStart(6, '0');
    const hash = this.digest(`${userId}:${purpose}:${email}`, code);
    const result = await client.query(
      `INSERT INTO identity_email_proofs (user_id, purpose, email, proof_hash, family_id, expires_at)
       VALUES ($1, $2, $3, $4, $5, clock_timestamp() + interval '15 minutes')
       ON CONFLICT (user_id, purpose) DO UPDATE SET
         email = EXCLUDED.email, proof_hash = EXCLUDED.proof_hash, family_id = EXCLUDED.family_id,
         expires_at = EXCLUDED.expires_at, consumed_at = NULL,
         attempts = CASE WHEN identity_email_proofs.expires_at <= clock_timestamp()
                         THEN 0 ELSE identity_email_proofs.attempts END
       WHERE identity_email_proofs.expires_at <= clock_timestamp()
          OR (identity_email_proofs.attempts < 5
              AND identity_email_proofs.expires_at <= clock_timestamp() + interval '14 minutes')
       RETURNING user_id`,
      [userId, purpose, email, hash, familyId ?? null],
    );
    if (result.rowCount) return { userId, email, purpose, code, hash };
  }

  private async deliver(delivery: {
    userId: string;
    email: string;
    purpose: EmailPurpose;
    code: string;
    hash: string;
  }) {
    try {
      await this.mail.deliver(delivery.email, delivery.purpose, delivery.code);
    } catch (error) {
      await this.auth.holderTransaction(delivery.userId, async (client) => {
        await client.query(
          `UPDATE identity_email_proofs SET consumed_at = clock_timestamp(),
             expires_at = LEAST(expires_at, clock_timestamp() + interval '14 minutes')
           WHERE user_id = $1 AND purpose = $2 AND proof_hash = $3 AND consumed_at IS NULL`,
          [delivery.userId, delivery.purpose, delivery.hash],
        );
      });
      throw error;
    }
  }

  private async consumeEmailProof(
    client: PoolClient,
    userId: string,
    email: string,
    purpose: EmailPurpose,
    code: string,
    familyId?: string,
  ) {
    const hash = this.digest(`${userId}:${purpose}:${email}`, code);
    const result = await client.query<{ valid: boolean }>(
      `UPDATE identity_email_proofs SET attempts = attempts + 1,
           consumed_at = CASE WHEN proof_hash = $4 THEN clock_timestamp() ELSE NULL END
       WHERE user_id = $1 AND purpose = $2 AND email = $3 AND attempts < 5
         AND consumed_at IS NULL AND clock_timestamp() < expires_at
         AND family_id IS NOT DISTINCT FROM $5::uuid
       RETURNING consumed_at IS NOT NULL AS valid`,
      [userId, purpose, email, hash, familyId ?? null],
    );
    return result.rows[0]?.valid === true;
  }

  private async replacePassword(
    client: PoolClient,
    userId: string,
    hash: string,
    preserveFamily: string | null,
  ) {
    await client.query('UPDATE users SET password_hash = $2 WHERE id = $1', [
      userId,
      hash,
    ]);
    await client.query(
      `UPDATE refresh_sessions SET revoked_at = clock_timestamp()
       WHERE user_id = $1 AND auth_identity_id IS NULL AND revoked_at IS NULL
         AND family_id IS DISTINCT FROM $2::uuid`,
      [userId, preserveFamily],
    );
    await client.query(
      'DELETE FROM identity_password_changes WHERE user_id = $1 AND committed_at IS NULL',
      [userId],
    );
    await client.query(
      `UPDATE identity_email_proofs SET consumed_at = clock_timestamp()
       WHERE user_id = $1 AND purpose = 'recover' AND consumed_at IS NULL`,
      [userId],
    );
  }

  private digest(scope: string, proof: string) {
    return createHmac('sha256', this.config.jwtSecret)
      .update(JSON.stringify(['identity-v1', scope, proof]))
      .digest('hex');
  }
}
