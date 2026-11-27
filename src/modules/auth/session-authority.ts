import {
  ForbiddenException,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import type { PoolClient } from 'pg';
import type { DatabaseService } from '../../common/database/database.service';
import type { AuthPrincipal } from './auth.types';

export function lockHolder(client: PoolClient, userId: string) {
  return client.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [
    userId,
  ]);
}

export async function sessionAuthority(
  db: Pick<DatabaseService, 'query'>,
  principal: AuthPrincipal,
  financial = false,
) {
  if (
    !principal.familyId ||
    !principal.expiresAt ||
    principal.expiresAt <= Date.now()
  ) {
    throw new UnauthorizedException();
  }

  const result = await db
    .query<{
      email: string | null;
      passwordVerified: boolean;
      hasPassword: boolean;
      hasApple: boolean;
      financialAccess: boolean;
    }>(
      `SELECT u.email,
            u.email_verified_at IS NOT NULL AS "passwordVerified",
            u.password_hash IS NOT NULL AS "hasPassword",
            EXISTS (SELECT 1 FROM auth_identities i
                    WHERE i.user_id = u.id AND i.revoked_at IS NULL
                      AND i.unlinked_at IS NULL) AS "hasApple",
            (i.id IS NOT NULL OR u.email_verified_at IS NOT NULL) AS "financialAccess"
       FROM refresh_sessions s
       JOIN users u ON u.id = s.user_id
       LEFT JOIN auth_identities i ON i.id = s.auth_identity_id AND i.user_id = u.id
       WHERE s.user_id = $1 AND s.family_id = $2 AND s.revoked_at IS NULL
         AND clock_timestamp() < LEAST(s.expires_at, s.family_expires_at)
         AND s.family_expires_at IS NOT NULL
         AND (($3 = 'password' AND s.auth_identity_id IS NULL AND u.password_hash IS NOT NULL)
           OR ($3 = 'apple' AND i.id IS NOT NULL AND i.revoked_at IS NULL AND i.unlinked_at IS NULL))`,
      [principal.userId, principal.familyId, principal.authMethod],
    )
    .catch(() => {
      throw new ServiceUnavailableException(
        'Session authority temporarily unavailable',
      );
    });
  const authority = result.rows[0];
  if (!authority) throw new UnauthorizedException();
  if (financial && !authority.financialAccess) {
    throw new ForbiddenException({ code: 'EMAIL_VERIFICATION_REQUIRED' });
  }
  return { ...authority, authMethod: principal.authMethod };
}

export async function authorizeFinancialWrite(
  client: PoolClient,
  userId: string,
  principal?: AuthPrincipal,
): Promise<void> {
  if (principal && principal.userId !== userId) throw new ForbiddenException();
  await lockHolder(client, userId);
  if (principal) await sessionAuthority(client, principal, true);
}

export async function commitFinancialWrite(
  client: PoolClient,
  principal?: AuthPrincipal,
) {
  if (principal) await sessionAuthority(client, principal, true);
  await client.query('COMMIT');
}
