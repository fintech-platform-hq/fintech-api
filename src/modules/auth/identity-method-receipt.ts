import { ConflictException } from '@nestjs/common';
import type { DatabaseService } from '../../common/database/database.service';
import type { PoolClient } from 'pg';
import type { AuthPrincipal } from './auth.types';

type IdentityMethodAction =
  'apple_link' | 'apple_unlink' | 'password_link' | 'password_unlink';

export class IdentityMethodReceipt {
  constructor(
    private readonly principal: AuthPrincipal,
    private readonly operationId: string,
    private readonly action: IdentityMethodAction,
  ) {}

  async exists(db: Pick<DatabaseService, 'query'>): Promise<boolean> {
    const {
      rows: [receipt],
    } = await db.query<{ action: IdentityMethodAction }>(
      `SELECT action FROM identity_method_receipts
       WHERE user_id = $1 AND family_id = $2 AND operation_id = $3`,
      this.scope,
    );
    if (receipt && receipt.action !== this.action) {
      throw new ConflictException(
        'Operation ID already used for another action',
      );
    }
    return receipt !== undefined;
  }

  async record(client: PoolClient): Promise<void> {
    await client.query(
      `INSERT INTO identity_method_receipts (user_id, family_id, operation_id, action)
       VALUES ($1, $2, $3, $4)`,
      [...this.scope, this.action],
    );
  }

  private get scope() {
    return [this.principal.userId, this.principal.familyId, this.operationId];
  }
}
