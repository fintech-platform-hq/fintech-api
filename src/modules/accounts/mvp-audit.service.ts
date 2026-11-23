import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { isUUID } from 'class-validator';
import {
  createHash,
  createHmac,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';
import { DatabaseService } from '../../common/database/database.service';
import { AuthConfig } from '../auth/auth.config';
import type { MvpAuditConfirmation, MvpAuditInput } from './mvp-audit.dto';
import { receiptFields } from './mvp-check.service';

const timestamp = (column: string) =>
  `to_char(${column} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;

const movementPreviewSql = `
  WITH current AS (
    SELECT t.*, a.revision, a.coverage_start, a.base_minor,
      COALESCE($4::integer, t.amount_minor) AS next_amount,
      CASE WHEN $5::boolean THEN $6::text ELSE t.description END AS next_description,
      COALESCE($7::timestamptz, t.occurred_at) AS next_time,
      CASE WHEN $7 IS NULL THEN t.latest_occurrence_at END AS next_last
    FROM mvp_accounts a JOIN mvp_effective_movements t ON (t.user_id, t.account_id) = (a.user_id, a.account_id)
    WHERE a.user_id = $1 AND a.account_id = $2 AND t.id = $3
  ), impacts AS (
    SELECT t.*,
      mvp_balance_at(t.user_id, t.account_id, t.base_minor, t.coverage_start, statement_timestamp()) AS balance,
      mvp_movement_effect(t.type, t.next_amount, t.next_time, t.next_last, t.coverage_start, statement_timestamp(), $8::boolean)
      - mvp_movement_effect(t.type, t.amount_minor, t.occurred_at, t.latest_occurrence_at,
          t.coverage_start, statement_timestamp(), t.invalidated) AS delta
    FROM current t
  )
  SELECT t.revision::text, t.invalidated AS blocked,
    ($8 OR t.next_time BETWEEN t.coverage_start AND statement_timestamp()) AS covered,
    ($8 OR ROW(t.next_amount, t.next_description, t.next_time, t.next_last)
      IS DISTINCT FROM ROW(t.amount_minor, t.description, t.occurred_at, t.latest_occurrence_at)) AS changed,
    t.balance::text AS "balanceMinor", (t.balance + t.delta)::text AS "projectedBalanceMinor",
    COALESCE((
      SELECT jsonb_agg(jsonb_build_object('id', c.id, 'referenceAt', ${timestamp('c.reference_at')},
        'originalDifferenceMinor', c.original_difference_minor::text, 'beforeMinor', d.before::text,
        'afterMinor', (d.before + d.delta)::text) ORDER BY c.reference_at DESC, c.id)
      FROM mvp_balance_checks c
      CROSS JOIN LATERAL (
        SELECT mvp_balance_at(t.user_id, t.account_id, t.base_minor, t.coverage_start, c.reference_at)
          - c.observed_minor AS before,
          mvp_movement_effect(t.type, t.next_amount, t.next_time, t.next_last, t.coverage_start, c.reference_at, $8)
          - mvp_movement_effect(t.type, t.amount_minor, t.occurred_at, t.latest_occurrence_at,
              t.coverage_start, c.reference_at, t.invalidated) AS delta
      ) d
      WHERE (c.user_id, c.account_id) = (t.user_id, t.account_id) AND d.delta <> 0
    ), '[]'::jsonb) AS checks
  FROM impacts t
`;

const replacementPreviewSql = `
  SELECT a.revision::text,
    EXISTS (SELECT 1 FROM mvp_check_replacements x WHERE x.original_id = c.id) AS blocked,
    $4::timestamptz BETWEEN a.coverage_start AND statement_timestamp() AS covered,
    ($4 <> c.reference_at OR $5::bigint <> c.observed_minor) AS changed,
    mvp_cut_needs_occurrence_time(a.user_id, a.account_id, $4) AS ambiguous,
    b.current::text AS "balanceMinor", b.current::text AS "projectedBalanceMinor",
    jsonb_build_array(jsonb_build_object('id', c.id, 'referenceAt', ${timestamp('$4::timestamptz')},
      'originalDifferenceMinor', c.original_difference_minor::text,
      'beforeMinor', (b.previous - c.observed_minor)::text, 'afterMinor', (b.proposed - $5::bigint)::text)) AS checks
  FROM mvp_accounts a
  JOIN mvp_balance_checks c ON (c.user_id, c.account_id) = (a.user_id, a.account_id) AND c.id = $3
  CROSS JOIN LATERAL (
    SELECT mvp_balance_at(a.user_id, a.account_id, a.base_minor, a.coverage_start, statement_timestamp()) AS current,
      mvp_balance_at(a.user_id, a.account_id, a.base_minor, a.coverage_start, c.reference_at) AS previous,
      mvp_balance_at(a.user_id, a.account_id, a.base_minor, a.coverage_start, $4) AS proposed
  ) b
  WHERE a.user_id = $1 AND a.account_id = $2
`;

interface AuditProjection {
  revision: string;
  blocked: boolean;
  covered: boolean;
  changed: boolean;
  ambiguous?: boolean;
  balanceMinor: string;
  projectedBalanceMinor: string;
  checks: {
    id: string;
    referenceAt: string;
    originalDifferenceMinor: string;
    beforeMinor: string;
    afterMinor: string;
  }[];
}

export interface AuditReceipt {
  id: string;
  accountId: string;
  authorId: string;
  action: MvpAuditInput['action'];
  reason: string;
  revision: string;
  createdAt: string;
  transactionId?: string;
  replacesCheckId?: string;
}

@Injectable()
export class MvpAuditService {
  private readonly previewKey: Buffer;

  constructor(
    private readonly db: DatabaseService,
    config: AuthConfig,
  ) {
    this.previewKey = createHmac('sha256', config.jwtSecret)
      .update('mvp.audit.preview.v1')
      .digest();
  }

  async preview(userId: string, dto: MvpAuditInput) {
    const input = this.normalize(dto);
    const { revision, balanceMinor, projectedBalanceMinor, checks } =
      await this.project(this.db, userId, input);
    return {
      accountId: input.accountId,
      targetId: input.targetId,
      revision,
      balanceMinor,
      projectedBalanceMinor,
      checks,
      previewToken: this.token(userId, input, revision),
    };
  }

  async versions(userId: string, accountId: string, targetId: string) {
    const { rows } = await this.db.query(
      `WITH versions AS (
         SELECT t.id, 'original' AS action, t.user_id AS "authorId", NULL AS reason,
           t.amount_minor::text AS "amountMinor", t.description, t.occurrence_day::text AS "occurrenceDay",
           ${timestamp('t.occurred_at')} AS "occurredAt", ${timestamp('t.created_at')} AS "createdAt",
           t.mvp_revision
         FROM transactions t JOIN mvp_accounts a USING (user_id, account_id)
         WHERE t.user_id = $1 AND t.account_id = $2 AND t.id = $3
         UNION ALL
         SELECT v.id, v.action, v.user_id, v.reason, v.amount_minor::text, v.description, v.occurrence_day::text,
           ${timestamp('v.occurred_at')}, ${timestamp('v.created_at')}, v.mvp_revision
         FROM mvp_movement_versions v WHERE v.user_id = $1 AND v.account_id = $2 AND v.transaction_id = $3
       )
       SELECT id, action, "authorId", reason, "amountMinor", description, "occurrenceDay", "occurredAt", "createdAt",
         mvp_revision::text AS revision
       FROM versions ORDER BY mvp_revision NULLS FIRST`,
      [userId, accountId, targetId],
    );
    if (rows.length === 0) throw new NotFoundException('Movement not found');
    return rows;
  }

  async confirm(
    userId: string,
    key: string,
    dto: MvpAuditConfirmation,
  ): Promise<AuditReceipt> {
    if (!isUUID(key))
      throw new BadRequestException('Idempotency-Key must be a UUID');
    key = key.toLowerCase();
    const input = this.normalize(dto);
    const revision = dto.expectedRevision;
    const hash = createHash('sha256')
      .update(JSON.stringify(['mvp.audit.confirm', 1, userId, input, revision]))
      .digest('hex');
    const client = await this.db.getClient();
    try {
      await client.query('BEGIN');
      await client.query("SET LOCAL lock_timeout = '3s'");
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [
        `${userId}:${key}`,
      ]);
      const {
        rows: [previous],
      } = await client.query<{ request_hash: string; response: AuditReceipt }>(
        'SELECT request_hash, response FROM idempotency_keys WHERE user_id = $1 AND idempotency_key = $2 FOR UPDATE',
        [userId, key],
      );
      if (previous) {
        if (previous.request_hash !== hash)
          this.conflict('IDEMPOTENCY_CONFLICT', 'Idempotency key already used');
        await client.query('COMMIT');
        return previous.response;
      }
      const {
        rows: [active],
      } = await client.query<{ revision: string }>(
        'SELECT revision::text FROM mvp_accounts WHERE user_id = $1 AND account_id = $2 FOR NO KEY UPDATE',
        [userId, input.accountId],
      );
      if (!active) throw new NotFoundException('Account not found');
      if (active.revision !== revision)
        this.conflict(
          'STALE_REVISION',
          'Account changed; request a new preview',
        );
      const expected = this.token(userId, input, revision);
      if (
        !/^[0-9a-f]{64}$/.test(dto.previewToken) ||
        !timingSafeEqual(
          Buffer.from(expected, 'hex'),
          Buffer.from(dto.previewToken, 'hex'),
        )
      ) {
        this.conflict(
          'AUDIT_PREVIEW_REQUIRED',
          'Request a preview of this change',
        );
      }
      await this.project(client, userId, input);
      const id = randomUUID();
      const params = [
        id,
        userId,
        input.accountId,
        input.targetId,
        revision,
        key,
        input.reason,
      ];
      let receipt: AuditReceipt;
      if (input.action === 'replace_check') {
        const {
          rows: [check],
        } = await client.query<AuditReceipt>(
          `INSERT INTO mvp_balance_checks (id, user_id, account_id, observed_minor, reference_at, mvp_revision, mvp_write_key)
           VALUES ($1, $2, $3, $4, $5, $6::bigint + 1, $7) RETURNING ${receiptFields}`,
          [
            id,
            userId,
            input.accountId,
            input.observedMinor,
            input.referenceAt,
            revision,
            key,
          ],
        );
        await client.query(
          'INSERT INTO mvp_check_replacements (user_id, account_id, original_id, replacement_id, reason) VALUES ($1,$2,$3,$4,$5)',
          [userId, input.accountId, input.targetId, id, input.reason],
        );
        receipt = {
          ...check,
          action: input.action,
          replacesCheckId: input.targetId,
          reason: input.reason,
        };
      } else {
        const {
          rows: [version],
        } = await client.query<AuditReceipt>(
          `INSERT INTO mvp_movement_versions
           (id,user_id,account_id,transaction_id,mvp_revision,mvp_write_key,reason,action,
             amount_minor,description,occurred_at,occurrence_day)
           SELECT $1,$2,$3,$4,$5::bigint + 1,$6,$7,$8,COALESCE($9::integer,t.amount_minor),
             CASE WHEN $10::boolean THEN NULLIF($11::text, '') ELSE t.description END,
             COALESCE($12::timestamptz,t.occurred_at), CASE WHEN $12 IS NULL THEN t.occurrence_day END
           FROM mvp_effective_movements t WHERE t.user_id = $2 AND t.account_id = $3 AND t.id = $4
           RETURNING id, account_id AS "accountId", user_id AS "authorId", action, reason, transaction_id AS "transactionId",
             mvp_revision::text AS revision, ${timestamp('created_at')} AS "createdAt"`,
          [
            ...params,
            input.action,
            input.amountMinor ?? null,
            input.description !== undefined,
            input.description ?? null,
            input.occurredAt ?? null,
          ],
        );
        receipt = version;
      }
      await client.query(
        'INSERT INTO idempotency_keys (id, user_id, idempotency_key, request_hash, response) VALUES ($1,$2,$3,$4,$5)',
        [randomUUID(), userId, key, hash, JSON.stringify(receipt)],
      );
      await client.query('COMMIT');
      return receipt;
    } catch (error) {
      await client.query('ROLLBACK');
      const { code } = error as { code?: string };
      if (code === '55P03')
        throw new ServiceUnavailableException(
          'Retry the same audited confirmation',
        );
      throw error;
    } finally {
      client.release();
    }
  }

  private async project(
    db: Pick<DatabaseService, 'query'>,
    userId: string,
    input: MvpAuditInput,
  ) {
    const scope = [userId, input.accountId, input.targetId];
    const result =
      input.action === 'replace_check'
        ? await db.query<AuditProjection>(replacementPreviewSql, [
            ...scope,
            input.referenceAt,
            input.observedMinor,
          ])
        : await db.query<AuditProjection>(movementPreviewSql, [
            ...scope,
            input.amountMinor ?? null,
            input.description !== undefined,
            input.description?.trim() || null,
            input.occurredAt ?? null,
            input.action === 'invalidate',
          ]);
    const [projection] = result.rows;
    if (!projection) throw new NotFoundException('Audited target not found');
    if (projection.blocked)
      this.conflict(
        'AUDIT_TARGET_INACTIVE',
        'The target has already been invalidated or replaced',
      );
    if (projection.ambiguous)
      this.conflict(
        'OCCURRENCE_TIME_REQUIRED',
        'A date-only movement is ambiguous at this cut',
      );
    if (!projection.covered || !projection.changed)
      throw new BadRequestException(
        'Provide a change within the account coverage',
      );
    return projection;
  }

  private token(userId: string, input: MvpAuditInput, revision: string) {
    return createHmac('sha256', this.previewKey)
      .update(JSON.stringify([userId, input, revision]))
      .digest('hex');
  }

  private normalize(dto: MvpAuditInput): MvpAuditInput {
    const reason = dto.reason.trim();
    const change =
      dto.amountMinor != null ||
      dto.description != null ||
      dto.occurredAt != null;
    const observation = dto.observedMinor != null || dto.referenceAt != null;
    if (
      !reason ||
      reason.includes('\u0000') ||
      dto.description?.includes('\u0000') ||
      (dto.action === 'correct' && (!change || observation)) ||
      (dto.action === 'invalidate' && (change || observation)) ||
      (dto.action === 'replace_check' &&
        (change || dto.observedMinor == null || !dto.referenceAt))
    ) {
      throw new BadRequestException(
        'Provide a reason and only the fields allowed for this operation',
      );
    }
    if (
      dto.observedMinor != null &&
      (BigInt(dto.observedMinor) < -(1n << 63n) ||
        BigInt(dto.observedMinor) >= 1n << 63n)
    ) {
      throw new BadRequestException(
        'Observed balance is outside the supported range',
      );
    }
    const utc = (input?: string) => {
      if (!input) return undefined;
      const [seconds, fraction = ''] = input.slice(0, -1).split('.');
      return `${seconds}.${fraction.padEnd(6, '0')}Z`;
    };
    return {
      accountId: dto.accountId.toLowerCase(),
      targetId: dto.targetId.toLowerCase(),
      action: dto.action,
      reason,
      amountMinor: dto.amountMinor ?? undefined,
      description: dto.description?.trim(),
      occurredAt: utc(dto.occurredAt),
      observedMinor: dto.observedMinor ?? undefined,
      referenceAt: utc(dto.referenceAt),
    };
  }

  private conflict(code: string, message: string): never {
    throw new ConflictException({ statusCode: 409, code, message });
  }
}
