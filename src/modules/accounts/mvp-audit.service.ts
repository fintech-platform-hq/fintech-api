import {
  authorizeFinancialWrite,
  commitFinancialWrite,
} from '../auth/session-authority';
import type { AuthPrincipal } from '../auth/auth.types';
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

import {
  auditTimestamp as timestamp,
  basePreviewSql,
  baseVersionFields,
} from './mvp-base-projection';

const isBaseAction = (action: MvpAuditInput['action']) =>
  action === 'correct_base' || action === 'suspend_base';

const isI5Action = (action: MvpAuditInput['action']) =>
  isBaseAction(action) || action === 'refine_occurrence';

const movementPreviewSql = `
  WITH current AS (
    SELECT t.*, a.revision, a.coverage_start, a.base_minor, a.base_suspended,
      COALESCE($4::integer, t.amount_minor) AS next_amount,
      CASE WHEN $5::boolean THEN $6::text ELSE t.description END AS next_description,
      COALESCE($7::timestamptz, t.occurred_at) AS next_time,
      CASE WHEN $7 IS NULL THEN t.latest_occurrence_at END AS next_last
    FROM mvp_accounts a JOIN mvp_effective_movements t ON (t.user_id, t.account_id) = (a.user_id, a.account_id)
    WHERE a.user_id = $1 AND a.account_id = $2 AND t.id = $3
  ), impacts AS (
    SELECT t.*,
      CASE WHEN NOT t.base_suspended THEN mvp_balance_at(t.user_id, t.account_id, t.base_minor, t.coverage_start, statement_timestamp()) END AS balance,
      mvp_movement_effect(t.type, t.next_amount, t.next_time, t.next_last, t.coverage_start, statement_timestamp(), $8::boolean)
      - mvp_movement_effect(t.type, t.amount_minor, t.occurred_at, t.latest_occurrence_at,
          t.coverage_start, statement_timestamp(), t.invalidated) AS delta
    FROM current t
  )
  SELECT t.revision::text, t.invalidated AS blocked, t.base_suspended AND NOT $9 AS suspended,
    CASE WHEN $9 THEN t.latest_occurrence_at IS NOT NULL AND t.next_time BETWEEN t.occurred_at AND t.latest_occurrence_at
      ELSE $8 OR $7 IS NULL OR t.next_time BETWEEN t.coverage_start AND statement_timestamp() END AS covered,
    ($8 OR ROW(t.next_amount, t.next_description, t.next_time, t.next_last)
      IS DISTINCT FROM ROW(t.amount_minor, t.description, t.occurred_at, t.latest_occurrence_at)) AS changed,
    t.balance::text AS "balanceMinor", (t.balance + t.delta)::text AS "projectedBalanceMinor",
    COALESCE((
      SELECT jsonb_agg(jsonb_build_object('id', c.id, 'referenceAt', ${timestamp('c.reference_at')},
        'originalDifferenceMinor', c.original_difference_minor::text, 'beforeMinor', d.before::text,
        'afterMinor', (d.before + d.delta)::text) ORDER BY c.reference_at DESC, c.id)
      FROM mvp_balance_checks c
      CROSS JOIN LATERAL (
        SELECT CASE WHEN NOT t.base_suspended THEN mvp_balance_at(t.user_id, t.account_id, t.base_minor, t.coverage_start, c.reference_at)
          - c.observed_minor END AS before,
          mvp_movement_effect(t.type, t.next_amount, t.next_time, t.next_last, t.coverage_start, c.reference_at, $8)
          - mvp_movement_effect(t.type, t.amount_minor, t.occurred_at, t.latest_occurrence_at,
              t.coverage_start, c.reference_at, t.invalidated) AS delta
      ) d
      WHERE (c.user_id, c.account_id) = (t.user_id, t.account_id) AND d.delta <> 0
    ), '[]'::jsonb) AS checks
  FROM impacts t
`;

const replacementPreviewSql = `
  SELECT a.revision::text, a.base_suspended AS suspended,
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
  suspended?: boolean;
  balanceMinor: string | null;
  projectedBalanceMinor: string | null;
  previousBaseMinor?: string;
  previousCoverageStart?: string;
  proposedBaseMinor?: string;
  proposedCoverageStart?: string;
  ambiguousMovementIds?: string[];
  coverageChanges?: {
    id: string;
    description: string | null;
    occurrenceDay: string | null;
    occurredAt: string | null;
    before: 'covered' | 'before_base';
    after: 'covered' | 'before_base' | 'ambiguous';
  }[];
  checks: {
    id: string;
    referenceAt: string;
    originalDifferenceMinor: string;
    beforeMinor: string | null;
    afterMinor: string | null;
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
    const projection = await this.project(this.db, userId, input);
    const { revision, balanceMinor, projectedBalanceMinor, checks } =
      projection;
    return {
      accountId: input.accountId,
      targetId: input.targetId,
      revision,
      balanceMinor,
      projectedBalanceMinor,
      checks,
      ...(isBaseAction(input.action) && {
        previousBaseMinor: projection.previousBaseMinor,
        previousCoverageStart: projection.previousCoverageStart,
        proposedBaseMinor: projection.proposedBaseMinor,
        proposedCoverageStart: projection.proposedCoverageStart,
        ambiguousMovementIds: projection.ambiguousMovementIds,
        coverageChanges: projection.coverageChanges,
      }),
      previewToken: projection.ambiguousMovementIds?.length
        ? null
        : this.token(userId, input, revision),
    };
  }

  async baseVersions(userId: string, accountId: string) {
    const { rows } = await this.db.query(
      `SELECT ${baseVersionFields} FROM mvp_base_versions
       WHERE user_id = $1 AND account_id = $2 ORDER BY mvp_base_versions.revision DESC`,
      [userId, accountId],
    );
    if (!rows.length)
      throw new NotFoundException('Confirmed account not found');
    return rows;
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
    principal?: AuthPrincipal,
  ): Promise<AuditReceipt> {
    if (!isUUID(key))
      throw new BadRequestException('Idempotency-Key must be a UUID');
    key = key.toLowerCase();
    const input = this.normalize(dto);
    if (isI5Action(input.action) && dto.confirmed !== true)
      throw new BadRequestException('Confirm the reviewed change explicitly');
    const revision = dto.expectedRevision;
    const terms = ['mvp.audit.confirm', 1, userId, input, revision];
    if (isI5Action(input.action)) terms.push(dto.previewToken);
    const hash = createHash('sha256')
      .update(JSON.stringify(terms))
      .digest('hex');
    const client = await this.db.getClient();
    try {
      await client.query('BEGIN');
      await client.query("SET LOCAL lock_timeout = '3s'");
      await authorizeFinancialWrite(client, userId, principal);
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
        await commitFinancialWrite(client, principal);
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
      const projection = await this.project(client, userId, input);
      if (projection.ambiguousMovementIds?.length)
        this.conflict(
          'OCCURRENCE_TIME_REQUIRED',
          'Resolve the ambiguous movements before changing the base',
        );
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
      if (isBaseAction(input.action)) {
        const {
          rows: [version],
        } = await client.query<AuditReceipt>(
          `INSERT INTO mvp_base_versions
           (id,user_id,account_id,revision,action,base_minor,coverage_start,reason,write_key)
           VALUES ($1,$2,$3,$4::bigint + 1,$5,$6,$7,$8,$9)
           RETURNING ${baseVersionFields}`,
          [
            id,
            userId,
            input.accountId,
            revision,
            input.action,
            projection.proposedBaseMinor,
            projection.proposedCoverageStart,
            input.reason,
            key,
          ],
        );
        receipt = version;
      } else if (input.action === 'replace_check') {
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
      await commitFinancialWrite(client, principal);
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
    const result = isBaseAction(input.action)
      ? await db.query<AuditProjection>(basePreviewSql, [
          userId,
          input.accountId,
          input.baseMinor ?? null,
          input.coverageStart ?? null,
          input.action === 'suspend_base',
        ])
      : input.action === 'replace_check'
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
            input.action === 'refine_occurrence',
          ]);
    const [projection] = result.rows;
    if (!projection) throw new NotFoundException('Audited target not found');
    if (projection.suspended)
      this.conflict('BASE_SUSPENDED', 'The opening balance is under review');
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
    const baseAction = isBaseAction(dto.action);
    const baseTerms = dto.baseMinor != null || dto.coverageStart != null;
    if (
      !reason ||
      reason.includes('\u0000') ||
      dto.description?.includes('\u0000') ||
      (!baseAction && baseTerms) ||
      (baseAction &&
        (change ||
          observation ||
          dto.targetId.toLowerCase() !== dto.accountId.toLowerCase())) ||
      (dto.action === 'correct_base' && dto.baseMinor == null) ||
      (dto.action === 'suspend_base' && baseTerms) ||
      (dto.action === 'refine_occurrence' &&
        (!dto.occurredAt ||
          dto.amountMinor != null ||
          dto.description != null ||
          observation)) ||
      (dto.action === 'correct' && (!change || observation)) ||
      (dto.action === 'invalidate' && (change || observation)) ||
      (dto.action === 'replace_check' &&
        (change || dto.observedMinor == null || !dto.referenceAt))
    ) {
      throw new BadRequestException(
        'Provide a reason and only the fields allowed for this operation',
      );
    }
    const signedMinor = dto.baseMinor ?? dto.observedMinor;
    if (
      signedMinor != null &&
      (BigInt(signedMinor) < -(1n << 63n) || BigInt(signedMinor) >= 1n << 63n)
    ) {
      throw new BadRequestException('Balance is outside the supported range');
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
      baseMinor: dto.baseMinor ?? undefined,
      coverageStart: utc(dto.coverageStart),
    };
  }

  private conflict(code: string, message: string): never {
    throw new ConflictException({ statusCode: 409, code, message });
  }
}
