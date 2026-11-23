import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { isUUID } from 'class-validator';
import { createHash, randomUUID } from 'node:crypto';
import { DatabaseService } from '../../common/database/database.service';
import { summarySql } from './mvp-account.service';
import type { MvpAccountSummary } from './mvp-account.service';
import type {
  MvpCheckConfirmation,
  MvpCheckInput,
  MvpCheckQuery,
} from './mvp-check.dto';

export interface MvpCheckReceipt extends MvpCheckInput {
  id: string;
  authorId: string;
  revision: string;
  createdAt: string;
  baseConfirmedAt: string;
  originalCalculatedMinor: string;
  originalDifferenceMinor: string;
}

export interface MvpCheckEntry extends MvpCheckReceipt {
  calculatedAtReferenceMinor: string | null;
  remainingDifferenceMinor: string | null;
  status: 'open' | 'coincident' | 'unavailable';
  resolutionStatus:
    'open' | 'coincident' | 'partially_explained' | 'resolved' | 'unavailable';
  supersededBy: string | null;
  replacesCheckId: string | null;
  replacementReason: string | null;
}

export const receiptFields = `
  id, account_id AS "accountId", user_id AS "authorId",
  observed_minor::text AS "observedMinor", mvp_revision::text AS revision,
  to_char(reference_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "referenceAt",
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "createdAt",
  to_char(base_confirmed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "baseConfirmedAt",
  original_calculated_minor::text AS "originalCalculatedMinor",
  original_difference_minor::text AS "originalDifferenceMinor"
`;

const checksSql = `
  WITH summary AS (${summarySql()}), anchor AS (
    SELECT reference_at, created_at, id FROM mvp_balance_checks
    WHERE user_id = $1 AND account_id = $2 AND id = $3
  )
  SELECT to_jsonb(s) AS summary, EXISTS (SELECT 1 FROM anchor) AS "hasAnchor",
    COALESCE(page.entries, '[]'::jsonb) AS entries
  FROM summary s
  LEFT JOIN LATERAL (
    SELECT jsonb_agg(to_jsonb(entry) ORDER BY entry."referenceAt" DESC, entry."createdAt" DESC, entry.id DESC) AS entries
    FROM (
      SELECT ${receiptFields}, cut.balance::text AS "calculatedAtReferenceMinor",
        (cut.balance - c.observed_minor)::text AS "remainingDifferenceMinor",
        CASE WHEN cut.balance IS NULL THEN 'unavailable'
          WHEN cut.balance = c.observed_minor THEN 'coincident' ELSE 'open' END AS status,
        CASE WHEN cut.balance IS NULL THEN 'unavailable' ELSE
          mvp_recovery_status(c.original_difference_minor, cut.balance - c.observed_minor,
            mvp_recovery_delta(c.id, c.mvp_revision)) END AS "resolutionStatus",
        (SELECT x.replacement_id FROM mvp_check_replacements x WHERE x.original_id = c.id) AS "supersededBy",
        (SELECT x.original_id FROM mvp_check_replacements x WHERE x.replacement_id = c.id) AS "replacesCheckId",
        (SELECT x.reason FROM mvp_check_replacements x WHERE x.replacement_id = c.id OR x.original_id = c.id
          ORDER BY (x.original_id = c.id) DESC LIMIT 1) AS "replacementReason"
      FROM mvp_balance_checks c
      CROSS JOIN LATERAL (
        SELECT CASE WHEN s.status = 'available' THEN
          mvp_balance_at(c.user_id, c.account_id, (s.base->>'baseMinor')::bigint,
            (s.base->>'coverageStart')::timestamptz, c.reference_at) END AS balance
      ) cut
      WHERE c.user_id = $1 AND c.account_id = $2 AND s.revision IS NOT NULL
        AND ($4::text IS NULL OR s.revision = $4)
        AND (NOT $5::boolean OR (cut.balance <> c.observed_minor AND NOT EXISTS
          (SELECT 1 FROM mvp_check_replacements x WHERE x.original_id = c.id)))
        AND ($3::uuid IS NULL OR (c.reference_at, c.created_at, c.id) <
          (SELECT reference_at, created_at, id FROM anchor))
      ORDER BY c.reference_at DESC, c.created_at DESC, c.id DESC
      LIMIT 51
    ) entry
  ) page ON true
`;

@Injectable()
export class MvpCheckService {
  constructor(private readonly db: DatabaseService) {}

  async preview(userId: string, dto: MvpCheckInput) {
    const input = this.normalize(dto);
    const {
      rows: [check],
    } = await this.db.query<{
      revision: string | null;
      covered: boolean;
      ambiguous: boolean;
      suspended: boolean;
      calculatedMinor: string;
      differenceMinor: string;
    }>(
      `SELECT m.revision::text, m.base_suspended AS suspended,
        $3::timestamptz BETWEEN m.coverage_start AND statement_timestamp() AS covered,
        mvp_cut_needs_occurrence_time(a.user_id, a.id, $3) AS ambiguous,
        cut.balance::text AS "calculatedMinor",
        (cut.balance - $4::bigint)::text AS "differenceMinor"
       FROM accounts a
       LEFT JOIN mvp_accounts m ON m.user_id = a.user_id AND m.account_id = a.id
       CROSS JOIN LATERAL (
         SELECT mvp_balance_at(m.user_id, m.account_id, m.base_minor, m.coverage_start, $3) AS balance
       ) cut
       WHERE a.user_id = $1 AND a.id = $2 AND a.currency = 'BRL'`,
      [userId, input.accountId, input.referenceAt, input.observedMinor],
    );
    const revision = this.requireBase(check?.revision);
    if (check.suspended) this.suspended();
    if (!check.covered) {
      throw new BadRequestException(
        'Reference time is outside account coverage',
      );
    }
    if (check.ambiguous) this.ambiguousCut();
    return {
      ...input,
      revision,
      calculatedMinor: check.calculatedMinor,
      differenceMinor: check.differenceMinor,
    };
  }

  async list(userId: string, accountId: string, query: MvpCheckQuery) {
    if (Boolean(query.after) !== Boolean(query.revision)) {
      throw new BadRequestException(
        'A check page requires both after and revision',
      );
    }
    const {
      rows: [page],
    } = await this.db.query<{
      summary: MvpAccountSummary;
      hasAnchor: boolean;
      entries: MvpCheckEntry[];
    }>(checksSql, [
      userId,
      accountId,
      query.after ?? null,
      query.revision ?? null,
      query.view === 'pending',
    ]);
    const revision = this.requireBase(
      page.summary.account ? page.summary.revision : undefined,
    );
    if (query.revision !== undefined && query.revision !== revision)
      this.stale();
    if (query.after && !page.hasAnchor)
      throw new BadRequestException('Invalid check page anchor');

    const entries = page.entries.slice(0, 50);
    return {
      summary: page.summary,
      entries,
      nextAfter:
        page.entries.length > entries.length ? entries.at(-1)?.id : null,
    };
  }

  async confirm(
    userId: string,
    key: string,
    dto: MvpCheckConfirmation,
  ): Promise<MvpCheckReceipt> {
    if (!isUUID(key))
      throw new BadRequestException('Idempotency-Key must be a UUID');
    if (BigInt(dto.expectedRevision) >= 1n << 63n) {
      throw new BadRequestException('Revision is outside the supported range');
    }
    key = key.toLowerCase();
    const input = this.normalize(dto);
    const hash = createHash('sha256')
      .update(
        JSON.stringify([
          'mvp.check.confirm',
          1,
          userId,
          input,
          dto.expectedRevision,
        ]),
      )
      .digest('hex');
    const client = await this.db.getClient();
    try {
      await client.query('BEGIN');
      await client.query("SET LOCAL lock_timeout = '3s'");
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [
        `${userId}:${key}`,
      ]);
      const {
        rows: [receipt],
      } = await client.query<{
        request_hash: string;
        response: MvpCheckReceipt;
      }>(
        'SELECT request_hash, response FROM idempotency_keys WHERE user_id = $1 AND idempotency_key = $2 FOR UPDATE',
        [userId, key],
      );
      if (receipt) {
        if (receipt.request_hash !== hash) {
          throw new ConflictException({
            statusCode: 409,
            code: 'IDEMPOTENCY_CONFLICT',
            message: 'Idempotency key already used for another request',
          });
        }
        await client.query('COMMIT');
        return receipt.response;
      }

      const {
        rows: [active],
      } = await client.query<{ revision: string }>(
        'SELECT revision::text FROM mvp_accounts WHERE user_id = $1 AND account_id = $2 FOR NO KEY UPDATE',
        [userId, input.accountId],
      );
      if (!active) {
        const owned = await client.query(
          "SELECT 1 FROM accounts WHERE user_id = $1 AND id = $2 AND currency = 'BRL'",
          [userId, input.accountId],
        );
        this.requireBase(owned.rowCount ? null : undefined);
      }
      if (active.revision !== dto.expectedRevision) this.stale();
      const {
        rows: [created],
      } = await client.query<MvpCheckReceipt>(
        `INSERT INTO mvp_balance_checks (id, user_id, account_id, observed_minor, reference_at, mvp_revision, mvp_write_key)
         VALUES ($1, $2, $3, $4, $5, $6::bigint + 1, $7) RETURNING ${receiptFields}`,
        [
          randomUUID(),
          userId,
          input.accountId,
          input.observedMinor,
          input.referenceAt,
          active.revision,
          key,
        ],
      );
      await client.query(
        `INSERT INTO idempotency_keys (id, user_id, idempotency_key, request_hash, response)
         VALUES ($1, $2, $3, $4, $5::jsonb)`,
        [randomUUID(), userId, key, hash, JSON.stringify(created)],
      );
      await client.query('COMMIT');
      return created;
    } catch (error) {
      await client.query('ROLLBACK');
      const { code, constraint } = error as {
        code?: string;
        constraint?: string;
      };
      if (code === '55P03') {
        throw new ServiceUnavailableException(
          'Check confirmation is temporarily unavailable; retry the same request',
        );
      }
      if (constraint === 'mvp_base_suspended') this.suspended();
      if (constraint === 'mvp_cut_requires_time') this.ambiguousCut();
      if (constraint === 'mvp_check_coverage') {
        throw new BadRequestException(
          'Reference time is outside account coverage',
        );
      }
      throw error;
    } finally {
      client.release();
    }
  }

  private normalize(dto: MvpCheckInput): MvpCheckInput {
    const value = BigInt(dto.observedMinor);
    if (value < -(1n << 63n) || value >= 1n << 63n) {
      throw new BadRequestException(
        'Observed balance is outside the supported range',
      );
    }
    const [seconds, fraction = ''] = dto.referenceAt.slice(0, -1).split('.');
    return {
      accountId: dto.accountId.toLowerCase(),
      observedMinor: dto.observedMinor,
      referenceAt: `${seconds}.${fraction.padEnd(6, '0')}Z`,
    };
  }

  private requireBase(revision: string | null | undefined): string {
    if (revision === undefined)
      throw new NotFoundException('Account not found');
    if (revision === null) {
      throw new ConflictException({
        statusCode: 409,
        code: 'BASE_REQUIRED',
        message: 'A confirmed balance base is required',
      });
    }
    return revision;
  }

  private suspended(): never {
    throw new ConflictException({
      statusCode: 409,
      code: 'BASE_SUSPENDED',
      message: 'The opening balance is under review',
    });
  }

  private ambiguousCut(): never {
    throw new ConflictException({
      statusCode: 409,
      code: 'OCCURRENCE_TIME_REQUIRED',
      message:
        'Choose another cut; a date-only movement is ambiguous at this time',
    });
  }

  private stale(): never {
    throw new ConflictException({
      statusCode: 409,
      code: 'STALE_REVISION',
      message: 'Account changed; review the current balance',
    });
  }
}
