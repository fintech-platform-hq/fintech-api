import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { isUUID } from 'class-validator';
import { createHash, randomUUID } from 'node:crypto';
import type { PoolClient } from 'pg';
import { DatabaseService } from '../../common/database/database.service';
import type {
  MvpRecoveryConfirmation,
  MvpRecoveryInput,
} from './mvp-recovery.dto';

type DateStatus =
  'eligible' | 'time_required' | 'outside_coverage' | 'after_check';
interface RecoveryCandidate {
  id: string;
  amountMinor: string;
  description: string | null;
  occurredAt: string | null;
  occurrenceDay: string | null;
  occurrenceZone: string | null;
  alreadyLinked: boolean;
}

export interface RecoveryPreview {
  checkId: string;
  accountId: string;
  revision: string;
  referenceZone: string;
  dateStatus: DateStatus;
  balanceMinor: string;
  remainingDifferenceMinor: string;
  projectedBalanceMinor: string | null;
  projectedRemainingDifferenceMinor: string | null;
  ambiguousCheckIds: string[];
  candidates: RecoveryCandidate[];
  existingRecovery: RecoveryReceipt | null;
}

export interface RecoveryReceipt {
  id: string;
  accountId: string;
  checkId: string;
  authorId: string;
  action: 'link' | 'create';
  transactionId: string;
  revision: string;
  createdAt: string;
}

const receiptFields = `
  id, account_id AS "accountId", check_id AS "checkId", user_id AS "authorId",
  action, transaction_id AS "transactionId", mvp_revision::text AS revision,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "createdAt"
`;

const previewSql = `
  SELECT c.id AS "checkId", m.account_id AS "accountId", m.revision::text,
    m.reference_zone AS "referenceZone",
    eligibility.status AS "dateStatus",
    balances.current::text AS "balanceMinor",
    balances.remaining::text AS "remainingDifferenceMinor",
    CASE WHEN eligibility.status = 'eligible' AND existing.receipt IS NULL
      THEN (balances.current - $4::integer)::text END AS "projectedBalanceMinor",
    CASE WHEN eligibility.status = 'eligible' AND existing.receipt IS NULL
      THEN (balances.remaining - $4::integer)::text END AS "projectedRemainingDifferenceMinor",
    cuts.ids AS "ambiguousCheckIds",
    candidates.items AS candidates,
    existing.receipt AS "existingRecovery"
  FROM mvp_accounts m
  JOIN mvp_balance_checks c ON c.user_id = m.user_id AND c.account_id = m.account_id AND c.id = $3
  CROSS JOIN LATERAL (
    SELECT mvp_civil_day_start($5::date, m.reference_zone) AS start,
      mvp_civil_day_start($5::date + 1, m.reference_zone) AS next
  ) day
  CROSS JOIN LATERAL (
    SELECT COALESCE($6::timestamptz, day.start) AS first,
      COALESCE($6::timestamptz, LEAST(day.next - interval '1 microsecond', statement_timestamp())) AS last
  ) occurrence
  CROSS JOIN LATERAL (
    SELECT ARRAY(SELECT other.id FROM mvp_balance_checks other
      WHERE other.user_id = m.user_id AND other.account_id = m.account_id
        AND other.reference_at >= occurrence.first AND other.reference_at < occurrence.last
      ORDER BY other.reference_at, other.id) AS ids
  ) cuts
  CROSS JOIN LATERAL (
    SELECT CASE
      WHEN day.start >= day.next OR occurrence.first > occurrence.last
        OR occurrence.last < m.coverage_start OR occurrence.last > statement_timestamp()
        OR ($6::timestamptz IS NOT NULL AND ($6 AT TIME ZONE m.reference_zone)::date <> $5::date)
        THEN 'outside_coverage'
      WHEN occurrence.first < m.coverage_start OR cardinality(cuts.ids) > 0 THEN 'time_required'
      WHEN occurrence.last > c.reference_at THEN 'after_check'
      ELSE 'eligible'
    END AS status
  ) eligibility
  CROSS JOIN LATERAL (
    SELECT mvp_balance_at(m.user_id, m.account_id, m.base_minor, m.coverage_start, statement_timestamp()) AS current,
      mvp_balance_at(m.user_id, m.account_id, m.base_minor, m.coverage_start, c.reference_at) - c.observed_minor AS remaining
  ) balances
  CROSS JOIN LATERAL (
    SELECT COALESCE(jsonb_agg(to_jsonb(match) - 'description_match' - 'sort_at'
      ORDER BY description_match DESC, sort_at DESC, id DESC), '[]'::jsonb) AS items
    FROM (
      SELECT t.id, t.amount_minor::text AS "amountMinor", t.description,
        CASE WHEN t.occurrence_day IS NULL
          THEN to_char(t.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END AS "occurredAt",
        t.occurrence_day::text AS "occurrenceDay", t.occurrence_zone AS "occurrenceZone",
        t.occurred_at AS sort_at,
        COALESCE(lower(regexp_replace(t.description, '\\s+', ' ', 'g')) =
          lower(regexp_replace($7::text, '\\s+', ' ', 'g')), false) AS description_match,
        EXISTS (SELECT 1 FROM mvp_expense_recoveries r
          WHERE r.check_id = c.id AND r.transaction_id = t.id) AS "alreadyLinked"
      FROM mvp_effective_movements t
      WHERE t.user_id = m.user_id AND t.account_id = m.account_id AND t.type = 'expense'
        AND NOT t.invalidated AND t.amount_minor = $4 AND t.occurred_at < day.next
        AND COALESCE(t.latest_occurrence_at, t.occurred_at) >= day.start
        AND t.occurred_at >= m.coverage_start AND COALESCE(t.latest_occurrence_at, t.occurred_at) <= c.reference_at
      ORDER BY description_match DESC, sort_at DESC, t.id DESC
      LIMIT 50
    ) match
  ) candidates
  LEFT JOIN LATERAL (
    SELECT k.response AS receipt FROM mvp_expense_recoveries r
    JOIN idempotency_keys k ON k.user_id = r.user_id AND k.idempotency_key = r.mvp_write_key
    WHERE r.user_id = m.user_id AND r.account_id = m.account_id
      AND r.external_source = $8 AND r.external_reference = $9
  ) existing ON true
  WHERE m.user_id = $1 AND m.account_id = $2 AND NOT m.base_suspended
    AND c.reference_at >= m.coverage_start
    AND NOT EXISTS (SELECT 1 FROM mvp_check_replacements x WHERE x.original_id = c.id)
`;

@Injectable()
export class MvpRecoveryService {
  constructor(private readonly db: DatabaseService) {}

  async preview(
    userId: string,
    dto: MvpRecoveryInput,
  ): Promise<RecoveryPreview> {
    return this.readPreview(this.db, userId, this.normalize(dto));
  }

  async confirm(
    userId: string,
    key: string,
    dto: MvpRecoveryConfirmation,
  ): Promise<RecoveryReceipt> {
    if (!isUUID(key))
      throw new BadRequestException('Idempotency-Key must be a UUID');
    if (BigInt(dto.expectedRevision) >= 1n << 63n) {
      throw new BadRequestException('Revision is outside the supported range');
    }
    const input = this.normalize(dto);
    const action = dto.action;
    const target = dto.transactionId?.toLowerCase() ?? null;
    if ((action === 'link') !== Boolean(target)) {
      throw new BadRequestException(
        'Link requires a movement; create requires a distinct expense',
      );
    }
    const evidence = dto.evidence.trim();
    if (!evidence || evidence.includes('\u0000')) {
      throw new BadRequestException(
        'Describe the evidence supporting the recovery',
      );
    }
    key = key.toLowerCase();
    const hash = createHash('sha256')
      .update(
        JSON.stringify([
          'mvp.recovery.confirm',
          1,
          userId,
          input,
          action,
          target,
          evidence,
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
        response: RecoveryReceipt;
      }>(
        'SELECT request_hash, response FROM idempotency_keys WHERE user_id = $1 AND idempotency_key = $2 FOR UPDATE',
        [userId, key],
      );
      if (receipt) {
        if (receipt.request_hash !== hash)
          this.conflict(
            'IDEMPOTENCY_CONFLICT',
            'Idempotency key already used for another request',
          );
        await client.query('COMMIT');
        return receipt.response;
      }

      const {
        rows: [active],
      } = await client.query<{ revision: string }>(
        'SELECT revision::text FROM mvp_accounts WHERE user_id = $1 AND account_id = $2 FOR NO KEY UPDATE',
        [userId, input.accountId],
      );
      if (!active)
        throw new NotFoundException(
          'Recovery account or balance check not found',
        );
      const preview = await this.readPreview(client, userId, input);
      const existing = preview.existingRecovery;
      if (existing) {
        await this.requireCompatibleReference(client, existing, input, target);
        await this.saveReceipt(client, userId, key, hash, existing);
        await client.query('COMMIT');
        return existing;
      }
      if (preview.revision !== dto.expectedRevision) {
        this.conflict(
          'STALE_REVISION',
          'Account changed; review the recovery again',
        );
      }

      const id = randomUUID();
      if (target) {
        const { rowCount } = await client.query(
          'SELECT 1 FROM transactions WHERE user_id = $1 AND account_id = $2 AND id = $3',
          [userId, input.accountId, target],
        );
        if (!rowCount) throw new NotFoundException('Movement not found');
      } else {
        if (preview.dateStatus === 'time_required') {
          this.conflict(
            'OCCURRENCE_TIME_REQUIRED',
            'Provide the occurrence time or defer the recovery',
          );
        }
        if (preview.dateStatus !== 'eligible') {
          throw new BadRequestException(
            'Expense is outside the recovery coverage or cut',
          );
        }
        await client.query(
          `INSERT INTO transactions
            (id, user_id, account_id, type, amount_minor, currency, description, occurred_at,
             occurrence_day, occurrence_zone, latest_occurrence_at, mvp_revision, mvp_write_key, mvp_recovery_id)
           VALUES ($1, $2, $3, 'expense', $4, 'BRL', $5,
             COALESCE($6::timestamptz, mvp_civil_day_start($7::date, $8)),
             CASE WHEN $6 IS NULL THEN $7::date END,
             CASE WHEN $6 IS NULL THEN $8 END,
             CASE WHEN $6 IS NULL THEN LEAST(statement_timestamp(),
               mvp_civil_day_start($7::date + 1, $8) - interval '1 microsecond') END,
             $9::bigint + 1, $10, $1)`,
          [
            id,
            userId,
            input.accountId,
            input.amountMinor,
            input.description,
            input.occurredAt,
            input.day,
            preview.referenceZone,
            active.revision,
            key,
          ],
        );
      }

      const {
        rows: [created],
      } = await client.query<RecoveryReceipt>(
        `INSERT INTO mvp_expense_recoveries
          (id, user_id, account_id, check_id, transaction_id, action, declaration, evidence,
           external_source, external_reference, mvp_revision, mvp_write_key)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11::bigint + 1, $12)
         RETURNING ${receiptFields}`,
        [
          id,
          userId,
          input.accountId,
          input.checkId,
          target ?? id,
          action,
          JSON.stringify(input),
          evidence,
          input.externalSource,
          input.externalReference,
          active.revision,
          key,
        ],
      );
      await this.saveReceipt(client, userId, key, hash, created);
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
          'Recovery confirmation is temporarily unavailable; retry the same request',
        );
      }
      if (constraint === 'mvp_expense_recoveries_check_id_transaction_id_key') {
        this.conflict(
          'MOVEMENT_ALREADY_LINKED',
          'This movement is already linked to this balance check',
        );
      }
      if (constraint === 'mvp_recovery_movement_ineligible') {
        this.conflict(
          'MOVEMENT_INELIGIBLE',
          'This movement does not contribute at the balance check cut',
        );
      }
      if (constraint === 'mvp_cut_requires_time') {
        this.conflict(
          'OCCURRENCE_TIME_REQUIRED',
          'Provide the occurrence time or defer the recovery',
        );
      }
      throw error;
    } finally {
      client.release();
    }
  }

  private async readPreview(
    db: Pick<DatabaseService, 'query'>,
    userId: string,
    input: ReturnType<MvpRecoveryService['normalize']>,
  ): Promise<RecoveryPreview> {
    const {
      rows: [preview],
    } = await db.query<RecoveryPreview>(previewSql, [
      userId,
      input.accountId,
      input.checkId,
      input.amountMinor,
      input.day,
      input.occurredAt,
      input.description,
      input.externalSource,
      input.externalReference,
    ]);
    if (!preview)
      throw new NotFoundException(
        'Recovery account or balance check not found',
      );
    return preview;
  }

  private async requireCompatibleReference(
    client: PoolClient,
    existing: RecoveryReceipt,
    input: ReturnType<MvpRecoveryService['normalize']>,
    target: string | null,
  ) {
    const {
      rows: [row],
    } = await client.query<{ compatible: boolean }>(
      `SELECT declaration->>'amountMinor' = $2 AND declaration->>'day' = $3
         AND declaration->>'occurredAt' IS NOT DISTINCT FROM $4 AS compatible
       FROM mvp_expense_recoveries WHERE id = $1`,
      [existing.id, input.amountMinor, input.day, input.occurredAt],
    );
    if (
      existing.checkId !== input.checkId ||
      (target
        ? existing.transactionId !== target
        : existing.action !== 'create' || !row.compatible)
    ) {
      this.conflict(
        'EXTERNAL_REFERENCE_CONFLICT',
        'This external reference already identifies another recovery',
      );
    }
  }

  private async saveReceipt(
    client: PoolClient,
    owner: string,
    key: string,
    hash: string,
    receipt: RecoveryReceipt,
  ) {
    await client.query(
      'INSERT INTO idempotency_keys (id, user_id, idempotency_key, request_hash, response) VALUES ($1, $2, $3, $4, $5::jsonb)',
      [randomUUID(), owner, key, hash, JSON.stringify(receipt)],
    );
  }

  private normalize(input: MvpRecoveryInput) {
    const externalReference = input.externalReference?.trim() || null;
    const hasControlCharacter = [...(externalReference ?? '')].some(
      (character) =>
        character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
    );
    if (
      Boolean(input.externalSource) !== Boolean(externalReference) ||
      hasControlCharacter ||
      input.description?.includes('\u0000')
    ) {
      throw new BadRequestException(
        'Provide a valid source and genuine external reference together',
      );
    }
    const [seconds, fraction = ''] =
      input.occurredAt?.slice(0, -1).split('.') ?? [];
    return {
      accountId: input.accountId.toLowerCase(),
      checkId: input.checkId.toLowerCase(),
      amountMinor: input.amountMinor,
      day: input.day,
      occurredAt: seconds ? `${seconds}.${fraction.padEnd(6, '0')}Z` : null,
      description: input.description?.trim() || null,
      externalSource: input.externalSource ?? null,
      externalReference,
    };
  }

  private conflict(code: string, message: string): never {
    throw new ConflictException({ statusCode: 409, code, message });
  }
}
