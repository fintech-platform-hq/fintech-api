import {
  BadRequestException,
  ConflictException,
  HttpException,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { createHash, randomUUID } from 'node:crypto';
import { isISO8601, isUUID } from 'class-validator';
import { DatabaseService } from '../../common/database/database.service';
import { AccountResponseDto } from './dto/account-response.dto';
import { MvpOpeningDto } from './mvp-opening.dto';
import type { MvpTransactionReceipt } from '../transactions/dto/mvp-transaction.dto';

export interface MvpAccountSummary {
  principalId: string;
  account: AccountResponseDto | null;
  legacyAccounts: AccountResponseDto[];
  status: 'no_account' | 'base_required' | 'unavailable' | 'available';
  base: {
    baseMinor: string;
    coverageStart: string;
    referenceZone: string;
    confirmedAt: string;
  } | null;
  balanceMinor: string | null;
  revision: string | null;
  asOf: string;
}

export const summarySql = (cut = 'statement_timestamp()') => `
  WITH params AS (
    SELECT $1::uuid AS principal, $2::uuid AS target, ${cut} AS cut
  )
  SELECT p.principal AS "principalId",
    to_char(p.cut AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "asOf",
    CASE WHEN a.id IS NOT NULL THEN
      jsonb_build_object('id', a.id, 'name', a.name, 'currency', a.currency,
        'createdAt', a.created_at)
    END AS account,
    CASE WHEN p.target IS NULL AND a.id IS NULL THEN COALESCE((
      SELECT jsonb_agg(jsonb_build_object('id', l.id, 'name', l.name,
        'currency', l.currency, 'createdAt', l.created_at) ORDER BY l.created_at, l.id)
      FROM accounts l WHERE l.user_id = p.principal AND l.currency = 'BRL'
    ), '[]'::jsonb) ELSE '[]'::jsonb END AS "legacyAccounts",
    CASE
      WHEN a.id IS NULL THEN 'no_account'
      WHEN m.account_id IS NULL THEN 'base_required'
      WHEN p.cut < m.coverage_start THEN 'unavailable'
      ELSE 'available'
    END AS status,
    CASE WHEN m.account_id IS NOT NULL THEN
      jsonb_build_object('baseMinor', m.base_minor::text,
        'coverageStart', to_char(m.coverage_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'referenceZone', m.reference_zone, 'confirmedAt', m.confirmed_at)
    END AS base,
    mvp_balance_at(p.principal, m.account_id, m.base_minor, m.coverage_start, p.cut)::text AS "balanceMinor",
    m.revision::text AS revision
  FROM params p
  LEFT JOIN mvp_accounts m ON m.user_id = p.principal
    AND (p.target IS NULL OR m.account_id = p.target)
  LEFT JOIN accounts a ON a.id = COALESCE(p.target, m.account_id)
    AND a.user_id = p.principal AND a.currency = 'BRL'
`;

type HistoryEntry = Omit<MvpTransactionReceipt, 'revision'> & {
  occurrenceDay: string | null;
  occurrenceZone: string | null;
  auditAction: 'correct' | 'invalidate' | null;
  coverage: 'covered' | 'before_base' | 'after_cut' | 'no_base';
};

interface HistoryCursor {
  accountId: string;
  asOf: string;
  version: string;
  occurredAt: string;
  id: string;
}

const historySql = `
  WITH summary AS (
    ${summarySql('COALESCE($3::timestamptz, statement_timestamp())')}
  )
  SELECT to_jsonb(s) AS summary,
    COALESCE(s.revision, (
      SELECT md5(COALESCE(string_agg(t.id::text || ':' || t.xmin::text, ',' ORDER BY t.id), ''))
      FROM transactions t WHERE t.user_id = $1 AND t.account_id = $2
    )) AS version,
    COALESCE(entries.items, '[]'::jsonb) AS entries
  FROM summary s
  LEFT JOIN LATERAL (
    SELECT jsonb_agg(to_jsonb(page) ORDER BY page."occurredAt" DESC, page.id DESC) AS items
    FROM (
      SELECT t.id, t.account_id AS "accountId", t.type, t.amount_minor::text AS "amountMinor",
        t.currency, t.description, t.audit_action AS "auditAction", t.occurrence_day::text AS "occurrenceDay",
        t.occurrence_zone AS "occurrenceZone",
        to_char(t.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "occurredAt",
        to_char(t.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "createdAt",
        CASE
          WHEN s.base IS NULL THEN 'no_base'
          WHEN t.occurred_at < (s.base->>'coverageStart')::timestamptz THEN 'before_base'
          WHEN COALESCE(t.latest_occurrence_at, t.occurred_at) > s."asOf"::timestamptz THEN 'after_cut'
          ELSE 'covered'
        END AS coverage
      FROM mvp_effective_movements t
      WHERE s.account IS NOT NULL AND t.user_id = $1 AND t.account_id = $2
        AND ($4::timestamptz IS NULL OR (t.occurred_at, t.id) < ($4, $5::uuid))
      ORDER BY t.occurred_at DESC, t.id DESC LIMIT 51
    ) page
  ) entries ON true
`;

@Injectable()
export class MvpAccountService {
  constructor(private readonly db: DatabaseService) {}

  async read(userId: string, accountId?: string): Promise<MvpAccountSummary> {
    const {
      rows: [summary],
    } = await this.db.query<MvpAccountSummary>(summarySql(), [
      userId,
      accountId ?? null,
    ]);
    if (accountId && !summary.account) {
      throw new NotFoundException('Account not found');
    }
    return summary;
  }

  async history(userId: string, accountId: string, token?: string) {
    accountId = accountId.toLowerCase();
    const cursor =
      token === undefined ? null : this.historyCursor(token, accountId);
    const {
      rows: [page],
    } = await this.db.query<{
      summary: MvpAccountSummary;
      version: string;
      entries: HistoryEntry[];
    }>(historySql, [
      userId,
      accountId,
      cursor?.asOf ?? null,
      cursor?.occurredAt ?? null,
      cursor?.id ?? null,
    ]);
    if (!page.summary.account) throw new NotFoundException('Account not found');
    if (cursor && cursor.version !== page.version) {
      this.conflict('STALE_REVISION', 'History changed; reload the account');
    }
    const entries = page.entries.slice(0, 50);
    const last = entries.at(-1);
    const nextCursor =
      last && page.entries.length > entries.length
        ? Buffer.from(
            JSON.stringify({
              accountId,
              version: page.version,
              asOf: page.summary.asOf,
              occurredAt: last.occurredAt,
              id: last.id,
            } satisfies HistoryCursor),
          ).toString('base64url')
        : null;
    return { summary: page.summary, entries, nextCursor };
  }

  private historyCursor(token: string, accountId: string): HistoryCursor {
    const validTimestamp = (value: string) =>
      typeof value === 'string' &&
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/.test(value) &&
      !value.startsWith('0000') &&
      isISO8601(value, { strict: true });
    try {
      if (!/^[A-Za-z0-9_-]{1,600}$/.test(token)) throw new Error();
      const cursor = JSON.parse(
        Buffer.from(token, 'base64url').toString(),
      ) as HistoryCursor;
      if (
        cursor.accountId === accountId &&
        isUUID(cursor.id) &&
        typeof cursor.version === 'string' &&
        /^(?:[1-9]\d{0,18}|[a-f0-9]{32})$/.test(cursor.version) &&
        validTimestamp(cursor.asOf) &&
        validTimestamp(cursor.occurredAt)
      ) {
        return cursor;
      }
    } catch {
      // A malformed cursor never reaches the database.
    }
    throw new BadRequestException('Invalid history cursor');
  }

  async preview(userId: string, dto: MvpOpeningDto): Promise<MvpOpeningDto> {
    const terms = this.normalize(dto);
    if (terms.accountId) {
      await this.read(userId, terms.accountId);
      this.conflict(
        'LEGACY_ADOPTION_BLOCKED',
        'Existing account adoption is disabled',
      );
    }
    const {
      rows: [state],
    } = await this.db.query<{ active: boolean; future: boolean }>(
      `SELECT EXISTS (SELECT 1 FROM mvp_accounts WHERE user_id = $1) AS active,
        $2::timestamptz > statement_timestamp() AS future`,
      [userId, terms.coverageStart],
    );
    if (state.future) {
      throw new BadRequestException('Coverage start must not be in the future');
    }
    if (state.active) {
      this.conflict(
        'MVP_ACCOUNT_EXISTS',
        'A personal account is already active',
      );
    }
    return terms;
  }

  async open(
    userId: string,
    key: string,
    dto: MvpOpeningDto,
  ): Promise<MvpAccountSummary> {
    if (!isUUID(key)) {
      throw new BadRequestException('Idempotency-Key must be a UUID');
    }
    const terms = this.normalize(dto);
    key = key.toLowerCase();
    const hash = createHash('sha256')
      .update(JSON.stringify(['mvp.account.open', 1, userId, terms]))
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
        response: MvpAccountSummary;
      }>(
        'SELECT request_hash, response FROM idempotency_keys WHERE user_id = $1 AND idempotency_key = $2 FOR UPDATE',
        [userId, key],
      );
      if (receipt) {
        if (receipt.request_hash !== hash) {
          this.conflict(
            'IDEMPOTENCY_CONFLICT',
            'Idempotency key already used for another request',
          );
        }
        await client.query('COMMIT');
        return receipt.response;
      }

      if (terms.accountId) {
        const { rowCount } = await client.query(
          "SELECT 1 FROM accounts WHERE user_id = $1 AND id = $2 AND currency = 'BRL'",
          [userId, terms.accountId],
        );
        if (!rowCount) {
          throw new NotFoundException('Account not found');
        }
        this.conflict(
          'LEGACY_ADOPTION_BLOCKED',
          'Existing account adoption is disabled',
        );
      }

      await client.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [
        userId,
      ]);
      const active = await client.query(
        'SELECT 1 FROM mvp_accounts WHERE user_id = $1',
        [userId],
      );
      if (active.rowCount) {
        this.conflict(
          'MVP_ACCOUNT_EXISTS',
          'A personal account is already active',
        );
      }

      const accountId = randomUUID();
      await client.query(
        "INSERT INTO accounts (id, user_id, name, currency) VALUES ($1, $2, 'Conta pessoal', 'BRL')",
        [accountId, userId],
      );
      const opened = await client.query(
        `INSERT INTO mvp_accounts (user_id, account_id, base_minor, coverage_start, reference_zone)
         SELECT $1, $2, $3, $4, $5 WHERE $4::timestamptz <= statement_timestamp()`,
        [
          userId,
          accountId,
          terms.baseMinor,
          terms.coverageStart,
          terms.referenceZone,
        ],
      );
      if (!opened.rowCount) {
        throw new BadRequestException(
          'Coverage start must not be in the future',
        );
      }

      const {
        rows: [summary],
      } = await client.query<MvpAccountSummary>(summarySql(), [userId, null]);
      await client.query(
        `INSERT INTO idempotency_keys (id, user_id, idempotency_key, request_hash, response)
         VALUES ($1, $2, $3, $4, $5::jsonb)`,
        [randomUUID(), userId, key, hash, JSON.stringify(summary)],
      );
      await client.query('COMMIT');
      return summary;
    } catch (error) {
      await client.query('ROLLBACK');
      if (error instanceof HttpException) throw error;
      if ((error as { code?: string }).code === '55P03') {
        throw new ServiceUnavailableException(
          'Opening is temporarily unavailable; retry the same request',
        );
      }
      throw error;
    } finally {
      client.release();
    }
  }

  private normalize(dto: MvpOpeningDto): MvpOpeningDto {
    const baseMinor = BigInt(dto.baseMinor);
    if (
      baseMinor.toString() !== dto.baseMinor ||
      baseMinor < -(1n << 63n) ||
      baseMinor >= 1n << 63n
    ) {
      throw new BadRequestException(
        'Opening balance is outside the supported range',
      );
    }
    try {
      new Intl.DateTimeFormat('en', { timeZone: dto.referenceZone });
    } catch {
      throw new BadRequestException('Invalid reference time zone');
    }
    const [seconds, fraction = ''] = dto.coverageStart.slice(0, -1).split('.');
    return {
      baseMinor: dto.baseMinor,
      coverageStart: `${seconds}.${fraction.padEnd(6, '0')}Z`,
      referenceZone: dto.referenceZone,
      ...(dto.accountId ? { accountId: dto.accountId.toLowerCase() } : {}),
    };
  }

  private conflict(code: string, message: string): never {
    throw new ConflictException({ statusCode: 409, code, message });
  }
}
