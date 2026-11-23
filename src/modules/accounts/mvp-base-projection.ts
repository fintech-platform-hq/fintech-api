export const auditTimestamp = (column: string) =>
  `to_char(${column} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;

export const baseVersionFields = `
  id, account_id AS "accountId", user_id AS "authorId", revision::text, action, reason,
  base_minor::text AS "baseMinor", ${auditTimestamp('coverage_start')} AS "coverageStart",
  reference_zone AS "referenceZone", ${auditTimestamp('created_at')} AS "createdAt"
`;

export const basePreviewSql = `
  WITH terms AS (
    SELECT a.*, COALESCE($3::bigint, a.base_minor) AS next_base,
      COALESCE($4::timestamptz, a.coverage_start) AS next_start
    FROM mvp_accounts a WHERE a.user_id = $1 AND a.account_id = $2
  ), impact AS (
    SELECT a.*,
      CASE WHEN NOT a.base_suspended THEN
        mvp_balance_at(a.user_id, a.account_id, a.base_minor, a.coverage_start, statement_timestamp())
      END AS current_balance,
      CASE WHEN NOT $5::boolean THEN
        mvp_balance_at(a.user_id, a.account_id, a.next_base, a.next_start, statement_timestamp())
      END AS projected_balance
    FROM terms a
  )
  SELECT a.revision::text, ($5 AND a.base_suspended) AS blocked,
    a.next_start <= statement_timestamp() AS covered,
    ($5 OR a.base_suspended OR (a.base_minor, a.coverage_start) <> (a.next_base, a.next_start)) AS changed,
    a.current_balance::text AS "balanceMinor", a.projected_balance::text AS "projectedBalanceMinor",
    a.base_minor::text AS "previousBaseMinor", ${auditTimestamp('a.coverage_start')} AS "previousCoverageStart",
    a.next_base::text AS "proposedBaseMinor", ${auditTimestamp('a.next_start')} AS "proposedCoverageStart",
    CASE WHEN $5 THEN ARRAY[]::uuid[]
      ELSE mvp_coverage_ambiguities(a.user_id, a.account_id, a.next_start) END AS "ambiguousMovementIds",
    COALESCE((
      SELECT jsonb_agg(jsonb_build_object('id', t.id, 'description', t.description,
        'occurrenceDay', t.occurrence_day::text,
        'occurredAt', CASE WHEN t.occurrence_day IS NULL THEN ${auditTimestamp('t.occurred_at')} END,
        'before', coverage.before, 'after', coverage.after) ORDER BY t.occurred_at, t.id)
      FROM mvp_effective_movements t
      CROSS JOIN LATERAL (
        SELECT CASE WHEN t.occurred_at >= a.coverage_start THEN 'covered' ELSE 'before_base' END AS before,
          CASE WHEN t.occurred_at >= a.next_start THEN 'covered'
            WHEN t.latest_occurrence_at >= a.next_start THEN 'ambiguous' ELSE 'before_base' END AS after
      ) coverage
      WHERE t.user_id = a.user_id AND t.account_id = a.account_id AND NOT t.invalidated
        AND coverage.before <> coverage.after
    ), '[]'::jsonb) AS "coverageChanges",
    COALESCE((
      SELECT jsonb_agg(jsonb_build_object('id', c.id, 'referenceAt', ${auditTimestamp('c.reference_at')},
        'originalDifferenceMinor', c.original_difference_minor::text, 'beforeMinor', d.before::text,
        'afterMinor', d.after::text) ORDER BY c.reference_at DESC, c.id)
      FROM mvp_balance_checks c
      CROSS JOIN LATERAL (
        SELECT CASE WHEN NOT a.base_suspended THEN
          mvp_balance_at(a.user_id, a.account_id, a.base_minor, a.coverage_start, c.reference_at) - c.observed_minor END AS before,
          CASE WHEN NOT $5 THEN
          mvp_balance_at(a.user_id, a.account_id, a.next_base, a.next_start, c.reference_at) - c.observed_minor END AS after
      ) d
      WHERE (c.user_id, c.account_id) = (a.user_id, a.account_id)
        AND (d.before IS DISTINCT FROM d.after OR ($4 IS NOT NULL AND d.after IS NULL))
    ), '[]'::jsonb) AS checks
  FROM impact a
`;
