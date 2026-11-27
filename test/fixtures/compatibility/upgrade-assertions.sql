DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM transactions
    WHERE id = '30000000-0000-4000-8000-000000000001'
      AND account_id = '20000000-0000-4000-8000-000000000001'
      AND type = 'expense' AND amount_minor = 1250
  ) THEN
    RAISE EXCEPTION 'upgrade changed or lost the legacy movement';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM idempotency_keys
    WHERE id = '40000000-0000-4000-8000-000000000001'
      AND response->>'type' = 'expense'
      AND response->>'amountMinor' = '1250'
  ) THEN
    RAISE EXCEPTION 'upgrade changed or lost the canonical receipt';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM mvp_base_versions
    WHERE account_id = '20000000-0000-4000-8000-000000000001'
      AND revision = 1 AND action = 'original' AND base_minor = 8500
      AND coverage_start = '2026-11-20T00:00:00Z'::timestamptz
  ) THEN
    RAISE EXCEPTION 'upgrade did not preserve the confirmed opening base';
  END IF;

  IF (SELECT version FROM lenver_schema_version WHERE singleton = true) IS DISTINCT FROM '20261127_v1_method_receipts' THEN
    RAISE EXCEPTION 'upgrade schema marker does not match';
  END IF;
END
$$;
