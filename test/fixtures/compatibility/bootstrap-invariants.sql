INSERT INTO users (id, email, password_hash, created_at)
VALUES
  ('10000000-0000-4000-8000-000000000001', 'one@example.test', 'synthetic-only', '2026-11-20T12:00:00Z'),
  ('10000000-0000-4000-8000-000000000002', 'two@example.test', 'synthetic-only', '2026-11-20T12:00:00Z');

INSERT INTO accounts (id, user_id, name, currency, created_at)
VALUES
  ('20000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001', 'Main', 'BRL', '2026-11-20T12:00:00Z'),
  ('20000000-0000-4000-8000-000000000002', '10000000-0000-4000-8000-000000000001', 'Second', 'BRL', '2026-11-20T12:00:00Z'),
  ('20000000-0000-4000-8000-000000000003', '10000000-0000-4000-8000-000000000002', 'Foreign', 'BRL', '2026-11-20T12:00:00Z');

INSERT INTO idempotency_keys (id, user_id, idempotency_key, request_hash, response, created_at)
VALUES (
  '40000000-0000-4000-8000-000000000001',
  '10000000-0000-4000-8000-000000000001',
  '40000000-0000-4000-8000-000000000002',
  repeat('a', 64),
  '{"type":"expense","amountMinor":1250}'::jsonb,
  '2026-11-20T12:00:00Z'
);

INSERT INTO transactions (id, user_id, account_id, type, amount_minor, currency, description, occurred_at, created_at)
VALUES (
  '30000000-0000-4000-8000-000000000001',
  '10000000-0000-4000-8000-000000000001',
  '20000000-0000-4000-8000-000000000001',
  'expense', 1250, 'BRL', 'Synthetic compatibility movement',
  '2026-11-20T12:00:00Z', '2026-11-20T12:00:00Z'
);

INSERT INTO mvp_accounts (user_id, account_id, currency, base_minor, coverage_start, reference_zone, confirmed_at)
VALUES (
  '10000000-0000-4000-8000-000000000001',
  '20000000-0000-4000-8000-000000000001',
  'BRL', 10000, '2026-11-20T00:00:00Z', 'America/Sao_Paulo', '2026-11-21T00:00:00Z'
);

DO $$
BEGIN
  IF (SELECT version FROM lenver_schema_version WHERE singleton = true) IS DISTINCT FROM '20261127_v1_method_receipts' THEN
    RAISE EXCEPTION 'bootstrap schema marker does not match';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM mvp_base_versions WHERE account_id = '20000000-0000-4000-8000-000000000001' AND revision = 1 AND base_minor = 10000) THEN
    RAISE EXCEPTION 'bootstrap did not record the opening base';
  END IF;

  BEGIN
    INSERT INTO mvp_accounts (user_id, account_id, currency, base_minor, coverage_start, reference_zone, confirmed_at)
    VALUES ('10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000002', 'BRL', 0, '2026-11-20T00:00:00Z', 'America/Sao_Paulo', '2026-11-21T00:00:00Z');
    RAISE EXCEPTION 'bootstrap allowed a second promoted account';
  EXCEPTION WHEN unique_violation THEN
    NULL;
  END;

  BEGIN
    INSERT INTO transactions (id, user_id, account_id, type, amount_minor, currency, occurred_at, created_at)
    VALUES ('30000000-0000-4000-8000-000000000002', '10000000-0000-4000-8000-000000000002', '20000000-0000-4000-8000-000000000002', 'expense', 1, 'BRL', '2026-11-20T12:00:00Z', '2026-11-20T12:00:00Z');
    RAISE EXCEPTION 'bootstrap allowed a cross-owner movement';
  EXCEPTION WHEN foreign_key_violation THEN
    NULL;
  END;

  BEGIN
    INSERT INTO transactions (id, user_id, account_id, type, amount_minor, currency, occurred_at, created_at)
    VALUES ('30000000-0000-4000-8000-000000000003', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001', 'expense', 1, 'BRL', '2026-11-20T12:00:00Z', '2026-11-20T12:00:00Z');
    RAISE EXCEPTION 'bootstrap allowed a legacy write to an active MVP account';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
END
$$;
