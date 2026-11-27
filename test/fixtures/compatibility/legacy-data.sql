INSERT INTO users (id, email, password_hash, created_at)
VALUES (
  '10000000-0000-4000-8000-000000000001',
  'compatibility@example.test',
  'synthetic-only',
  '2026-11-20T12:00:00Z'
);

INSERT INTO accounts (id, user_id, name, currency, created_at)
VALUES (
  '20000000-0000-4000-8000-000000000001',
  '10000000-0000-4000-8000-000000000001',
  'Compatibility fixture',
  'BRL',
  '2026-11-20T12:00:00Z'
);

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
  'expense',
  1250,
  'BRL',
  'Synthetic compatibility movement',
  '2026-11-20T12:00:00Z',
  '2026-11-20T12:00:00Z'
);
