BEGIN;

ALTER TYPE transaction_type RENAME VALUE 'debit' TO 'expense';
ALTER TYPE transaction_type RENAME VALUE 'credit' TO 'income';

UPDATE idempotency_keys
SET response = jsonb_set(
  response,
  '{type}',
  CASE response->>'type'
    WHEN 'debit' THEN '"expense"'::jsonb
    WHEN 'credit' THEN '"income"'::jsonb
    ELSE response->'type'
  END
)
WHERE response->>'type' IN ('debit', 'credit');

COMMIT;
