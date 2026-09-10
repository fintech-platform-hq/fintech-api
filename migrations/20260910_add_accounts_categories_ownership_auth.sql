BEGIN;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM transactions LIMIT 1)
    OR EXISTS (SELECT 1 FROM idempotency_keys LIMIT 1) THEN
    RAISE EXCEPTION
      'ownership migration requires an empty database; existing production data must be handled only after explicit approval';
  END IF;
END
$$;

CREATE TABLE users (
  id uuid PRIMARY KEY,
  email varchar(254) NOT NULL UNIQUE,
  password_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (email = lower(btrim(email)))
);

CREATE TABLE accounts (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users (id),
  name text NOT NULL CHECK (length(btrim(name)) > 0),
  currency char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, id),
  UNIQUE (user_id, id, currency)
);

CREATE TABLE categories (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users (id),
  name text NOT NULL CHECK (length(btrim(name)) > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, id)
);

ALTER TABLE transactions
  ADD COLUMN user_id uuid NOT NULL REFERENCES users (id),
  ADD CONSTRAINT transactions_account_ownership_currency_fk
    FOREIGN KEY (user_id, account_id, currency)
    REFERENCES accounts (user_id, id, currency),
  ADD CONSTRAINT transactions_category_ownership_fk
    FOREIGN KEY (user_id, category_id)
    REFERENCES categories (user_id, id);

DROP INDEX IF EXISTS idx_transactions_account_id;
DROP INDEX IF EXISTS idx_transactions_occurred_at;

CREATE INDEX idx_transactions_user_account
ON transactions (user_id, account_id);

CREATE INDEX idx_transactions_user_category
ON transactions (user_id, category_id)
WHERE category_id IS NOT NULL;

CREATE INDEX idx_transactions_user_occurred_at
ON transactions (user_id, occurred_at DESC);

ALTER TABLE idempotency_keys
  DROP CONSTRAINT IF EXISTS idempotency_keys_idempotency_key_key,
  DROP CONSTRAINT IF EXISTS idempotency_keys_idempotency_key_request_hash_key,
  ADD COLUMN user_id uuid NOT NULL REFERENCES users (id),
  ADD CONSTRAINT idempotency_keys_user_key_unique
    UNIQUE (user_id, idempotency_key);

DROP INDEX IF EXISTS idx_idempotency_keys_key;

CREATE TABLE refresh_sessions (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users (id),
  family_id uuid NOT NULL,
  token_hash char(64) NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_refresh_sessions_family
ON refresh_sessions (family_id);

COMMIT;
