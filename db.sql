DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'transaction_type') THEN
    CREATE TYPE transaction_type AS ENUM ('expense', 'income');
  END IF;
END
$$;

CREATE TABLE transactions (
  id uuid PRIMARY KEY,
  account_id uuid NOT NULL,
  category_id uuid NULL,
  type transaction_type NOT NULL,
  amount_minor integer NOT NULL CHECK (amount_minor > 0),
  currency char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  description text NULL,
  occurred_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_transactions_account_id 
ON transactions (account_id);

CREATE INDEX idx_transactions_occurred_at 
ON transactions (occurred_at);

CREATE TABLE idempotency_keys (
  id uuid PRIMARY KEY,
  idempotency_key uuid NOT NULL,
  request_hash text NOT NULL,
  response jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (idempotency_key),
  UNIQUE (idempotency_key, request_hash)
);

CREATE INDEX idx_idempotency_keys_key 
ON idempotency_keys (idempotency_key);
