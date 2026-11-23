DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'transaction_type') THEN
    CREATE TYPE transaction_type AS ENUM ('expense', 'income');
  END IF;
END
$$;

CREATE TABLE users (
  id uuid PRIMARY KEY,
  email varchar(254) UNIQUE,
  password_hash text,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (email IS NULL OR email = lower(btrim(email))),
  CHECK (password_hash IS NULL OR email IS NOT NULL)
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

CREATE TABLE transactions (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users (id),
  account_id uuid NOT NULL,
  category_id uuid NULL,
  type transaction_type NOT NULL,
  amount_minor integer NOT NULL CHECK (amount_minor > 0),
  currency char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  description text NULL,
  occurred_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (user_id, account_id, currency)
    REFERENCES accounts (user_id, id, currency),
  FOREIGN KEY (user_id, category_id)
    REFERENCES categories (user_id, id)
);

CREATE INDEX idx_transactions_user_account
ON transactions (user_id, account_id);

CREATE INDEX idx_transactions_user_category
ON transactions (user_id, category_id)
WHERE category_id IS NOT NULL;

CREATE INDEX idx_transactions_user_occurred_at
ON transactions (user_id, occurred_at DESC);

CREATE TABLE idempotency_keys (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users (id),
  idempotency_key uuid NOT NULL,
  request_hash text NOT NULL,
  response jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, idempotency_key)
);

CREATE TABLE auth_identities (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users (id),
  provider text NOT NULL CHECK (provider = 'apple'),
  provider_subject text NOT NULL CHECK (length(btrim(provider_subject)) > 0),
  provider_email varchar(254) NULL,
  is_private_email boolean NOT NULL DEFAULT false,
  provider_refresh_token_ciphertext text NULL,
  last_provider_validation_at timestamptz NULL,
  revoked_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (
    provider_email IS NULL
    OR provider_email = lower(btrim(provider_email))
  ),
  UNIQUE (provider, provider_subject),
  UNIQUE (user_id, provider),
  UNIQUE (id, user_id)
);

CREATE FUNCTION assert_user_has_auth_method(p_user_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  has_auth_method boolean;
BEGIN
  PERFORM 1 FROM users WHERE id = p_user_id FOR UPDATE;

  SELECT u.password_hash IS NOT NULL
    OR EXISTS (
      SELECT 1 FROM auth_identities ai
      WHERE ai.user_id = u.id
    )
  INTO has_auth_method
  FROM users u
  WHERE u.id = p_user_id;

  IF NOT COALESCE(has_auth_method, false) THEN
    RAISE EXCEPTION 'user must have a password or external identity'
      USING ERRCODE = '23514', CONSTRAINT = 'users_auth_method_check';
  END IF;
END;
$$;

CREATE FUNCTION enforce_user_auth_method()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM assert_user_has_auth_method(NEW.id);
  RETURN NULL;
END;
$$;

CREATE FUNCTION enforce_identity_user_auth_method()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM assert_user_has_auth_method(
    CASE WHEN TG_OP = 'DELETE' THEN OLD.user_id ELSE NEW.user_id END
  );
  RETURN NULL;
END;
$$;

CREATE FUNCTION prevent_auth_identity_reparenting()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.user_id IS DISTINCT FROM OLD.user_id THEN
    RAISE EXCEPTION 'auth identity user_id is immutable'
      USING ERRCODE = '23514', CONSTRAINT = 'auth_identities_user_id_immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER users_must_have_auth_method
AFTER INSERT OR UPDATE OF email, password_hash ON users
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION enforce_user_auth_method();

CREATE CONSTRAINT TRIGGER auth_identities_must_have_user_auth_method
AFTER INSERT OR DELETE ON auth_identities
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION enforce_identity_user_auth_method();

CREATE TRIGGER auth_identities_user_id_immutable
BEFORE UPDATE OF user_id ON auth_identities
FOR EACH ROW EXECUTE FUNCTION prevent_auth_identity_reparenting();

CREATE TABLE refresh_sessions (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users (id),
  auth_identity_id uuid NULL,
  family_id uuid NOT NULL,
  token_hash char(64) NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (auth_identity_id, user_id)
    REFERENCES auth_identities (id, user_id)
);

CREATE INDEX idx_refresh_sessions_family
ON refresh_sessions (family_id);

CREATE INDEX idx_refresh_sessions_auth_identity
ON refresh_sessions (auth_identity_id, user_id)
WHERE auth_identity_id IS NOT NULL;


CREATE TABLE mvp_accounts (
  user_id uuid PRIMARY KEY,
  account_id uuid NOT NULL UNIQUE,
  currency char(3) NOT NULL DEFAULT 'BRL' CHECK (currency = 'BRL'),
  base_minor bigint NOT NULL,
  coverage_start timestamptz NOT NULL CHECK (isfinite(coverage_start)),
  reference_zone text NOT NULL CHECK (length(reference_zone) > 0),
  confirmed_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
  CHECK (coverage_start <= confirmed_at),
  FOREIGN KEY (user_id, account_id, currency)
    REFERENCES accounts (user_id, id, currency)
);

CREATE INDEX idx_transactions_account_coverage
ON transactions (user_id, account_id, occurred_at);

ALTER TABLE transactions
  ADD COLUMN mvp_write_key uuid,
  ADD COLUMN mvp_revision bigint,
  ADD CONSTRAINT mvp_transaction_receipt_fk
    FOREIGN KEY (user_id, mvp_write_key)
    REFERENCES idempotency_keys (user_id, idempotency_key)
    DEFERRABLE INITIALLY DEFERRED,
  ADD CONSTRAINT mvp_transaction_revision_pair
    CHECK ((mvp_write_key IS NULL AND mvp_revision IS NULL)
      OR (mvp_write_key IS NOT NULL AND mvp_revision IS NOT NULL AND mvp_revision > 1));

CREATE UNIQUE INDEX idx_transactions_mvp_write_key
ON transactions (user_id, mvp_write_key) WHERE mvp_write_key IS NOT NULL;

CREATE INDEX idx_transactions_history
ON transactions (user_id, account_id, occurred_at DESC, id DESC);

CREATE FUNCTION block_mvp_transaction_writes()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  active mvp_accounts%ROWTYPE;
BEGIN
  IF TG_OP <> 'INSERT' THEN
    IF EXISTS (SELECT 1 FROM mvp_accounts WHERE account_id = OLD.account_id) THEN
      RAISE EXCEPTION 'MVP transactions are immutable'
        USING ERRCODE = '23514', CONSTRAINT = 'mvp_transaction_writes_disabled';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  END IF;

  SELECT * INTO active FROM mvp_accounts WHERE account_id = NEW.account_id FOR NO KEY UPDATE;
  IF NOT FOUND THEN
    IF NEW.mvp_write_key IS NOT NULL OR NEW.mvp_revision IS NOT NULL THEN
      RAISE EXCEPTION 'MVP requires a confirmed base'
        USING ERRCODE = '23514', CONSTRAINT = 'mvp_transaction_base_required';
    END IF;
    RETURN NEW;
  END IF;

  IF TG_OP <> 'INSERT' OR NEW.mvp_write_key IS NULL OR NEW.mvp_revision IS NULL THEN
    RAISE EXCEPTION 'MVP transactions require the revisioned writer'
      USING ERRCODE = '23514', CONSTRAINT = 'mvp_transaction_writes_disabled';
  END IF;
  IF NEW.user_id <> active.user_id OR NEW.currency <> active.currency
     OR NEW.amount_minor NOT BETWEEN 1 AND 999999999
     OR NEW.occurred_at < active.coverage_start OR NEW.occurred_at > statement_timestamp() THEN
    RAISE EXCEPTION 'Movement is outside MVP coverage'
      USING ERRCODE = '23514', CONSTRAINT = 'mvp_transaction_coverage';
  END IF;
  IF NEW.mvp_revision - 1 <> active.revision THEN
    RAISE EXCEPTION 'Account revision changed'
      USING ERRCODE = '23514', CONSTRAINT = 'mvp_transaction_stale_revision';
  END IF;

  UPDATE mvp_accounts SET revision = NEW.mvp_revision WHERE user_id = active.user_id;
  NEW.created_at := statement_timestamp();
  RETURN NEW;
END;
$$;

CREATE TRIGGER mvp_transaction_writes_disabled
BEFORE INSERT OR UPDATE OR DELETE ON transactions
FOR EACH ROW EXECUTE FUNCTION block_mvp_transaction_writes();

CREATE FUNCTION check_mvp_transaction_receipt()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM idempotency_keys
    WHERE user_id = NEW.user_id AND idempotency_key = NEW.mvp_write_key
      AND response->>'id' = NEW.id::text
      AND response->>'accountId' = NEW.account_id::text
      AND response->>'revision' = NEW.mvp_revision::text
  ) THEN
    RAISE EXCEPTION 'MVP transaction requires its own receipt'
      USING ERRCODE = '23514', CONSTRAINT = 'mvp_transaction_receipt_required';
  END IF;
  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER mvp_transaction_receipt_required
AFTER INSERT ON transactions DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW WHEN (NEW.mvp_write_key IS NOT NULL)
EXECUTE FUNCTION check_mvp_transaction_receipt();
