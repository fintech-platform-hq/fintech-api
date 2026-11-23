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
CREATE FUNCTION mvp_balance_at(
  owner_id uuid, target_id uuid, base bigint, coverage_start timestamptz, cut timestamptz
) RETURNS numeric LANGUAGE sql STABLE AS $$
  SELECT CASE WHEN cut >= coverage_start THEN base + COALESCE((
    SELECT sum(CASE t.type WHEN 'income' THEN t.amount_minor::bigint ELSE -t.amount_minor::bigint END)
    FROM transactions t
    WHERE t.user_id = owner_id AND t.account_id = target_id
      AND t.occurred_at BETWEEN coverage_start AND cut
  ), 0) END
$$;

ALTER TABLE mvp_accounts ADD UNIQUE (user_id, account_id);

CREATE TABLE mvp_balance_checks (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL,
  account_id uuid NOT NULL,
  observed_minor bigint NOT NULL,
  reference_at timestamptz NOT NULL CHECK (isfinite(reference_at)),
  created_at timestamptz NOT NULL,
  mvp_revision bigint NOT NULL CHECK (mvp_revision > 1),
  base_confirmed_at timestamptz NOT NULL,
  original_calculated_minor numeric NOT NULL,
  original_difference_minor numeric GENERATED ALWAYS AS (original_calculated_minor - observed_minor) STORED,
  mvp_write_key uuid NOT NULL,
  UNIQUE (account_id, mvp_revision),
  UNIQUE (user_id, mvp_write_key),
  FOREIGN KEY (user_id, account_id) REFERENCES mvp_accounts (user_id, account_id),
  FOREIGN KEY (user_id, mvp_write_key) REFERENCES idempotency_keys (user_id, idempotency_key)
    DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX idx_mvp_checks_order
ON mvp_balance_checks (account_id, reference_at DESC, created_at DESC, id DESC);

CREATE FUNCTION write_mvp_balance_check()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  active mvp_accounts%ROWTYPE;
BEGIN
  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION 'MVP balance checks are immutable'
      USING ERRCODE = '23514', CONSTRAINT = 'mvp_check_immutable';
  END IF;

  SELECT * INTO STRICT active FROM mvp_accounts
  WHERE user_id = NEW.user_id AND account_id = NEW.account_id FOR NO KEY UPDATE;
  IF NEW.reference_at < active.coverage_start OR NEW.reference_at > statement_timestamp() THEN
    RAISE EXCEPTION 'Check is outside MVP coverage'
      USING ERRCODE = '23514', CONSTRAINT = 'mvp_check_coverage';
  END IF;
  IF NEW.mvp_revision - 1 <> active.revision THEN
    RAISE EXCEPTION 'Account revision changed'
      USING ERRCODE = '23514', CONSTRAINT = 'mvp_check_stale_revision';
  END IF;

  NEW.created_at := statement_timestamp();
  NEW.base_confirmed_at := active.confirmed_at;
  NEW.original_calculated_minor := mvp_balance_at(
    active.user_id, active.account_id, active.base_minor, active.coverage_start, NEW.reference_at
  );
  UPDATE mvp_accounts SET revision = NEW.mvp_revision WHERE user_id = active.user_id;
  RETURN NEW;
END;
$$;

CREATE TRIGGER mvp_check_write
BEFORE INSERT OR UPDATE OR DELETE ON mvp_balance_checks
FOR EACH ROW EXECUTE FUNCTION write_mvp_balance_check();

CREATE FUNCTION check_mvp_balance_check_receipt()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM idempotency_keys
    WHERE user_id = NEW.user_id AND idempotency_key = NEW.mvp_write_key
      AND response->>'id' = NEW.id::text
      AND response->>'accountId' = NEW.account_id::text
      AND response->>'revision' = NEW.mvp_revision::text
  ) THEN
    RAISE EXCEPTION 'MVP balance check requires its own receipt'
      USING ERRCODE = '23514', CONSTRAINT = 'mvp_check_receipt_required';
  END IF;
  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER mvp_check_receipt_required
AFTER INSERT ON mvp_balance_checks DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION check_mvp_balance_check_receipt();

ALTER TABLE transactions
  ADD COLUMN occurrence_day date,
  ADD COLUMN occurrence_zone text,
  ADD COLUMN latest_occurrence_at timestamptz,
  ADD COLUMN mvp_recovery_id uuid,
  ADD CONSTRAINT mvp_occurrence_precision CHECK (
    (occurrence_day IS NULL AND occurrence_zone IS NULL AND latest_occurrence_at IS NULL)
    OR (occurrence_day IS NOT NULL AND occurrence_zone IS NOT NULL
      AND latest_occurrence_at IS NOT NULL AND isfinite(latest_occurrence_at)
      AND latest_occurrence_at >= occurred_at AND mvp_recovery_id IS NOT NULL)
  ),
  ADD CONSTRAINT mvp_recovery_movement CHECK (
    mvp_recovery_id IS NULL OR (mvp_recovery_id = id AND mvp_write_key IS NOT NULL AND type = 'expense')
  ),
  ADD UNIQUE (user_id, account_id, id);

CREATE TABLE mvp_expense_recoveries (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL,
  account_id uuid NOT NULL,
  check_id uuid NOT NULL REFERENCES mvp_balance_checks (id),
  transaction_id uuid NOT NULL,
  action text NOT NULL CHECK (action IN ('link', 'create')),
  declaration jsonb NOT NULL,
  evidence text NOT NULL CHECK (length(btrim(evidence)) BETWEEN 1 AND 1000),
  external_source text,
  external_reference text,
  created_at timestamptz NOT NULL,
  mvp_revision bigint NOT NULL CHECK (mvp_revision > 1),
  mvp_write_key uuid NOT NULL,
  CHECK ((external_source IS NULL) = (external_reference IS NULL)),
  UNIQUE (user_id, account_id, id),
  UNIQUE (account_id, mvp_revision),
  UNIQUE (check_id, transaction_id),
  UNIQUE (account_id, external_source, external_reference),
  FOREIGN KEY (user_id, account_id) REFERENCES mvp_accounts (user_id, account_id),
  FOREIGN KEY (user_id, account_id, transaction_id) REFERENCES transactions (user_id, account_id, id),
  FOREIGN KEY (user_id, mvp_write_key) REFERENCES idempotency_keys (user_id, idempotency_key)
    DEFERRABLE INITIALLY DEFERRED
);

ALTER TABLE transactions ADD CONSTRAINT mvp_expense_requires_recovery
  FOREIGN KEY (user_id, account_id, mvp_recovery_id)
  REFERENCES mvp_expense_recoveries (user_id, account_id, id) DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION mvp_civil_day_start(day date, zone text)
RETURNS timestamptz LANGUAGE sql STABLE AS $$
  WITH midnight AS (
    SELECT day::timestamp AT TIME ZONE zone AS instant
  ), alternative AS (
    SELECT day::timestamp AT TIME ZONE 'UTC' -
      ((instant - interval '36 hours') AT TIME ZONE zone -
        (instant - interval '36 hours') AT TIME ZONE 'UTC') AS instant
    FROM midnight
  )
  SELECT LEAST(midnight.instant, (
    SELECT instant FROM alternative WHERE instant AT TIME ZONE zone = day::timestamp
  )) FROM midnight
$$;

CREATE FUNCTION mvp_cut_needs_occurrence_time(owner_id uuid, target_id uuid, cut timestamptz)
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (
    SELECT 1 FROM transactions t
    WHERE t.user_id = owner_id AND t.account_id = target_id
      AND t.occurred_at <= cut AND t.latest_occurrence_at > cut
  )
$$;

CREATE OR REPLACE FUNCTION mvp_balance_at(
  owner_id uuid, target_id uuid, base bigint, coverage_start timestamptz, cut timestamptz
) RETURNS numeric LANGUAGE sql STABLE AS $$
  SELECT CASE WHEN cut >= coverage_start THEN base + COALESCE((
    SELECT sum(CASE t.type WHEN 'income' THEN t.amount_minor::bigint ELSE -t.amount_minor::bigint END)
    FROM transactions t
    WHERE t.user_id = owner_id AND t.account_id = target_id
      AND t.occurred_at BETWEEN coverage_start AND cut
      AND (t.latest_occurrence_at IS NULL OR t.latest_occurrence_at <= cut)
  ), 0) END
$$;

CREATE FUNCTION guard_mvp_recovery_time()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  active mvp_accounts%ROWTYPE;
BEGIN
  IF TG_TABLE_NAME = 'mvp_balance_checks' THEN
    IF mvp_cut_needs_occurrence_time(NEW.user_id, NEW.account_id, NEW.reference_at) THEN
      RAISE EXCEPTION 'Cut requires a more precise movement occurrence'
        USING ERRCODE = '23514', CONSTRAINT = 'mvp_cut_requires_time';
    END IF;
  ELSIF NEW.latest_occurrence_at IS NOT NULL THEN
    SELECT * INTO STRICT active FROM mvp_accounts
    WHERE user_id = NEW.user_id AND account_id = NEW.account_id FOR NO KEY UPDATE;
    IF NEW.occurrence_zone <> active.reference_zone
       OR NEW.occurred_at <> mvp_civil_day_start(NEW.occurrence_day, active.reference_zone)
       OR NEW.latest_occurrence_at <> LEAST(statement_timestamp(),
          mvp_civil_day_start(NEW.occurrence_day + 1, active.reference_zone) - interval '1 microsecond')
       OR EXISTS (SELECT 1 FROM mvp_balance_checks c
          WHERE c.user_id = NEW.user_id AND c.account_id = NEW.account_id
            AND c.reference_at >= NEW.occurred_at AND c.reference_at < NEW.latest_occurrence_at) THEN
      RAISE EXCEPTION 'Movement day is ambiguous or invalid'
        USING ERRCODE = '23514', CONSTRAINT = 'mvp_cut_requires_time';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER mvp_guard_check_cut BEFORE INSERT ON mvp_balance_checks
FOR EACH ROW EXECUTE FUNCTION guard_mvp_recovery_time();
CREATE TRIGGER mvp_guard_transaction_day BEFORE INSERT ON transactions
FOR EACH ROW EXECUTE FUNCTION guard_mvp_recovery_time();

CREATE FUNCTION write_mvp_expense_recovery()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  active mvp_accounts%ROWTYPE;
  movement transactions%ROWTYPE;
  observation mvp_balance_checks%ROWTYPE;
BEGIN
  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION 'MVP recoveries are immutable'
      USING ERRCODE = '23514', CONSTRAINT = 'mvp_recovery_immutable';
  END IF;

  SELECT * INTO STRICT active FROM mvp_accounts
  WHERE user_id = NEW.user_id AND account_id = NEW.account_id FOR NO KEY UPDATE;
  SELECT * INTO STRICT observation FROM mvp_balance_checks
  WHERE user_id = NEW.user_id AND account_id = NEW.account_id AND id = NEW.check_id;
  SELECT * INTO STRICT movement FROM transactions
  WHERE user_id = NEW.user_id AND account_id = NEW.account_id AND id = NEW.transaction_id;
  IF movement.type <> 'expense' OR movement.occurred_at < active.coverage_start
     OR COALESCE(movement.latest_occurrence_at, movement.occurred_at) > observation.reference_at THEN
    RAISE EXCEPTION 'Movement is outside the recovery cut'
      USING ERRCODE = '23514', CONSTRAINT = 'mvp_recovery_movement_ineligible';
  END IF;

  IF NEW.action = 'create' THEN
    IF movement.mvp_recovery_id IS DISTINCT FROM NEW.id
       OR movement.mvp_revision IS DISTINCT FROM NEW.mvp_revision
       OR movement.mvp_write_key IS DISTINCT FROM NEW.mvp_write_key
       OR NEW.mvp_revision <> active.revision THEN
      RAISE EXCEPTION 'Recovery requires a movement created by this operation'
        USING ERRCODE = '23514', CONSTRAINT = 'mvp_recovery_requires_movement';
    END IF;
  ELSE
    IF movement.mvp_recovery_id = NEW.id OR NEW.mvp_revision - 1 <> active.revision THEN
      RAISE EXCEPTION 'Recovery requires the current account revision and an existing movement'
        USING ERRCODE = '23514', CONSTRAINT = 'mvp_recovery_stale_revision';
    END IF;
    UPDATE mvp_accounts SET revision = NEW.mvp_revision WHERE user_id = NEW.user_id;
  END IF;

  NEW.created_at := statement_timestamp();
  RETURN NEW;
END;
$$;

CREATE TRIGGER mvp_expense_recovery_write
BEFORE INSERT OR UPDATE OR DELETE ON mvp_expense_recoveries
FOR EACH ROW EXECUTE FUNCTION write_mvp_expense_recovery();

CREATE FUNCTION check_mvp_expense_recovery_receipt()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM idempotency_keys
    WHERE user_id = NEW.user_id AND idempotency_key = NEW.mvp_write_key
      AND response->>'id' = NEW.id::text
      AND response->>'accountId' = NEW.account_id::text
      AND response->>'checkId' = NEW.check_id::text
      AND response->>'transactionId' = NEW.transaction_id::text
      AND response->>'revision' = NEW.mvp_revision::text
      AND response->>'action' = NEW.action
  ) THEN
    RAISE EXCEPTION 'MVP recovery requires its own receipt'
      USING ERRCODE = '23514', CONSTRAINT = 'mvp_recovery_receipt_required';
  END IF;
  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER mvp_recovery_receipt_required
AFTER INSERT ON mvp_expense_recoveries DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION check_mvp_expense_recovery_receipt();

CREATE FUNCTION mvp_recovery_delta(check_id uuid, original_revision bigint)
RETURNS numeric LANGUAGE sql STABLE AS $$
  SELECT COALESCE(-sum(t.amount_minor::bigint), 0)
  FROM mvp_expense_recoveries r
  JOIN transactions t ON t.id = r.transaction_id
  WHERE r.check_id = mvp_recovery_delta.check_id AND t.mvp_revision > original_revision
$$;

CREATE FUNCTION mvp_recovery_status(original numeric, remaining numeric, linked_delta numeric)
RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN remaining = 0 AND original <> 0 AND linked_delta = -original THEN 'resolved'
    WHEN remaining = 0 THEN 'coincident'
    WHEN sign(remaining) = sign(original) AND abs(remaining) < abs(original)
      AND sign(linked_delta) = -sign(original) THEN 'partially_explained'
    ELSE 'open'
  END
$$;
