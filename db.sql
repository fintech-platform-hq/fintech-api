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

CREATE TABLE mvp_movement_versions (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL,
  account_id uuid NOT NULL,
  transaction_id uuid NOT NULL,
  action text NOT NULL CHECK (action IN ('correct', 'invalidate')),
  amount_minor integer NOT NULL CHECK (amount_minor > 0),
  description text,
  occurred_at timestamptz NOT NULL CHECK (isfinite(occurred_at)),
  occurrence_day date,
  occurrence_zone text,
  latest_occurrence_at timestamptz,
  reason text NOT NULL CHECK (length(btrim(reason)) BETWEEN 1 AND 1000),
  created_at timestamptz NOT NULL,
  mvp_revision bigint NOT NULL CHECK (mvp_revision > 1),
  mvp_write_key uuid NOT NULL,
  UNIQUE (account_id, mvp_revision),
  UNIQUE (user_id, mvp_write_key),
  FOREIGN KEY (user_id, account_id, transaction_id) REFERENCES transactions (user_id, account_id, id),
  FOREIGN KEY (user_id, mvp_write_key) REFERENCES idempotency_keys (user_id, idempotency_key)
    DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX mvp_movement_versions_lookup ON mvp_movement_versions (transaction_id, mvp_revision DESC);

ALTER TABLE mvp_balance_checks ADD UNIQUE (user_id, account_id, id);
CREATE TABLE mvp_check_replacements (
  user_id uuid NOT NULL,
  account_id uuid NOT NULL,
  original_id uuid PRIMARY KEY,
  replacement_id uuid NOT NULL UNIQUE,
  reason text NOT NULL CHECK (length(btrim(reason)) BETWEEN 1 AND 1000),
  CHECK (original_id <> replacement_id),
  FOREIGN KEY (user_id, account_id, original_id) REFERENCES mvp_balance_checks (user_id, account_id, id),
  FOREIGN KEY (user_id, account_id, replacement_id) REFERENCES mvp_balance_checks (user_id, account_id, id)
);

CREATE VIEW mvp_effective_movements AS
SELECT t.id, t.user_id, t.account_id, t.type, t.currency, t.created_at,
  t.mvp_revision, t.mvp_write_key, t.mvp_recovery_id,
  COALESCE(v.amount_minor, t.amount_minor) AS amount_minor,
  CASE WHEN v.id IS NULL THEN t.description ELSE v.description END AS description,
  COALESCE(v.occurred_at, t.occurred_at) AS occurred_at,
  CASE WHEN v.id IS NULL THEN t.occurrence_day ELSE v.occurrence_day END AS occurrence_day,
  CASE WHEN v.id IS NULL THEN t.occurrence_zone ELSE v.occurrence_zone END AS occurrence_zone,
  CASE WHEN v.id IS NULL THEN t.latest_occurrence_at ELSE v.latest_occurrence_at END AS latest_occurrence_at,
  COALESCE(v.action = 'invalidate', false) AS invalidated,
  v.action AS "audit_action"
FROM transactions t
LEFT JOIN LATERAL (
  SELECT * FROM mvp_movement_versions v WHERE v.transaction_id = t.id
  ORDER BY v.mvp_revision DESC LIMIT 1
) v ON true;

CREATE FUNCTION write_mvp_movement_version()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  active mvp_accounts%ROWTYPE;
  movement mvp_effective_movements%ROWTYPE;
BEGIN
  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION 'Movement versions are immutable' USING ERRCODE = '23514';
  END IF;
  SELECT * INTO STRICT active FROM mvp_accounts
    WHERE user_id = NEW.user_id AND account_id = NEW.account_id FOR NO KEY UPDATE;
  SELECT * INTO STRICT movement FROM mvp_effective_movements
    WHERE user_id = NEW.user_id AND account_id = NEW.account_id AND id = NEW.transaction_id;
  IF active.revision + 1 <> NEW.mvp_revision OR movement.invalidated THEN
    RAISE EXCEPTION 'Movement version is stale or invalidated' USING ERRCODE = '23514';
  END IF;
  IF NEW.action = 'invalidate' THEN
    NEW.amount_minor := movement.amount_minor;
    NEW.description := movement.description;
    NEW.occurred_at := movement.occurred_at;
  ELSIF (NEW.amount_minor <> movement.amount_minor AND NEW.amount_minor > 999999999)
    OR NEW.occurred_at NOT BETWEEN active.coverage_start AND statement_timestamp() THEN
    RAISE EXCEPTION 'Correction is outside supported coverage or amount' USING ERRCODE = '23514';
  END IF;
  IF NEW.action = 'invalidate' OR
     (NEW.occurred_at = movement.occurred_at AND NEW.occurrence_day IS NOT NULL) THEN
    NEW.occurrence_day := movement.occurrence_day;
    NEW.occurrence_zone := movement.occurrence_zone;
    NEW.latest_occurrence_at := movement.latest_occurrence_at;
  ELSE
    NEW.occurrence_day := NULL;
    NEW.occurrence_zone := NULL;
    NEW.latest_occurrence_at := NULL;
  END IF;
  IF NEW.action = 'correct' AND ROW(NEW.amount_minor, NEW.description, NEW.occurred_at, NEW.occurrence_day)
     IS NOT DISTINCT FROM ROW(movement.amount_minor, movement.description, movement.occurred_at, movement.occurrence_day) THEN
    RAISE EXCEPTION 'Correction does not change the movement' USING ERRCODE = '23514';
  END IF;
  NEW.created_at := statement_timestamp();
  UPDATE mvp_accounts SET revision = NEW.mvp_revision WHERE user_id = NEW.user_id;
  RETURN NEW;
END;
$$;
CREATE TRIGGER mvp_movement_version_write BEFORE INSERT OR UPDATE OR DELETE ON mvp_movement_versions
FOR EACH ROW EXECUTE FUNCTION write_mvp_movement_version();

CREATE FUNCTION check_mvp_audit_receipt()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_TABLE_NAME = 'mvp_movement_versions' THEN
    IF EXISTS (SELECT 1 FROM idempotency_keys k
      WHERE k.user_id = NEW.user_id AND k.idempotency_key = NEW.mvp_write_key
        AND k.response @> jsonb_build_object('id', NEW.id, 'accountId', NEW.account_id,
          'authorId', NEW.user_id, 'action', NEW.action, 'reason', NEW.reason,
          'transactionId', NEW.transaction_id, 'revision', NEW.mvp_revision::text)) THEN
      RETURN NULL;
    END IF;
  ELSE
    IF EXISTS (SELECT 1 FROM mvp_balance_checks c JOIN idempotency_keys k
      ON k.user_id = c.user_id AND k.idempotency_key = c.mvp_write_key
      WHERE c.id = NEW.replacement_id
        AND k.response @> jsonb_build_object('id', NEW.replacement_id, 'accountId', NEW.account_id,
          'authorId', NEW.user_id, 'action', 'replace_check', 'reason', NEW.reason,
          'replacesCheckId', NEW.original_id, 'revision', c.mvp_revision::text)) THEN
      RETURN NULL;
    END IF;
  END IF;
  RAISE EXCEPTION 'Audited write requires its canonical receipt' USING ERRCODE = '23514';
END;
$$;
CREATE CONSTRAINT TRIGGER mvp_movement_version_receipt AFTER INSERT ON mvp_movement_versions
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_mvp_audit_receipt();
CREATE CONSTRAINT TRIGGER mvp_check_replacement_receipt AFTER INSERT ON mvp_check_replacements
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_mvp_audit_receipt();

CREATE FUNCTION guard_mvp_check_replacement()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  active bigint;
BEGIN
  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION 'Check replacements are immutable' USING ERRCODE = '23514';
  END IF;
  SELECT revision INTO STRICT active FROM mvp_accounts
    WHERE user_id = NEW.user_id AND account_id = NEW.account_id FOR NO KEY UPDATE;
  IF NOT EXISTS (SELECT 1 FROM mvp_balance_checks n JOIN mvp_balance_checks o
    ON o.id = NEW.original_id AND o.user_id = n.user_id AND o.account_id = n.account_id
    WHERE n.id = NEW.replacement_id AND n.user_id = NEW.user_id AND n.account_id = NEW.account_id
      AND n.mvp_revision = active AND o.mvp_revision < n.mvp_revision) THEN
    RAISE EXCEPTION 'Replacement requires a newly confirmed observation' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER mvp_check_replacement_write BEFORE INSERT OR UPDATE OR DELETE ON mvp_check_replacements
FOR EACH ROW EXECUTE FUNCTION guard_mvp_check_replacement();

CREATE OR REPLACE FUNCTION mvp_cut_needs_occurrence_time(owner_id uuid, target_id uuid, cut timestamptz)
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (
    SELECT 1 FROM mvp_effective_movements t
    WHERE t.user_id = owner_id AND t.account_id = target_id AND NOT t.invalidated
      AND t.occurred_at <= cut AND t.latest_occurrence_at > cut
  )
$$;

CREATE FUNCTION mvp_movement_effect(
  kind transaction_type, minor integer, first_at timestamptz, last_at timestamptz,
  coverage_start timestamptz, cut timestamptz, invalidated boolean
) RETURNS bigint LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE WHEN NOT invalidated AND first_at >= coverage_start AND COALESCE(last_at, first_at) <= cut
    THEN CASE WHEN kind = 'income' THEN minor::bigint ELSE -minor::bigint END ELSE 0 END
$$;

CREATE OR REPLACE FUNCTION mvp_balance_at(
  owner_id uuid, target_id uuid, base bigint, coverage_start timestamptz, cut timestamptz
) RETURNS numeric LANGUAGE sql STABLE AS $$
  SELECT CASE WHEN cut >= coverage_start THEN base + COALESCE((
    SELECT sum(mvp_movement_effect(t.type, t.amount_minor, t.occurred_at, t.latest_occurrence_at, coverage_start, cut, t.invalidated))
    FROM mvp_effective_movements t
    WHERE t.user_id = owner_id AND t.account_id = target_id
      AND t.occurred_at BETWEEN coverage_start AND cut AND NOT t.invalidated
  ), 0) END
$$;

CREATE OR REPLACE FUNCTION mvp_recovery_delta(check_id uuid, original_revision bigint)
RETURNS numeric LANGUAGE sql STABLE AS $$
  SELECT COALESCE(sum(
    mvp_movement_effect(live.type, live.amount_minor, live.occurred_at, live.latest_occurrence_at,
      a.coverage_start, c.reference_at, live.invalidated)
    - CASE WHEN COALESCE(t.mvp_revision, 0) <= original_revision THEN mvp_movement_effect(
      t.type, COALESCE(v.amount_minor, t.amount_minor), COALESCE(v.occurred_at, t.occurred_at),
      CASE WHEN v.id IS NULL THEN t.latest_occurrence_at ELSE v.latest_occurrence_at END,
      a.coverage_start, c.reference_at, COALESCE(v.action = 'invalidate', false))
      ELSE 0 END
  ), 0)
  FROM mvp_expense_recoveries r
  JOIN mvp_balance_checks c ON c.id = r.check_id
  JOIN mvp_accounts a ON a.user_id = c.user_id AND a.account_id = c.account_id
  JOIN transactions t ON t.id = r.transaction_id
  JOIN mvp_effective_movements live ON live.id = t.id
  LEFT JOIN LATERAL (
    SELECT * FROM mvp_movement_versions v WHERE v.transaction_id = t.id AND v.mvp_revision <= original_revision
    ORDER BY v.mvp_revision DESC LIMIT 1
  ) v ON true
  WHERE r.check_id = mvp_recovery_delta.check_id
$$;

CREATE OR REPLACE FUNCTION write_mvp_expense_recovery()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  active mvp_accounts%ROWTYPE;
  movement mvp_effective_movements%ROWTYPE;
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
  SELECT * INTO STRICT movement FROM mvp_effective_movements
  WHERE user_id = NEW.user_id AND account_id = NEW.account_id AND id = NEW.transaction_id;
  IF movement.invalidated OR EXISTS (SELECT 1 FROM mvp_check_replacements x WHERE x.original_id = observation.id)
     OR movement.type <> 'expense' OR movement.occurred_at < active.coverage_start
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

BEGIN;

ALTER TABLE mvp_accounts ADD COLUMN base_suspended boolean NOT NULL DEFAULT false;

CREATE TABLE mvp_base_versions (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL,
  account_id uuid NOT NULL,
  revision bigint NOT NULL,
  action text NOT NULL CHECK (action IN ('original', 'suspend_base', 'correct_base')),
  base_minor bigint NOT NULL,
  coverage_start timestamptz NOT NULL CHECK (isfinite(coverage_start)),
  reference_zone text NOT NULL,
  reason text CHECK (length(btrim(reason)) BETWEEN 1 AND 1000),
  created_at timestamptz NOT NULL,
  write_key uuid,
  CHECK (coverage_start <= created_at),
  CHECK ((revision = 1 AND action = 'original' AND reason IS NULL AND write_key IS NULL)
      OR (revision > 1 AND action <> 'original' AND reason IS NOT NULL AND write_key IS NOT NULL)),
  UNIQUE (account_id, revision),
  UNIQUE (user_id, write_key),
  FOREIGN KEY (user_id, account_id) REFERENCES mvp_accounts (user_id, account_id),
  FOREIGN KEY (user_id, write_key) REFERENCES idempotency_keys (user_id, idempotency_key)
    DEFERRABLE INITIALLY DEFERRED
);

INSERT INTO mvp_base_versions (id, user_id, account_id, revision, action, base_minor,
  coverage_start, reference_zone, created_at)
SELECT account_id, user_id, account_id, 1, 'original', base_minor, coverage_start,
  reference_zone, confirmed_at FROM mvp_accounts;

CREATE FUNCTION record_original_mvp_base()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.revision <> 1 OR NEW.base_suspended THEN
    RAISE EXCEPTION 'A new account requires its first confirmed base' USING ERRCODE = '23514';
  END IF;
  INSERT INTO mvp_base_versions (id,user_id,account_id,revision,action,base_minor,coverage_start,reference_zone,created_at)
  VALUES (NEW.account_id,NEW.user_id,NEW.account_id,1,'original',NEW.base_minor,NEW.coverage_start,NEW.reference_zone,NEW.confirmed_at);
  RETURN NULL;
END;
$$;
CREATE TRIGGER mvp_original_base AFTER INSERT ON mvp_accounts
FOR EACH ROW EXECUTE FUNCTION record_original_mvp_base();

CREATE FUNCTION mvp_coverage_ambiguities(owner_id uuid, target_id uuid, start_at timestamptz)
RETURNS uuid[] LANGUAGE sql STABLE AS $$
  SELECT ARRAY(SELECT t.id FROM mvp_effective_movements t
    WHERE t.user_id = owner_id AND t.account_id = target_id AND NOT t.invalidated
      AND t.occurred_at < start_at AND t.latest_occurrence_at >= start_at
    ORDER BY t.id)
$$;

CREATE FUNCTION write_mvp_base_version()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  active mvp_accounts%ROWTYPE;
BEGIN
  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION 'Base versions are immutable' USING ERRCODE = '23514';
  END IF;
  SELECT * INTO STRICT active FROM mvp_accounts
    WHERE user_id = NEW.user_id AND account_id = NEW.account_id FOR NO KEY UPDATE;
  IF NEW.action = 'original' AND NEW.revision = 1 AND NEW.id = active.account_id
      AND (NEW.base_minor, NEW.coverage_start, NEW.reference_zone, NEW.created_at)
          = (active.base_minor, active.coverage_start, active.reference_zone, active.confirmed_at) THEN
    RETURN NEW;
  END IF;
  IF NEW.action = 'original' OR NEW.revision - 1 <> active.revision THEN
    RAISE EXCEPTION 'Base version is stale' USING ERRCODE = '23514';
  END IF;
  NEW.created_at := statement_timestamp();
  NEW.reference_zone := active.reference_zone;
  IF NEW.action = 'suspend_base' THEN
    IF active.base_suspended THEN
      RAISE EXCEPTION 'Base is already suspended' USING ERRCODE = '23514';
    END IF;
    NEW.base_minor := active.base_minor;
    NEW.coverage_start := active.coverage_start;
  ELSIF cardinality(mvp_coverage_ambiguities(NEW.user_id, NEW.account_id, NEW.coverage_start)) > 0
     OR (NOT active.base_suspended AND (NEW.base_minor, NEW.coverage_start) = (active.base_minor, active.coverage_start)) THEN
    RAISE EXCEPTION 'Resolve coverage ambiguities and provide a changed base' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER mvp_base_version_write BEFORE INSERT OR UPDATE OR DELETE ON mvp_base_versions
FOR EACH ROW EXECUTE FUNCTION write_mvp_base_version();

CREATE FUNCTION apply_mvp_base_version()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  UPDATE mvp_accounts
    SET base_minor = NEW.base_minor, coverage_start = NEW.coverage_start,
      confirmed_at = CASE WHEN NEW.action = 'correct_base' THEN NEW.created_at ELSE confirmed_at END,
      base_suspended = (NEW.action = 'suspend_base'), revision = NEW.revision
    WHERE user_id = NEW.user_id AND account_id = NEW.account_id;
  RETURN NULL;
END;
$$;
CREATE TRIGGER mvp_base_version_apply AFTER INSERT ON mvp_base_versions
FOR EACH ROW WHEN (NEW.action <> 'original') EXECUTE FUNCTION apply_mvp_base_version();

CREATE FUNCTION guard_mvp_base_update()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.user_id, NEW.account_id, NEW.currency, NEW.reference_zone)
       IS DISTINCT FROM (OLD.user_id, OLD.account_id, OLD.currency, OLD.reference_zone)
     OR (NEW.base_minor, NEW.coverage_start, NEW.confirmed_at, NEW.base_suspended)
       IS DISTINCT FROM (OLD.base_minor, OLD.coverage_start, OLD.confirmed_at, OLD.base_suspended)
       AND NOT EXISTS (
         SELECT 1 FROM mvp_base_versions v WHERE v.user_id = OLD.user_id AND v.account_id = OLD.account_id
           AND v.revision = NEW.revision AND v.revision - 1 = OLD.revision
           AND (v.base_minor, v.coverage_start, v.reference_zone) = (NEW.base_minor, NEW.coverage_start, NEW.reference_zone)
           AND (NEW.base_suspended, NEW.confirmed_at) =
             (v.action = 'suspend_base', CASE WHEN v.action = 'correct_base' THEN v.created_at ELSE OLD.confirmed_at END)
       ) THEN
    RAISE EXCEPTION 'Base updates require an audited version' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER mvp_base_update BEFORE UPDATE ON mvp_accounts
FOR EACH ROW EXECUTE FUNCTION guard_mvp_base_update();

CREATE FUNCTION require_mvp_base_receipt()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM idempotency_keys k WHERE k.user_id = NEW.user_id AND k.idempotency_key = NEW.write_key
    AND k.response @> jsonb_build_object('id', NEW.id, 'accountId', NEW.account_id,
      'authorId', NEW.user_id, 'action', NEW.action, 'reason', NEW.reason, 'revision', NEW.revision::text)) THEN
    RAISE EXCEPTION 'Base version requires its canonical receipt' USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER mvp_base_receipt AFTER INSERT ON mvp_base_versions
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.action <> 'original')
EXECUTE FUNCTION require_mvp_base_receipt();

CREATE FUNCTION require_unsuspended_mvp_base()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  suspended boolean;
BEGIN
  SELECT base_suspended INTO suspended FROM mvp_accounts
    WHERE account_id = NEW.account_id FOR NO KEY UPDATE;
  IF suspended THEN
    RAISE EXCEPTION 'Base is suspended' USING ERRCODE = '23514', CONSTRAINT = 'mvp_base_suspended';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER a_mvp_base_suspension BEFORE INSERT ON transactions
FOR EACH ROW EXECUTE FUNCTION require_unsuspended_mvp_base();
CREATE TRIGGER a_mvp_base_suspension BEFORE INSERT ON mvp_balance_checks
FOR EACH ROW EXECUTE FUNCTION require_unsuspended_mvp_base();
CREATE TRIGGER a_mvp_base_suspension BEFORE INSERT ON mvp_expense_recoveries
FOR EACH ROW EXECUTE FUNCTION require_unsuspended_mvp_base();

ALTER TABLE mvp_movement_versions DROP CONSTRAINT mvp_movement_versions_action_check;
ALTER TABLE mvp_movement_versions ADD CHECK (action IN ('correct', 'invalidate', 'refine_occurrence'));

CREATE OR REPLACE VIEW mvp_effective_movements AS
SELECT t.id, t.user_id, t.account_id, t.type, t.currency, t.created_at,
  t.mvp_revision, t.mvp_write_key, t.mvp_recovery_id,
  COALESCE(v.amount_minor, t.amount_minor) AS amount_minor,
  CASE WHEN v.id IS NULL THEN t.description ELSE v.description END AS description,
  COALESCE(v.occurred_at, t.occurred_at) AS occurred_at,
  CASE WHEN v.id IS NULL THEN t.occurrence_day ELSE v.occurrence_day END AS occurrence_day,
  CASE WHEN v.id IS NULL THEN t.occurrence_zone ELSE v.occurrence_zone END AS occurrence_zone,
  CASE WHEN v.id IS NULL THEN t.latest_occurrence_at ELSE v.latest_occurrence_at END AS latest_occurrence_at,
  COALESCE(v.action = 'invalidate', false) AS invalidated,
  CASE WHEN v.action = 'refine_occurrence' THEN 'correct' ELSE v.action END AS audit_action
FROM transactions t
LEFT JOIN LATERAL (
  SELECT * FROM mvp_movement_versions v WHERE v.transaction_id = t.id
  ORDER BY v.mvp_revision DESC LIMIT 1
) v ON true;

CREATE OR REPLACE FUNCTION write_mvp_movement_version()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  active mvp_accounts%ROWTYPE;
  movement mvp_effective_movements%ROWTYPE;
BEGIN
  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION 'Movement versions are immutable' USING ERRCODE = '23514';
  END IF;
  SELECT * INTO STRICT active FROM mvp_accounts
    WHERE user_id = NEW.user_id AND account_id = NEW.account_id FOR NO KEY UPDATE;
  SELECT * INTO STRICT movement FROM mvp_effective_movements
    WHERE user_id = NEW.user_id AND account_id = NEW.account_id AND id = NEW.transaction_id;
  IF active.revision + 1 <> NEW.mvp_revision OR movement.invalidated THEN
    RAISE EXCEPTION 'Movement version is stale or invalidated' USING ERRCODE = '23514';
  END IF;
  IF active.base_suspended AND NEW.action <> 'refine_occurrence' THEN
    RAISE EXCEPTION 'Base is suspended' USING ERRCODE = '23514', CONSTRAINT = 'mvp_base_suspended';
  END IF;
  IF NEW.action = 'refine_occurrence' THEN
    IF movement.latest_occurrence_at IS NULL OR NEW.occurrence_day IS NOT NULL
       OR NEW.occurred_at NOT BETWEEN movement.occurred_at AND movement.latest_occurrence_at
       OR (NEW.amount_minor, NEW.description) IS DISTINCT FROM (movement.amount_minor, movement.description) THEN
      RAISE EXCEPTION 'Refinement requires an instant within the original day' USING ERRCODE = '23514';
    END IF;
  ELSIF NEW.action = 'invalidate' THEN
    NEW.amount_minor := movement.amount_minor;
    NEW.description := movement.description;
    NEW.occurred_at := movement.occurred_at;
  ELSIF (NEW.amount_minor <> movement.amount_minor AND NEW.amount_minor > 999999999)
    OR (NEW.occurred_at IS DISTINCT FROM movement.occurred_at
      AND NEW.occurred_at NOT BETWEEN active.coverage_start AND statement_timestamp()) THEN
    RAISE EXCEPTION 'Correction is outside supported coverage or amount' USING ERRCODE = '23514';
  END IF;
  IF NEW.action = 'invalidate' OR
     (NEW.occurred_at = movement.occurred_at AND NEW.occurrence_day IS NOT NULL) THEN
    NEW.occurrence_day := movement.occurrence_day;
    NEW.occurrence_zone := movement.occurrence_zone;
    NEW.latest_occurrence_at := movement.latest_occurrence_at;
  ELSE
    NEW.occurrence_day := NULL;
    NEW.occurrence_zone := NULL;
    NEW.latest_occurrence_at := NULL;
  END IF;
  IF NEW.action = 'correct' AND ROW(NEW.amount_minor, NEW.description, NEW.occurred_at, NEW.occurrence_day)
     IS NOT DISTINCT FROM ROW(movement.amount_minor, movement.description, movement.occurred_at, movement.occurrence_day) THEN
    RAISE EXCEPTION 'Correction does not change the movement' USING ERRCODE = '23514';
  END IF;
  NEW.created_at := statement_timestamp();
  UPDATE mvp_accounts SET revision = NEW.mvp_revision WHERE user_id = NEW.user_id;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION mvp_balance_at(
  owner_id uuid, target_id uuid, base bigint, coverage_start timestamptz, cut timestamptz
) RETURNS numeric LANGUAGE sql STABLE AS $$
  SELECT CASE WHEN cut >= coverage_start AND NOT EXISTS (
    SELECT 1 FROM mvp_effective_movements t
    WHERE t.user_id = owner_id AND t.account_id = target_id AND NOT t.invalidated
      AND t.occurred_at <= cut
      AND ((t.occurred_at < coverage_start AND t.latest_occurrence_at >= coverage_start)
        OR (t.occurred_at >= coverage_start AND t.latest_occurrence_at > cut))
  ) THEN base + COALESCE((
    SELECT sum(mvp_movement_effect(t.type, t.amount_minor, t.occurred_at, t.latest_occurrence_at, coverage_start, cut, t.invalidated))
    FROM mvp_effective_movements t
    WHERE t.user_id = owner_id AND t.account_id = target_id
      AND t.occurred_at BETWEEN coverage_start AND cut AND NOT t.invalidated
  ), 0) END
$$;

CREATE OR REPLACE FUNCTION mvp_recovery_delta(check_id uuid, original_revision bigint)
RETURNS numeric LANGUAGE sql STABLE AS $$
  SELECT COALESCE(sum(
    CASE WHEN mvp_movement_effect(live.type, live.amount_minor, live.occurred_at, live.latest_occurrence_at,
      a.coverage_start, c.reference_at, live.invalidated) IS DISTINCT FROM
      mvp_movement_effect(live.type, live.amount_minor, live.occurred_at, live.latest_occurrence_at,
        original.coverage_start, c.reference_at, live.invalidated) THEN 0 ELSE
    mvp_movement_effect(live.type, live.amount_minor, live.occurred_at, live.latest_occurrence_at,
      a.coverage_start, c.reference_at, live.invalidated)
    - CASE WHEN COALESCE(t.mvp_revision, 0) <= original_revision THEN mvp_movement_effect(
      t.type, COALESCE(v.amount_minor, t.amount_minor), COALESCE(v.occurred_at, t.occurred_at),
      CASE WHEN v.id IS NULL THEN t.latest_occurrence_at ELSE v.latest_occurrence_at END,
      original.coverage_start, c.reference_at, COALESCE(v.action = 'invalidate', false))
      ELSE 0 END END
  ), 0)
  FROM mvp_expense_recoveries r
  JOIN mvp_balance_checks c ON c.id = r.check_id
  JOIN mvp_accounts a ON a.user_id = c.user_id AND a.account_id = c.account_id
  JOIN LATERAL (
    SELECT b.coverage_start FROM mvp_base_versions b
    WHERE b.account_id = c.account_id AND b.revision <= c.mvp_revision AND b.action <> 'suspend_base'
    ORDER BY b.revision DESC LIMIT 1
  ) original ON true
  JOIN transactions t ON t.id = r.transaction_id
  JOIN mvp_effective_movements live ON live.id = t.id
  LEFT JOIN LATERAL (
    SELECT * FROM mvp_movement_versions v WHERE v.transaction_id = t.id AND v.mvp_revision <= original_revision
    ORDER BY v.mvp_revision DESC LIMIT 1
  ) v ON true
  WHERE r.check_id = mvp_recovery_delta.check_id
$$;

COMMIT;
