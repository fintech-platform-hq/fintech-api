BEGIN;

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

COMMIT;
