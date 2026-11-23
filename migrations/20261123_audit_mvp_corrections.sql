BEGIN;

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

COMMIT;
