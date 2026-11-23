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
