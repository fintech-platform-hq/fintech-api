BEGIN;

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

COMMIT;
