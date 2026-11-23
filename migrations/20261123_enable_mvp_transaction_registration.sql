BEGIN;

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

CREATE OR REPLACE FUNCTION block_mvp_transaction_writes()
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

COMMIT;
