BEGIN;

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

-- I1-A admits no movement writer on active MVP accounts, including old binaries.
CREATE FUNCTION block_mvp_transaction_writes()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP <> 'INSERT' THEN
    IF EXISTS (SELECT 1 FROM mvp_accounts WHERE account_id = OLD.account_id) THEN
      RAISE EXCEPTION 'MVP transaction writes are disabled'
        USING ERRCODE = '23514', CONSTRAINT = 'mvp_transaction_writes_disabled';
    END IF;
  END IF;
  IF TG_OP <> 'DELETE' THEN
    IF EXISTS (SELECT 1 FROM mvp_accounts WHERE account_id = NEW.account_id) THEN
      RAISE EXCEPTION 'MVP transaction writes are disabled'
        USING ERRCODE = '23514', CONSTRAINT = 'mvp_transaction_writes_disabled';
    END IF;
    RETURN NEW;
  END IF;
  RETURN OLD;
END;
$$;

CREATE TRIGGER mvp_transaction_writes_disabled
BEFORE INSERT OR UPDATE OR DELETE ON transactions
FOR EACH ROW EXECUTE FUNCTION block_mvp_transaction_writes();

COMMIT;
