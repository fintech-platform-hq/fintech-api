BEGIN;

DO $$
BEGIN
  IF (SELECT version FROM lenver_schema_version WHERE singleton) IS DISTINCT FROM '20261127_v1' THEN
    RAISE EXCEPTION 'Identity method receipts require the V1 identity schema';
  END IF;
END;
$$;

CREATE TABLE identity_method_receipts (
  user_id uuid NOT NULL REFERENCES users (id),
  family_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  action text NOT NULL CHECK (action IN ('apple_link', 'apple_unlink', 'password_link', 'password_unlink')),
  PRIMARY KEY (user_id, family_id, operation_id)
);

UPDATE lenver_schema_version
SET version = '20261127_v1_method_receipts', recorded_at = statement_timestamp()
WHERE singleton AND version = '20261127_v1';

COMMIT;
