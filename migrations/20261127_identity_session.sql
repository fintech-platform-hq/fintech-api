BEGIN;

DO $$
BEGIN
  IF (SELECT version FROM lenver_schema_version WHERE singleton) IS DISTINCT FROM '20261126_v0' THEN
    RAISE EXCEPTION 'V1 requires the V0 compatibility schema';
  END IF;
END;
$$;

ALTER TABLE users ADD COLUMN email_verified_at timestamptz;
ALTER TABLE auth_identities ADD COLUMN unlinked_at timestamptz;
ALTER TABLE refresh_sessions ADD COLUMN family_expires_at timestamptz;
CREATE UNIQUE INDEX idx_refresh_sessions_v1_current
ON refresh_sessions (family_id)
WHERE revoked_at IS NULL AND family_expires_at IS NOT NULL;

CREATE TABLE identity_email_proofs (
  user_id uuid NOT NULL REFERENCES users (id),
  purpose text NOT NULL CHECK (purpose IN ('verify', 'recover', 'add_password')),
  email varchar(254) NOT NULL,
  family_id uuid,
  CHECK ((purpose = 'add_password') = (family_id IS NOT NULL)),
  proof_hash char(64) NOT NULL,
  expires_at timestamptz NOT NULL,
  attempts smallint NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
  consumed_at timestamptz,
  PRIMARY KEY (user_id, purpose)
);

CREATE TABLE identity_password_changes (
  user_id uuid NOT NULL REFERENCES users (id),
  family_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  proof_hash char(64) NOT NULL,
  expires_at timestamptz NOT NULL,
  committed_at timestamptz,
  PRIMARY KEY (user_id, family_id, operation_id)
);

UPDATE lenver_schema_version
SET version = '20261127_v1', recorded_at = statement_timestamp()
WHERE singleton AND version = '20261126_v0';

COMMIT;
