BEGIN;

CREATE TABLE lenver_schema_version (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  version text NOT NULL CHECK (length(version) BETWEEN 1 AND 64),
  recorded_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

INSERT INTO lenver_schema_version (singleton, version)
VALUES (true, '20261126_v0');

COMMIT;
