DO $$
DECLARE
  missing_marker_detected boolean;
BEGIN
  DELETE FROM lenver_schema_version WHERE singleton = true;
  SELECT (
    SELECT version FROM lenver_schema_version WHERE singleton = true
  ) IS DISTINCT FROM '20261127_v1_method_receipts'
  INTO missing_marker_detected;

  IF missing_marker_detected IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'schema marker assertion did not detect a missing row';
  END IF;

  INSERT INTO lenver_schema_version (singleton, version)
  VALUES (true, '20261127_v1_method_receipts');
END
$$;
