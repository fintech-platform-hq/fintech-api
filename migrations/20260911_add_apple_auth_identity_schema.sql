BEGIN;

ALTER TABLE users
  ALTER COLUMN email DROP NOT NULL,
  ALTER COLUMN password_hash DROP NOT NULL,
  ADD CONSTRAINT users_password_requires_email_check
    CHECK (password_hash IS NULL OR email IS NOT NULL);

CREATE TABLE auth_identities (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users (id),
  provider text NOT NULL CHECK (provider = 'apple'),
  provider_subject text NOT NULL CHECK (length(btrim(provider_subject)) > 0),
  provider_email varchar(254) NULL,
  is_private_email boolean NOT NULL DEFAULT false,
  provider_refresh_token_ciphertext text NULL,
  last_provider_validation_at timestamptz NULL,
  revoked_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (
    provider_email IS NULL
    OR provider_email = lower(btrim(provider_email))
  ),
  UNIQUE (provider, provider_subject),
  UNIQUE (user_id, provider),
  UNIQUE (id, user_id)
);

CREATE FUNCTION assert_user_has_auth_method(p_user_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  has_auth_method boolean;
BEGIN
  PERFORM 1 FROM users WHERE id = p_user_id FOR UPDATE;

  SELECT u.password_hash IS NOT NULL
    OR EXISTS (
      SELECT 1 FROM auth_identities ai
      WHERE ai.user_id = u.id
    )
  INTO has_auth_method
  FROM users u
  WHERE u.id = p_user_id;

  IF NOT COALESCE(has_auth_method, false) THEN
    RAISE EXCEPTION 'user must have a password or external identity'
      USING ERRCODE = '23514', CONSTRAINT = 'users_auth_method_check';
  END IF;
END;
$$;

CREATE FUNCTION enforce_user_auth_method()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM assert_user_has_auth_method(NEW.id);
  RETURN NULL;
END;
$$;

CREATE FUNCTION enforce_identity_user_auth_method()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM assert_user_has_auth_method(
    CASE WHEN TG_OP = 'DELETE' THEN OLD.user_id ELSE NEW.user_id END
  );
  RETURN NULL;
END;
$$;

CREATE FUNCTION prevent_auth_identity_reparenting()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.user_id IS DISTINCT FROM OLD.user_id THEN
    RAISE EXCEPTION 'auth identity user_id is immutable'
      USING ERRCODE = '23514', CONSTRAINT = 'auth_identities_user_id_immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER users_must_have_auth_method
AFTER INSERT OR UPDATE OF email, password_hash ON users
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION enforce_user_auth_method();

CREATE CONSTRAINT TRIGGER auth_identities_must_have_user_auth_method
AFTER INSERT OR DELETE ON auth_identities
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION enforce_identity_user_auth_method();

CREATE TRIGGER auth_identities_user_id_immutable
BEFORE UPDATE OF user_id ON auth_identities
FOR EACH ROW EXECUTE FUNCTION prevent_auth_identity_reparenting();

ALTER TABLE refresh_sessions
  ADD COLUMN auth_identity_id uuid NULL,
  ADD CONSTRAINT refresh_sessions_auth_identity_owner_fk
    FOREIGN KEY (auth_identity_id, user_id)
    REFERENCES auth_identities (id, user_id);

CREATE INDEX idx_refresh_sessions_auth_identity
ON refresh_sessions (auth_identity_id, user_id)
WHERE auth_identity_id IS NOT NULL;

COMMIT;
