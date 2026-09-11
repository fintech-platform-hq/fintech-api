# Apple Authentication Contract

Status: `POST /auth/apple` implemented; explicit account linking remains planned.

The implemented Apple authentication endpoint is published in `openapi.yaml`.
The future linking endpoint remains only in this specification.

## Endpoints

### `POST /auth/apple`

Unauthenticated Apple sign-in. The request contains non-empty:

- `identityToken`: the compact JWT returned by Apple;
- `authorizationCode`: the single-use authorization code returned by Apple;
- `nonce`: the exact nonce generated for this authorization attempt.

On success, the backend returns the existing `AuthResponse` without changing
its shape: `accessToken`, `refreshToken`, `tokenType: Bearer`, and
`expiresIn: 900`.

If the Apple `sub` is not linked but its email matches an existing user, the
backend returns HTTP 409 with `code: ACCOUNT_LINK_REQUIRED`. Email matching
never performs a silent merge.

For a new identity, a verified Apple email is stored as metadata in both
`users.email` and `auth_identities.provider_email`; absence of email is valid.
The Apple `sub`, never email, remains the authoritative external identity.
Later logins without email preserve existing metadata.

### `POST /auth/apple/link`

Explicitly links the Apple identity to the currently authenticated user.

This endpoint is allowed only with a backend-signed access token whose
`auth_method` claim is `password`. A client-supplied method, flag, email, or
user ID is never trusted for this decision. The future access-token claims are:

- `auth_method: password` for register/login by email and password;
- `auth_method: apple` for Apple authentication.

Refresh rotation must preserve this origin. Existing access tokens without
the claim must not be accepted for linking and require a new email/password
login.

Successful linking returns `204` and keeps the current session. It does not
create a second `AuthenticationSession`, access token, or refresh token.

## Nonce

The iOS client generates a cryptographically random 32-byte `rawNonce`,
encodes it as unpadded Base64URL, and sends that exact value both to
`ASAuthorizationAppleIDRequest.nonce` and to the backend request body.

The backend requires the `nonce` claim in `identityToken` to equal the body
value exactly and compares the values in constant time. This contract does not
hash the nonce and does not persist a server-side used-nonce set.

The nonce binds a token to its authorization attempt. A replayed or ambiguous
authorization code cannot be retried automatically; a new attempt must obtain
a new nonce and authorization code.

## JWT artifacts

The Apple `identityToken` is signed by Apple with **RS256** and is verified by
the backend using Apple's RSA JWKS (`kty=RSA`, `n`, and `e`).

The backend keeps the JWKS in process memory for one hour and performs an
early refresh when a token uses an unknown `kid`. Unknown-key refreshes are
limited to one per minute, and concurrent refreshes share the same request.
Expired keys are not used when a refresh fails.

The `client_secret` is a different JWT created by the backend, signed with
**ES256** using the backend's Sign in with Apple `.p8` private key, and sent
only to Apple's token endpoint.

The backend creates a new five-minute `client_secret` for each token-endpoint
request. It is never persisted or reused as an application session token.

## Authorization code exchange

The backend exchanges each native iOS authorization code exactly once with
`POST https://appleid.apple.com/auth/token`. The request uses
`application/x-www-form-urlencoded` with `client_id`, a newly generated
`client_secret`, `code`, and `grant_type=authorization_code`. It omits
`redirect_uri` because the native authorization request does not use one.

The token response must contain a bearer access token, a positive expiry, an
identity token, and a refresh token. The backend validates and discards the
Apple access token in this checkpoint. The Apple refresh token remains opaque
and is persisted encrypted at rest with AES-256-GCM.

The identity token received from iOS is validated first, including its nonce.
The identity token returned by the token endpoint is independently validated
with RS256 and must contain the same Apple `sub`. If the returned token contains
a nonce, it must match in constant time; the two compact JWT strings do not
need to be identical.

The token exchange has a five-second timeout, rejects redirects, and performs
no automatic retry. A timeout, disconnect, or malformed response is ambiguous:
the same single-use authorization code must not be submitted again, and the
client must start a new interactive authorization attempt.

After a failed refresh of expired Apple JWKS, the backend waits one minute
before attempting another refresh. It does not use expired keys during this
backoff, and concurrent callers continue to share an in-flight refresh.

## Environment variables

Only secret-managed deployment configuration may provide these values:

```text
APPLE_CLIENT_ID=<configured Apple client identifier>
APPLE_TEAM_ID=<Apple team identifier>
APPLE_KEY_ID=<Sign in with Apple key identifier>
APPLE_PRIVATE_KEY_P8=<secret-managed .p8 private key>
APPLE_REFRESH_TOKEN_ENCRYPTION_KEY=<secret-managed encryption key>
```

No real value belongs in this repository.

## Persistence invariants

`auth_identities(provider, provider_subject)` is unique and points to exactly
one `users.id`. Apple `sub` is the stable external identity; email, including
private relay email, is metadata and a possible explicit-linking signal only.

`refresh_sessions.auth_identity_id` is nullable for existing email/password
sessions. Apple sessions populate it, and the composite foreign key requires
the identity and session to belong to the same user. Refresh rotation preserves
this value and the signed `auth_method` claim.

Apple refresh tokens are encrypted at rest with AES-256-GCM. The versioned
envelope is `v1.<iv>.<ciphertext>.<tag>` using unpadded Base64URL fields, a
random 96-bit IV, and AAD bound to the `auth_identities.id`. Fintech refresh
tokens remain opaque to clients and hash-only in the database.

## Deferred provider validation

The future periodic check uses Apple's token endpoint with
`grant_type=refresh_token`. A 24-hour validation window is an application MVP
policy, not an instantaneous revocation guarantee. Apple server-to-server
notifications remain outside this checkpoint.
