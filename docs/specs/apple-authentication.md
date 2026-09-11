# Apple Authentication Contract

Status: planned contract — not part of the published API.

This specification is intentionally separate from `openapi.yaml` until the
corresponding endpoints are implemented and available in the live API.

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

The `client_secret` is a different JWT created by the backend, signed with
**ES256** using the backend's Sign in with Apple `.p8` private key, and sent
only to Apple's token endpoint.

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
sessions. When populated in a future Apple flow, a composite foreign key also
requires the identity and session to belong to the same user.

## Deferred provider validation

The future periodic check uses Apple's token endpoint with
`grant_type=refresh_token`. A 24-hour validation window is an application MVP
policy, not an instantaneous revocation guarantee. Apple server-to-server
notifications remain outside this checkpoint.
