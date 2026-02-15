# Security & Deployment Audit (Private Key Handling)

Date: 2026-02-15

## Scope reviewed

- `README.md`
- `src/setup/README.md`
- Secrets subsystem (`src/secrets/*`)
- Session/auth persistence (`src/llm/session.rs`, `src/main.rs`)
- Gateway auth flow (`src/channels/web/*`)
- Deployment assets (`Dockerfile`, `docker-compose.yml`)
- Feature readiness tracker (`FEATURE_PARITY.md`)
- Repository credential hygiene (`USER.md`)

## What is secure today

1. **Secrets-at-rest encryption exists for normal API secrets.**
   - Secret values are encrypted before DB persistence using AES-256-GCM.
   - A per-secret salt is generated and used with HKDF-SHA256 to derive per-secret encryption keys from a master key.
2. **Master key can be protected by OS keychain** (macOS Keychain / Linux Secret Service) with env-var fallback.
3. **Gateway endpoints are token-protected** and token comparisons are constant-time in auth middleware.
4. **Session file permissions are restricted on Unix** to `0600` after write.

## High-risk findings

### 1) Plaintext credentials are committed to the repository

`USER.md` currently contains real-looking API keys and endpoint secrets in plaintext. This is a critical secret-management issue independent of runtime crypto.

**Risk:** Immediate credential compromise and potential unauthorized API usage if repo is shared.

**Recommended action:**
- Revoke/rotate all listed keys immediately.
- Replace values with placeholders.
- Add a pre-commit/CI secret scanner (e.g., gitleaks/trufflehog).

### 2) NEAR AI session token is persisted in plaintext JSON

`src/llm/session.rs` stores `session_token` directly in `~/.ironclaw/session.json` via `serde_json::to_string_pretty` + `tokio::fs::write`.

**Risk:** Any local compromise/user-account compromise can read a bearer token usable for API access.

**Recommended action:**
- Move session token to the encrypted secrets store (preferred) or OS keychain.
- Keep disk JSON as metadata-only (no token) if backward compatibility is needed.

### 3) NEAR AI session token is also persisted to DB settings (not encrypted by secrets subsystem)

`src/llm/session.rs` writes `nearai.session_token` using generic `set_setting`, and settings table stores JSON/TEXT values.

**Risk:** DB compromise reveals live bearer tokens in plaintext.

**Recommended action:**
- Store session token in `secrets` table encrypted with `SecretsCrypto`.
- Reserve `settings` table for non-sensitive configuration.

### 4) Web gateway auth token is logged in startup logs

`src/main.rs` logs: `Web UI: http://.../?token=<token>`.

**Risk:** Token leakage via logs, shell history, process supervisors, observability sinks.

**Recommended action:**
- Stop printing full token; print redacted token suffix only.
- Prefer header-based auth UX rather than query token sharing.

## Medium-risk findings

1. **Query-parameter auth token support** in web auth middleware (`?token=...`) increases accidental leakage risk through browser history, referrers, and logs.
2. **CORS includes localhost origins** which is okay for local UX, but production deployment should expose an explicit hardened origin list configurable per environment.
3. **`docker-compose.yml` includes hardcoded dev DB credentials** (explicitly marked dev-only). This is acceptable for local usage but must not be reused in staging/prod.

## Deployment readiness assessment

## Verdict

**Not ready for production deployment as-is** for environments with real credentials.

### Blocking reasons

1. Credential leakage exists in repository content (`USER.md`).
2. Session bearer tokens are persisted in plaintext (disk + DB settings path).
3. Web gateway token is emitted in cleartext logs.

### Functional maturity signal

`FEATURE_PARITY.md` still lists many non-implemented (`❌`) and partial (`🚧`) capabilities across gateway operations, channels, diagnostics, and operations tooling. This does not block all deployments, but indicates the project is still in a maturing phase and needs tighter production hardening.

## Minimal remediation checklist before deploy

1. Rotate/revoke exposed keys and purge/replace committed secrets.
2. Migrate NEAR session token storage to encrypted secrets/keychain.
3. Remove full-token logging from startup and telemetry paths.
4. Disable query-token auth (or make opt-in only) and rely on `Authorization: Bearer`.
5. Add automated secret scanning in CI.
6. Add a production security baseline document (threat model + hardening defaults).

## Suggested release gate

Do not approve a production release until all of the following pass:

- No plaintext credentials in repository scan.
- Session tokens stored only via encrypted secret mechanisms.
- No sensitive tokens/keys in application logs.
- Security regression tests for token redaction and storage paths.
