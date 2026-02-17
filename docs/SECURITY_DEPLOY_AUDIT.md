# Security & Deployment Audit (Private Key Handling)

Date: 2026-02-15

## Scope reviewed

- `README.md`
- `src/setup/README.md`
- Secrets subsystem (`src/secrets/*`)
- Session/auth persistence (`src/llm/session.rs`, `src/main.rs`, `src/bootstrap.rs`)
- Gateway auth flow (`src/channels/web/*`)
- Deployment assets (`Dockerfile`, `docker-compose.yml`)
- Feature readiness tracker (`FEATURE_PARITY.md`)
- Repository credential hygiene (`USER.md`)

## What is secure today

1. **Secrets-at-rest encryption exists for API secrets.**
   - Secret values are encrypted before DB persistence using AES-256-GCM.
   - A per-secret salt is generated and used with HKDF-SHA256 to derive per-secret encryption keys from a master key.
2. **Master key can be protected by OS keychain** (macOS Keychain / Linux Secret Service) with env-var fallback.
3. **Gateway endpoints are token-protected** and token comparisons are constant-time in auth middleware.
4. **Session file permissions are restricted on Unix** to `0600` after write.

## Fixes applied for previously reported blockers

1. **Repository plaintext credential leakage**
   - `USER.md` now uses placeholders / variable references instead of literal secrets.
2. **NEAR AI session token plaintext at rest**
   - Session tokens are now encrypted before disk persistence in `~/.uniclaw/session.json`.
   - Legacy plaintext session files are read for compatibility and auto-migrated to encrypted format.
3. **Session token stored in DB settings**
   - Session persistence to `settings` (`nearai.session_token`) has been removed.
   - Legacy bootstrap migration now explicitly skips moving session token material into DB settings.
4. **Gateway token leakage in logs/URLs**
   - Startup no longer logs `?token=<secret>` URLs.
   - Web auth middleware no longer accepts query-token auth; it accepts Bearer auth and secure session cookie fallback.
   - Frontend now uses cookie-backed EventSource auth instead of query-token URLs.

## Remaining medium-risk findings

1. **CORS policy** currently includes localhost/dev origins for local UX; production deployment should use an explicit hardened origin list.
2. **`docker-compose.yml` includes hardcoded dev DB credentials** (explicitly marked dev-only). This is acceptable for local usage but must not be reused in staging/prod.

## Deployment readiness assessment

## Verdict

**Conditionally ready for controlled deployment** once operational hardening below is complete.

### Remaining release checklist

1. Rotate/revoke any credentials that were previously exposed in repository history.
2. Add automated secret scanning in CI (e.g., gitleaks/trufflehog).
3. Add explicit production origin policy and deployment hardening docs.
4. Validate no token/secret leaks via integration log-scrub checks in CI.

### Functional maturity signal

`FEATURE_PARITY.md` still lists many non-implemented (`❌`) and partial (`🚧`) capabilities across gateway operations, channels, diagnostics, and operations tooling. This does not block all deployments, but indicates the project is still in a maturing phase and needs tighter production hardening.
