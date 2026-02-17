# PR #8 Resolution + IronClaw Upstream Review Proposal

## Objective

Resolve and harden the scope of **PR #8 (WebSocket gateway + control plane)** while reviewing upstream IronClaw improvements and adopting only changes that **enhance UniClaw without breaking current behavior**.

## What is already present in UniClaw

From repository history and parity docs:

- PR #8 capability is already represented as shipped work (`Add WebSocket gateway and control plane`).
- Feature parity currently marks both **WebSocket control plane** and **Gateway control plane** as implemented.
- Integration coverage already exists for:
  - WebSocket auth/upgrade + ping/pong
  - Client→agent message forwarding
  - SSE→WS broadcast bridge
  - Connection tracking and gateway status behavior

## Current risk baseline (must not regress)

1. **Gateway contract stability**
   - Keep `/api/chat/ws`, SSE fanout, and control endpoints behavior stable.
2. **Session/thread isolation**
   - Preserve per-user and per-thread routing behavior.
3. **Pairing safety controls**
   - Preserve short-lived pairing approvals and anti-bruteforce limits.
4. **Provider failover semantics**
   - Preserve retryable/non-retryable boundaries and fallback sequence behavior.

## IronClaw upstream intake plan

Because this environment currently blocks direct GitHub access, upstream PR intake will run in two stages:

### Stage A — Diff ingestion

For each upstream PR in `main...nearai:ironclaw:main`:

- Record PR number/title.
- Classify as `feature`, `fix`, `refactor`, or `infra/docs`.
- Map touched components to UniClaw modules.
- Assign risk level:
  - **Low**: docs/CI/no-runtime behavior
  - **Medium**: internal refactor with behavior parity
  - **High**: auth, gateway protocol, session routing, pairing, security policy, tool execution

### Stage B — Adopt/adapt/reject decision

For each PR:

- **Adopt** when behavior is additive and parity-aligned.
- **Adapt** when Rust architecture requires translation (e.g., wasm/tooling interfaces).
- **Reject/defer** when conflicting with UniClaw security posture or runtime model.

## Proposed implementation batches (non-breaking first)

### Batch 1 (safe, immediate)

- Gateway robustness improvements that do not alter external API schema.
- Additional integration assertions for WS+SSE ordering and auth edge cases.

### Batch 2 (guarded enhancements)

- Session lifecycle hardening (cleanup/observability) without changing message routing semantics.
- Pairing UX improvements that do not weaken TTL/rate limits.

### Batch 3 (feature parity lifts)

- Selectively lift high-value parity gaps (e.g., diagnostics/doctor-like checks) behind explicit commands.
- Update `FEATURE_PARITY.md` if implementation status changes.

## Validation gates before merge

A candidate upstream enhancement is accepted only if all applicable checks pass:

1. **Gateway invariants**
   - WS auth + origin checks remain enforced.
   - SSE events continue propagating to WS clients.
2. **Routing invariants**
   - Thread isolation remains deterministic by `(user, channel, external_thread_id)`.
3. **Security invariants**
   - Pairing TTL and approve rate-limits remain equal or stricter.
4. **Provider invariants**
   - Failover remains sequential on retryable errors only.
5. **Parity governance**
   - `FEATURE_PARITY.md` updated whenever feature status changes.

## Deliverables

1. Upstream PR matrix (`PR`, `area`, `risk`, `recommendation`, `expected tests`).
2. Implementation patch set in small subsystem-focused commits.
3. Regression evidence (targeted integration tests + unit tests).
4. Feature parity updates (if status changes).

## Definition of done

- PR #8 scope is confirmed stable via test evidence.
- Upstream IronClaw improvements are categorized with clear adopt/adapt/reject rationale.
- Accepted changes improve reliability/capability without breaking UniClaw’s current logic.
