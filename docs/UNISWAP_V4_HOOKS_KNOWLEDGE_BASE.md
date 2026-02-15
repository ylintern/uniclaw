# Uniswap v4 Hooks Knowledge Base

_Last updated: 2026-02-15_

## Purpose

This knowledge base consolidates Office Hours resources and practical guidance for building, reviewing, and shipping Uniswap v4 hooks. It is intended as a fast-start reference for:

- hook design and architecture
- security review workflows
- deployment and allowlist readiness
- gas sponsorship and UX patterns
- ongoing research and ecosystem examples

## Quick Start Checklist

1. Read Uniswap v4 security fundamentals and threat model.
2. Study production-style hook structure from Uniswap repositories.
3. Define hook invariants and adversarial test matrix before coding.
4. Validate if your hook needs allowlist submission.
5. Plan audit strategy and (optionally) subsidy/funding support.

## Core Learning Path

### 1) Security-first foundations

- **Uniswap v4 security framework:**
  - https://docs.uniswap.org/contracts/v4/security
- **Deep dive on hook security patterns:**
  - https://www.cyfrin.io/blog/uniswap-v4-hooks-security-deep-dive

Focus areas:

- call-order assumptions around `beforeSwap` / `afterSwap`
- reentrancy and callback safety
- fee manipulation and economic attacks
- denial-of-service vectors from hook logic

### 2) Reference implementations and structure

- **Uniswap v4 periphery hooks examples:**
  - https://github.com/Uniswap/v4-periphery/tree/main/src/hooks
- **Uniswap AI toolkit repository:**
  - https://github.com/Uniswap/ai-toolkit
- **Liquidity launcher LBP strategies:**
  - https://github.com/Uniswap/liquidity-launcher/tree/main/src/strategies/lbp

Suggested use:

- mirror directory conventions from periphery hooks
- compare initialization, config, and access-control patterns
- benchmark gas and complexity against reference code

### 3) Ecosystem-specific context

- **Clanker v4 core contracts references:**
  - https://clanker.gitbook.io/clanker-documentation/references/core-contracts/v4
- **v4hooks.dev (community resource):**
  - https://www.v4hooks.dev/

Use this to determine whether an integration relies on standard vs custom hook behavior and where compatibility assumptions may differ.

### 4) Product and historical context

- **Uniswap history and product evolution:**
  - https://blog.uniswap.org/uniswap-history
- **Paradigm Orbital AMM research (advanced math):**
  - https://www.paradigm.xyz/2025/06/orbital

These sources are useful for explaining design choices and understanding why specific AMM trade-offs matter.

### 5) Go-live and distribution constraints

- **Hooks allowlist submission form (Uniswap Labs Notion):**
  - https://uniswaplabs.notion.site/1aec52b2548b80f78dbef8d2f0d7183e?pvs=105

Relevant when hooks use:

- `beforeSwap`
- `afterSwap`
- dynamic fees
- delta flags

## Gasless / Sponsored UX References

For teams exploring sponsored swaps or account abstraction:

- **Gelato guide (ERC-4337 to EIP-7702):**
  - https://gelato.cloud/blog/gelato-s-guide-to-account-abstraction-from-erc-4337-to-eip-7702
- **Alchemy Gas Sponsorship API endpoints:**
  - https://www.alchemy.com/docs/wallets/low-level-infra/gas-manager/gas-sponsorship/api-endpoints

## Audits and Funding

- **Areta subsidy fund for audits:**
  - https://areta.market/uniswap

Use this during pre-launch planning to align security scope with available grant/subsidy opportunities.

## Community Note: Dynamic Fee Hook Example

From Office Hours:

- Igor shared a dynamic fee hook using `beforeSwap` to adjust fee tier based on swap size.
- Demo pool mentioned: small `$CLANKER/$WETH` deployment.
- Announcement thread:
  - https://x.com/igoryuzo/status/2017984227141177449

Implication for reviewers:

- dynamic fees can improve price discovery for larger trades, but should be assessed for fairness, manipulation resistance, and edge-case behavior under low liquidity.

## Skill Installation Notes

Requested command:

```bash
npx skills add https://github.com/igoryuzo/uniswapV4-hooks-skill
```

Observed in this environment:

- `npx` installation path failed with npm registry/proxy restrictions (`403 Forbidden`).
- Fallback installer script also failed due GitHub proxy tunnel restrictions (`403 Forbidden`).

If network policy allows GitHub access, retry with:

```bash
python3 /opt/codex/skills/.system/skill-installer/scripts/install-skill-from-github.py \
  --repo igoryuzo/uniswapV4-hooks-skill \
  --path <skill-subdirectory>
```

> Replace `<skill-subdirectory>` with the actual folder containing `SKILL.md` in that repository.

## Suggested Internal Maintenance

- Revisit this file when:
  - Uniswap v4 security docs are updated
  - allowlist requirements change
  - new audited hook patterns are published
- Keep a changelog section if this evolves into a team-standard runbook.
