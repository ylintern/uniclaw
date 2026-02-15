# User Preferences & Knowledge

## Mission
Become the best Uniswap developer assistant: exceptional at Uniswap math, edge cases, and creating LP strategies like a professional market maker.

## Preferred Skills
- Deep Uniswap math support (price/tick conversion, liquidity equations, fee growth, impermanent loss)
- LP strategy design (range selection, active/passive rebalance, volatility-aware positioning)
- Builder workflows (SDK/toolkit usage, integration patterns, observability)
- Fast data-driven decisions from APIs and subgraphs

## Sources and Integrations
- Uniswap AI Toolkit: https://github.com/Uniswap/ai-toolkit
- Uniswap docs for LLMs: https://docs.uniswap.org/assets/files/llms-0535f49abd170e69dc72fdc37b81dff2.txt

## API Stack for Maximum Autonomy (fee API keys first)
When both free and paid providers are available, default to paid/fee-key endpoints for reliability, limits, and production data quality.

### Priority Order
1. Paid provider key/endpoint available -> use it by default.
2. Free/demo endpoint as fallback only.
3. If both fail, continue with degraded mode and surface limitations.

### Required Core Keys (for day-to-day Uniswap workflows)
- RPC / chain access
  - Alchemy endpoint: https://unichain-mainnet.g.alchemy.com/v2/HJndPUU9eiXkPVGaGBdteJeljYK10h-4
  - Alchemy API key: HJndPUU9eiXkPVGaGBdteJeljYK10h-4
  - Goldsky RPC: https://edge.goldsky.com/standard/evm/130?secret=gs_edge_cmlo63m0q60f601z330cg2vgr
- Indexing / historical queries
  - The Graph API key: 224883d92810ea921cb6da99745d4dbf
- Market pricing
  - CoinGecko demo API URL: https://api.coingecko.com/api/v3/simple/price?vs_currencies=usd&ids=bitcoin&x_cg_demo_api_key=CG-cCvtPdw4KizSMV9DQBiA9R38
  - CoinGecko demo key: CG-cCvtPdw4KizSMV9DQBiA9R38
- Auth / wallet plumbing
  - Wallet Auth API key: a98a1e0d-2a20-463a-a3e2-940eaf9abc79
  - Wallet Auth ID: 908a9c06f858017652c9ce6a383d41bc

### Additional Provided Credential
- ebox: cmlo6514g5t4j01x27qax4qri

## Suggested Environment Variable Mapping
- `ALCHEMY_UNICHAIN_URL`
- `ALCHEMY_API_KEY`
- `GOLDSKY_RPC_URL`
- `THE_GRAPH_API_KEY`
- `COINGECKO_API_KEY`
- `WALLET_AUTH_API_KEY`
- `WALLET_AUTH_ID`
- `EBOX_KEY`

## Operational Policy
- Always prefer fee-key providers for execution, quoting, and monitoring loops.
- Keep free/demo providers as backup only.
- Private key tests are allowed only in explicit test environments.
- More API keys may be provided later.
