# erc8004-agent-auth

**Know which ERC-8004 agent is calling your API: checked against the blockchain, with no API keys and no middleman.**

AI agents are starting to call APIs, pay for services (x402) and talk to each other (A2A, MCP). [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004)
gives every agent an on-chain identity, but an HTTP request still has no standard way to prove *which* agent sent it.
Today servers either trust a self-reported name or hand out API keys, which defeats the point of open, permissionless agents.

This repo is a small, open standard and two reference libraries that fix that:

- **Agents** sign each request with the wallet registered for them in the ERC-8004 Identity Registry.
- **Servers** verify the signature and then read the registry directly over JSON-RPC (`ownerOf`, `getAgentWallet`,
  ERC-1271 for smart-contract wallets). There are no accounts, no API keys and no third-party service.

```
agent ── signed request ──▶ your API ── eth_call ──▶ ERC-8004 Identity Registry
          ERC8004-Agent: eip155:8453:1203          "is 0xAbc… the wallet of agent 1203?"
          ERC8004-Signature: 0x…
```

| | |
|---|---|
| Spec | [`SPEC.md`](SPEC.md) — `erc8004-agent-auth/1`, CC0 |
| Python | [`python/`](python) — `pip install erc8004-agent-auth` |
| JavaScript / TypeScript | [`js/`](js) — `npm install erc8004-agent-auth ethers` (Node 18+, Bun, Deno, edge, browsers) |
| Test vectors | [`vectors/v1.json`](vectors/v1.json) — both libraries must reproduce them byte for byte |
| License | MIT |

## What a check proves

Each request is bound to its **method, full URL, body hash, timestamp and a one-time nonce**, so a signature can't be
replayed, moved to another endpoint or reused with another body. The verifier accepts it only if the signer is the
agent's **verified agent wallet** (or, optionally, the agent NFT's **owner**) *right now*, on chain. ERC-8004 clears the
agent wallet when an agent is sold, so old keys stop working on transfer.

It does **not** tell you whether the agent is good. Combine it with ERC-8004 reputation and validation data and your
own limits.

## Agent side

```python
from erc8004_agent_auth import sign_request
import requests

body = b'{"amount":"10","asset":"USDC"}'
headers = sign_request(AGENT_PRIVATE_KEY, "eip155:8453:1203", "POST", "https://api.example.com/orders", body)
requests.post("https://api.example.com/orders", data=body, headers={**headers, "Content-Type": "application/json"})
```

```js
import { signRequest } from "erc8004-agent-auth";

const body = JSON.stringify({ amount: "10", asset: "USDC" });
const headers = await signRequest(wallet /* ethers Signer or key */, "eip155:8453:1203", "POST",
  "https://api.example.com/orders", body);
await fetch("https://api.example.com/orders", { method: "POST", body, headers: { ...headers, "content-type": "application/json" } });
```

Keep the private key in the agent's own environment or signer (KMS, hardware wallet, smart account). It is never sent anywhere.

## Server side

**Flask**

```python
from flask import Flask, request, abort, g
from erc8004_agent_auth import Verifier

verifier = Verifier({8453: "https://YOUR-BASE-RPC", 1: "https://YOUR-MAINNET-RPC"})

@app.before_request
def require_agent():
    result = verifier.verify(request.headers, request.method, request.url, request.get_data())
    if not result:
        abort(401, result.reason)
    g.agent = result.agent          # "eip155:8453:1203"
```

**Express**

```js
import express from "express";
import { Verifier } from "erc8004-agent-auth";

const verifier = new Verifier({ rpcUrls: { 8453: process.env.BASE_RPC, 1: process.env.MAINNET_RPC } });
const app = express();
app.use(express.raw({ type: "*/*" }));            // the signature covers the raw body
app.use(async (req, res, next) => {
  const url = `${req.protocol}://${req.get("host")}${req.originalUrl}`;
  const result = await verifier.verify(req.headers, req.method, url, req.body?.length ? req.body : "");
  if (!result.ok) return res.status(401).json({ error: result.reason });
  req.agent = result.agent;
  next();
});
```

Every result carries `ok`, a human-readable `reason`, `agent`, `chainId`/`chain_id`, `agentId`/`agent_id`, `signer`,
`role` (`agent_wallet` or `owner`) and the list of `checks` that passed.

### Options

| Option | Default | |
|---|---|---|
| `allow_owner` / `allowOwner` | `true` | Also accept signatures from the agent NFT's owner |
| `max_skew` / `maxSkew` | `300` | Allowed clock difference in seconds (can only be lowered) |
| `nonce_store` / `nonceStore` | in memory | Anything with `use(key, now) → bool`; use Redis `SET NX EX` or a unique DB index when you run several servers |
| `registries` | canonical address | `IdentityRegistry(rpc_url, address=…)` for testnets or custom deployments |
| `protocol` | `erc8004-agent-auth/1` | Verify a vendor-prefixed variant of the same message format |

## Security notes

- Fails closed: if the RPC is down or returns garbage, the request is rejected.
- Timestamps and header formats are checked before any RPC call, so junk requests cost nothing.
- A nonce is stored only after the signature checks out, so attackers can't burn a real agent's nonces.
- Behind a reverse proxy, verify against the public URL the client called.
- Use an RPC you trust (your own node or a provider you pay); the verifier believes what it returns.

## Status and roadmap

v0.1 — spec draft, Python and JS libraries, shared vectors, CI. Planned next:

1. Framework middleware packages (FastAPI, Express/Hono, Next.js) and an MCP-server helper.
2. Live integration tests against the Base and Ethereum mainnet registries, plus a Foundry fork test for ERC-1271 wallets.
3. Multi-RPC quorum reads and response caching, so one bad RPC can't lie about an agent.
4. An x402 extension so paid requests carry the paying agent's identity.
5. Proposing the header format to the ERC-8004 community as a companion standard.

Contributions, issues and other implementations are welcome. If you build one, make it pass `vectors/v1.json`.
