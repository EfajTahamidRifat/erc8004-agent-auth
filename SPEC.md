# ERC-8004 Agent Request Authentication — v1

**Status:** draft · **Version string:** `erc8004-agent-auth/1` · **License:** CC0

This document defines how an AI agent registered under [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004)
proves, on each HTTP request, that the request comes from that agent — and how any server verifies it using
only the canonical on-chain Identity Registry. No API key, account or third-party service is involved.

## 1. Who can sign

An agent is identified by `eip155:<chainId>:<agentId>` (the agent's ERC-721 token in the Identity Registry).
A request is valid if it is signed by one of:

| Role | Address | Read from |
|---|---|---|
| `agent_wallet` | the agent's verified wallet | `IdentityRegistry.getAgentWallet(agentId)` |
| `owner` | the agent NFT's owner | `IdentityRegistry.ownerOf(agentId)` |

Verifiers SHOULD accept `agent_wallet` and MAY accept `owner` (the default in the reference libraries is to
accept both). The ERC-8004 spec clears `agentWallet` when the agent is transferred, so a sold agent cannot keep
signing with the old wallet.

Signatures are EIP-191 `personal_sign` signatures. If the signing address is a smart-contract wallet,
verifiers check it with ERC-1271 `isValidSignature(hash, signature)`, where `hash` is the EIP-191 message hash.

## 2. Headers

| Header | Value |
|---|---|
| `ERC8004-Agent` | `eip155:<chainId>:<agentId>` — decimal numbers, e.g. `eip155:8453:1203` |
| `ERC8004-Timestamp` | Unix time in seconds when the request was signed |
| `ERC8004-Nonce` | 16–128 characters from `A–Z a–z 0–9 - _`, unique per request |
| `ERC8004-Signature` | `0x`-prefixed hex signature over the message below |

Header names are case-insensitive, as in HTTP.

## 3. Signed message

UTF-8 text, lines joined with a single `\n`, no trailing newline:

```
erc8004-agent-auth/1
agent: eip155:<chainId>:<agentId>
method: <HTTP method, upper case>
url: <normalized URL>
timestamp: <same as ERC8004-Timestamp>
nonce: <same as ERC8004-Nonce>
body-sha256: <lower-case hex SHA-256 of the raw request body; empty body → e3b0c442…b855>
```

**URL normalization:** scheme and host in lower case; default ports (`:443` for https, `:80` for http)
removed; any `user:pass@` part removed; IPv6 hosts in brackets; an empty path becomes `/`; the path and query string are kept exactly as
sent on the wire, i.e. ASCII with percent-encoding (no re-encoding, no reordering); an empty `?` is dropped; any
`#fragment` is dropped. Only `http` and `https` URLs are valid. Behind a proxy, verify against the public URL the
client called (scheme and host from `X-Forwarded-Proto`/`Host` set by your own proxy), not the internal one.

## 4. Verification

A verifier MUST reject the request unless all of these hold, in this order:

1. All four headers are present and well-formed.
2. `|now − timestamp| ≤ 300` seconds (verifiers MAY use a smaller window).
3. The recovered signer (or ERC-1271 check) matches `getAgentWallet(agentId)` or, if allowed,
   `ownerOf(agentId)`, read from the canonical Identity Registry on `chainId`. `ownerOf` reverting means the
   agent does not exist.
4. The nonce has not been seen for this agent within at least the last 15 minutes. Verifiers record the nonce
   only after steps 1–3 pass.

The URL and body used for verification are the ones the server actually received, so a signature cannot be
moved to another endpoint or another body.

## 5. Canonical registries

ERC-8004 registries are deployed at the same addresses on every supported mainnet:

| Registry | Address |
|---|---|
| Identity | `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` |
| Reputation | `0x8004BAa17C55a88189AE136b182e5fdA19dE9b63` |
| Validation | `0x8004Cc8439f36fd5F9F049D9fF86523Df6dAAB58` |

Testnets may use different addresses; the reference libraries accept an override.

## 6. What a valid signature does and does not mean

It proves that whoever controls the agent's registered wallet (or owner wallet) sent this exact request, now,
once. It does **not** say whether the agent is trustworthy — combine it with the agent's ERC-8004 reputation
and validation records, your own rules and limits.

## 7. Test vectors

`vectors/v1.json` contains fixed keys, requests, messages and signatures. Every implementation must reproduce
them exactly.

## 8. Delegation chains — `erc8004-delegation/1`

When agent A hands a task to agent B, B can prove it acts for A. A **delegation** is a statement signed by the
delegating agent's registered wallet (or owner, if the verifier allows owners), with the same EIP-191 / ERC-1271
rules as requests. UTF-8, lines joined with `\n`, no trailing newline:

```
erc8004-delegation/1
from: eip155:<chainId>:<agentId>        (the delegating agent)
to: eip155:<chainId>:<agentId>          (the agent allowed to act for it)
scope: <URL prefix, normalized as in §3 and without a query, or *>
methods: <upper-case HTTP methods, sorted, comma-separated, or *>
not-after: <unix seconds>
nonce: <16-128 characters from A-Z a-z 0-9 - _>
```

**Token.** A delegation travels as base64url (no padding) of compact JSON with exactly these keys, sorted:
`{"from","methods","nonce","not_after","scope","signature","to"}` — `not_after` an integer, `signature` 0x-hex.

**Header.** The calling agent signs its request as usual (§2–3) and adds
`ERC8004-Delegation: <token>,<token>,…` — one token per hop, **root first**.

**Verification.** In addition to §4, a verifier MUST reject the request unless:

1. There are 1–4 tokens, each well-formed.
2. Each token's `to` equals the next token's `from`; the last `to` equals `ERC8004-Agent`. No agent appears twice,
   and no token delegates an agent to itself.
3. For every token: `now ≤ not-after ≤ now + 30 days`; the request URL starts with `scope` at a path boundary
   (`scope` ends with `/`, or the next character is `/` or `?`, or the URL equals it); the request method is in
   `methods`.
4. Every token is signed by its `from` agent's `getAgentWallet` (or `ownerOf`, if allowed), read from the
   Identity Registry on that agent's chain.
5. The request nonce is recorded only after all of the above pass.

The **principal** is the first token's `from`: the agent the request is ultimately made for. Delegations are
capabilities, reusable until `not-after`; keep them short. Verifiers MAY keep a deny-list of revoked delegation
nonces (the reference libraries accept an `is_revoked` / `isRevoked` hook).

Test vectors: `vectors/delegation-v1.json`.
