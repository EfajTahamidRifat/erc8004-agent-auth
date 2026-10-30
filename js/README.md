# erc8004-agent-auth (JavaScript)

Sign and verify HTTP requests from ERC-8004 AI agents against the canonical on-chain Identity Registry.
See the [main README](https://github.com/EfajTahamidRifat/erc8004-agent-auth) and [SPEC.md](https://github.com/EfajTahamidRifat/erc8004-agent-auth/blob/main/SPEC.md).

```js
import { signRequest, Verifier } from "erc8004-agent-auth";

const headers = await signRequest(signer, "eip155:8453:1203", "POST", url, body);       // agent
const result = await new Verifier({ rpcUrls: { 8453: rpcUrl } }).verify(headers, "POST", url, body); // server
```

ESM, Node 18+, Bun, Deno, Cloudflare Workers and browsers. Peer dependency: `ethers` v6.
