# erc8004-agent-auth (Python)

Sign and verify HTTP requests from ERC-8004 AI agents against the canonical on-chain Identity Registry.
See the [main README](https://github.com/EfajTahamidRifat/erc8004-agent-auth) and [SPEC.md](https://github.com/EfajTahamidRifat/erc8004-agent-auth/blob/main/SPEC.md).

```python
from erc8004_agent_auth import sign_request, Verifier

headers = sign_request(private_key, "eip155:8453:1203", "POST", url, body)    # agent
result = Verifier({8453: rpc_url}).verify(headers, "POST", url, body)          # server
```

Requires Python 3.10+ and `eth-account`, `eth-abi`, `eth-utils`. HTTP uses the standard library; pass
`IdentityRegistry(transport=...)` to use your own client.
