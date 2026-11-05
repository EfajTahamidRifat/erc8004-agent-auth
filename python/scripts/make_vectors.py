"""Regenerate vectors/v1.json. The keys are the well-known public Hardhat/Anvil test keys — never use them for funds."""
import json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
from eth_account import Account
from erc8004_agent_auth import body_sha256, canonical_message, normalize_url, sign_request

KEYS = ["0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"]
CASES = [
    dict(key=0, agent="eip155:8453:1203", method="GET", url="https://api.example.com/v1/quote?pair=ETH-USDC", body=""),
    dict(key=0, agent="eip155:1:7", method="post", url="HTTPS://API.Example.com:443/orders#frag", body='{"amount":"10","asset":"USDC"}'),
    dict(key=1, agent="eip155:8453:42", method="PUT", url="http://localhost:8080", body="hello"),
    dict(key=1, agent="eip155:84532:999999", method="DELETE", url="https://[2001:DB8::1]:8443/a%20b/c?x=1&y=%2F", body=""),
    dict(key=0, agent="eip155:10:0", method="PATCH", url="https://example.org/%C3%BCber?q=%C3%A9", body="ünïcödé ✓"),
]
URLS = [["https://Example.COM", "https://example.com/"], ["http://a.io:80/x?b=2&a=1", "http://a.io/x?b=2&a=1"],
        ["https://a.io:8443/p#f", "https://a.io:8443/p"], ["https://a.io/%7Euser", "https://a.io/%7Euser"]]
out = {"protocol": "erc8004-agent-auth/1", "note": "Public test keys only. timestamp 1767225600, nonces fixed.",
       "url_normalization": [{"input": i, "output": o} for i, o in URLS], "requests": []}
for n, c in enumerate(CASES):
    ts, nonce = 1767225600 + n, f"vector-nonce-{n:04d}-abcdef"
    h = sign_request(KEYS[c["key"]], c["agent"], c["method"], c["url"], c["body"], timestamp=ts, nonce=nonce)
    for i, o in URLS: assert normalize_url(i) == o, (i, normalize_url(i))
    out["requests"].append({**{k: v for k, v in c.items() if k != "key"}, "private_key": KEYS[c["key"]],
        "address": Account.from_key(KEYS[c["key"]]).address, "timestamp": ts, "nonce": nonce,
        "body_sha256": body_sha256(c["body"]),
        "message": canonical_message(c["agent"], c["method"], c["url"], ts, nonce, body_sha256(c["body"])),
        "headers": h})
path = pathlib.Path(__file__).resolve().parents[2] / "vectors" / "v1.json"
path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
print("wrote", path)

# ── delegation vectors ───────────────────────────────────────────────
from erc8004_agent_auth import decode_token, sign_delegation
from erc8004_agent_auth.delegation import delegation_message

DCASES = [
    dict(key=0, frm="eip155:8453:1203", to="eip155:8453:77", scope="https://API.example.com:443/v1/", methods="post,get", not_after=1767229200),
    dict(key=1, frm="eip155:8453:77", to="eip155:1:7", scope="*", methods="*", not_after=1767232800),
]
dout = {"protocol": "erc8004-delegation/1", "note": "Public test keys only. Tokens are base64url JSON without padding.",
        "delegations": []}
for n, c in enumerate(DCASES):
    nonce = f"delegation-nonce-{n:04d}"
    tok = sign_delegation(KEYS[c["key"]], c["frm"], c["to"], c["scope"], c["methods"], not_after=c["not_after"],
                          nonce=nonce, now=c["not_after"] - 3600)
    d = decode_token(tok)
    dout["delegations"].append({"private_key": KEYS[c["key"]], "address": Account.from_key(KEYS[c["key"]]).address,
                                "input": {**{k: v for k, v in c.items() if k != "key"}, "nonce": nonce},
                                "message": delegation_message(d), "token": tok, "decoded": d})
dpath = pathlib.Path(__file__).resolve().parents[2] / "vectors" / "delegation-v1.json"
dpath.write_text(json.dumps(dout, indent=2, ensure_ascii=False) + "\n")
print("wrote", dpath)
