import json
import pathlib

import pytest
from eth_abi import decode, encode
from eth_account import Account

from erc8004_agent_auth import (AuthError, IdentityRegistry, MemoryNonceStore, Verifier, body_sha256,
                                canonical_message, normalize_url, parse_agent, sign_request)
from erc8004_agent_auth.registry import ERC1271_MAGIC, GET_AGENT_WALLET, IS_VALID_SIGNATURE, OWNER_OF, RpcError

VECTORS = json.loads((pathlib.Path(__file__).resolve().parents[2] / "vectors" / "v1.json").read_text())
REG = "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432"
AGENT_KEY = "0x" + "11" * 32
OWNER_KEY = "0x" + "22" * 32
STRANGER_KEY = "0x" + "33" * 32
SAFE = "0x" + "5a" * 20                     # a pretend smart-contract wallet
NOW = 1_800_000_000
URL = "https://api.example.com/v1/pay"
BODY = b'{"amount":"5"}'


class FakeChain:
    """Answers eth_call like the Identity Registry (and one ERC-1271 wallet) would."""

    def __init__(self):
        self.agents = {1203: {"owner": Account.from_key(OWNER_KEY).address,
                              "wallet": Account.from_key(AGENT_KEY).address},
                       77: {"owner": Account.from_key(OWNER_KEY).address, "wallet": None},
                       88: {"owner": Account.from_key(OWNER_KEY).address, "wallet": SAFE}}
        self.safe_accepts = set()
        self.calls = 0
        self.down = False

    def __call__(self, payload):
        self.calls += 1
        if self.down:
            raise RpcError("connection refused")
        call = payload["params"][0]
        data = bytes.fromhex(call["data"][2:])
        sel, args = data[:4], data[4:]
        if call["to"].lower() == REG.lower():
            (agent_id,) = decode(["uint256"], args)
            agent = self.agents.get(agent_id)
            if sel == OWNER_OF:
                if not agent:
                    return {"jsonrpc": "2.0", "id": 1, "error": {"code": 3, "message": "execution reverted"}}
                return {"jsonrpc": "2.0", "id": 1, "result": "0x" + encode(["address"], [agent["owner"]]).hex()}
            if sel == GET_AGENT_WALLET:
                wallet = (agent or {}).get("wallet") or "0x" + "00" * 20
                return {"jsonrpc": "2.0", "id": 1, "result": "0x" + encode(["address"], [wallet]).hex()}
        if call["to"].lower() == SAFE.lower() and sel == IS_VALID_SIGNATURE:
            digest, sig = decode(["bytes32", "bytes"], args)
            ok = (digest, sig) in self.safe_accepts
            return {"jsonrpc": "2.0", "id": 1, "result": "0x" + (ERC1271_MAGIC if ok else b"\0" * 4).ljust(32, b"\0").hex()}
        return {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "execution reverted"}}


@pytest.fixture
def chain():
    return FakeChain()


def make_verifier(chain, **kw):
    return Verifier(registries={8453: IdentityRegistry(transport=chain)}, clock=lambda: NOW, **kw)


def signed(key=AGENT_KEY, agent="eip155:8453:1203", method="POST", url=URL, body=BODY, ts=NOW, nonce=None):
    return sign_request(key, agent, method, url, body, timestamp=ts, nonce=nonce or "n" * 20)


# ── vectors ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("case", VECTORS["requests"], ids=lambda c: c["agent"])
def test_vectors(case):
    assert body_sha256(case["body"]) == case["body_sha256"]
    msg = canonical_message(case["agent"], case["method"], case["url"], case["timestamp"], case["nonce"],
                            case["body_sha256"])
    assert msg == case["message"]
    headers = sign_request(case["private_key"], case["agent"], case["method"], case["url"], case["body"],
                           timestamp=case["timestamp"], nonce=case["nonce"])
    assert headers == case["headers"]


@pytest.mark.parametrize("pair", VECTORS["url_normalization"], ids=lambda p: p["input"])
def test_url_vectors(pair):
    assert normalize_url(pair["input"]) == pair["output"]


# ── parsing ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("bad", ["", "8453:1", "eip155:8453", "eip155:0:1", "eip155:x:1", "eip155:1:-1",
                                 "eip155:1:1:1", "cosmos:1:1", f"eip155:1:{2**256}"])
def test_bad_agent_refs(bad):
    with pytest.raises(AuthError):
        parse_agent(bad)


@pytest.mark.parametrize("bad", ["ftp://a.io/x", "/relative", "https://", "https://a.io:99999/"])
def test_bad_urls(bad):
    with pytest.raises(AuthError):
        normalize_url(bad)


def test_bad_nonce_rejected_when_signing():
    with pytest.raises(AuthError):
        sign_request(AGENT_KEY, "eip155:8453:1", "GET", URL, nonce="short")


# ── verification ─────────────────────────────────────────────────────
def test_agent_wallet_signature_verifies(chain):
    r = make_verifier(chain).verify(signed(), "POST", URL, BODY)
    assert r.ok and r.role == "agent_wallet" and r.agent == "eip155:8453:1203"
    assert r.signer == Account.from_key(AGENT_KEY).address
    assert "nonce is new" in r.checks


def test_lowercase_header_names_and_url_variants(chain):
    h = {k.lower(): v for k, v in signed().items()}
    assert make_verifier(chain).verify(h, "post", "HTTPS://API.EXAMPLE.COM:443/v1/pay", BODY).ok


def test_owner_signature(chain):
    assert make_verifier(chain).verify(signed(key=OWNER_KEY), "POST", URL, BODY).role == "owner"


def test_owner_can_be_disallowed(chain):
    r = make_verifier(chain, allow_owner=False).verify(signed(key=OWNER_KEY), "POST", URL, BODY)
    assert not r.ok and "registered wallet" in r.reason


def test_agent_without_wallet_accepts_owner_only(chain):
    v = make_verifier(chain)
    assert v.verify(signed(key=OWNER_KEY, agent="eip155:8453:77"), "POST", URL, BODY).role == "owner"
    assert not v.verify(signed(agent="eip155:8453:77", nonce="m" * 20), "POST", URL, BODY).ok


def test_stranger_rejected(chain):
    r = make_verifier(chain).verify(signed(key=STRANGER_KEY), "POST", URL, BODY)
    assert not r.ok and r.signer == Account.from_key(STRANGER_KEY).address


def test_unknown_agent(chain):
    r = make_verifier(chain).verify(signed(agent="eip155:8453:5"), "POST", URL, BODY)
    assert not r.ok and "does not exist" in r.reason


def test_unknown_chain(chain):
    r = make_verifier(chain).verify(signed(agent="eip155:1:1203"), "POST", URL, BODY)
    assert not r.ok and "no RPC configured for chain 1" in r.reason


@pytest.mark.parametrize("change", [
    {"method": "GET"}, {"url": "https://api.example.com/v1/pay?x=1"}, {"url": "https://evil.example.com/v1/pay"},
    {"body": b'{"amount":"500"}'},
])
def test_tampering_breaks_signature(chain, change):
    args = {"method": "POST", "url": URL, "body": BODY, **change}
    assert not make_verifier(chain).verify(signed(), **args).ok


def test_replay_blocked(chain):
    v, h = make_verifier(chain), signed()
    assert v.verify(h, "POST", URL, BODY).ok
    r = v.verify(h, "POST", URL, BODY)
    assert not r.ok and "replay" in r.reason


def test_failed_attempt_does_not_burn_nonce(chain):
    v = make_verifier(chain)
    assert not v.verify(signed(key=STRANGER_KEY), "POST", URL, BODY).ok
    assert v.verify(signed(), "POST", URL, BODY).ok


@pytest.mark.parametrize("ts", [NOW - 301, NOW + 301])
def test_stale_or_future_timestamp(chain, ts):
    r = make_verifier(chain).verify(signed(ts=ts), "POST", URL, BODY)
    assert not r.ok and "clock skew" in r.reason
    assert chain.calls == 0          # rejected before any RPC call


def test_skew_cannot_be_widened(chain):
    assert make_verifier(chain, max_skew=10_000).max_skew == 300


@pytest.mark.parametrize("field,value", [("ERC8004-Timestamp", "soon"), ("ERC8004-Nonce", "bad nonce!"),
                                         ("ERC8004-Signature", "not-hex"), ("ERC8004-Signature", "0xabc"), ("ERC8004-Agent", "eip155:abc")])
def test_malformed_headers(chain, field, value):
    h = signed()
    h[field] = value
    assert not make_verifier(chain).verify(h, "POST", URL, BODY).ok
    assert chain.calls == 0


def test_missing_headers(chain):
    h = signed()
    del h["ERC8004-Signature"]
    r = make_verifier(chain).verify(h, "POST", URL, BODY)
    assert not r.ok and "ERC8004-Signature" in r.reason


def test_rpc_down_fails_closed(chain):
    chain.down = True
    r = make_verifier(chain).verify(signed(), "POST", URL, BODY)
    assert not r.ok and "could not read the registry" in r.reason


def test_erc1271_smart_wallet(chain):
    from eth_account.messages import _hash_eip191_message, encode_defunct
    h = sign_request(STRANGER_KEY, "eip155:8453:88", "POST", URL, BODY, timestamp=NOW, nonce="s" * 20)
    msg = canonical_message("eip155:8453:88", "POST", URL, NOW, "s" * 20, body_sha256(BODY))
    digest = _hash_eip191_message(encode_defunct(text=msg))
    sig = bytes.fromhex(h["ERC8004-Signature"][2:])
    v = make_verifier(chain)
    assert not v.verify(h, "POST", URL, BODY).ok             # wallet hasn't approved this signature
    chain.safe_accepts.add((digest, sig))
    h["ERC8004-Nonce"] = "s" * 20
    r = v.verify(h, "POST", URL, BODY)
    assert r.ok and r.role == "agent_wallet" and r.signer.lower() == SAFE.lower()


def test_nonce_store_ttl_and_capacity():
    store = MemoryNonceStore(ttl=10, max_entries=2)
    assert store.use("a", 0) and not store.use("a", 5) and store.use("a", 11)
    assert store.use("b", 11)
    assert not store.use("c", 12)          # full of live nonces: refuse rather than forget
    assert store.use("c", 30)              # old ones expired


def test_compat_protocol_string(chain):
    """Servers can verify a differently-named protocol line (e.g. a vendor's earlier version)."""
    from eth_account.messages import encode_defunct
    msg = canonical_message("eip155:8453:1203", "GET", URL, NOW, "c" * 20, body_sha256(b""),
                            protocol="neptuv-agent-auth/1")
    sig = Account.sign_message(encode_defunct(text=msg), AGENT_KEY).signature.hex()
    h = {"ERC8004-Agent": "eip155:8453:1203", "ERC8004-Timestamp": str(NOW), "ERC8004-Nonce": "c" * 20,
         "ERC8004-Signature": sig if sig.startswith("0x") else "0x" + sig}
    assert make_verifier(chain, protocol="neptuv-agent-auth/1").verify(h, "GET", URL, b"").ok
    assert not make_verifier(chain).verify(h, "GET", URL, b"").ok
