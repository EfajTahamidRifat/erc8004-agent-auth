import base64
import json

import pytest
from eth_account import Account

from erc8004_agent_auth import (AuthError, IdentityRegistry, Verifier, decode_token, join_chain, sign_delegation,
                                sign_request)
from erc8004_agent_auth.delegation import MAX_CHAIN, scope_allows

from test_auth import AGENT_KEY, BODY, NOW, OWNER_KEY, STRANGER_KEY, URL, FakeChain

C_KEY = "0x" + "44" * 32


@pytest.fixture
def chain():
    fc = FakeChain()
    fc.agents[55] = {"owner": Account.from_key(C_KEY).address, "wallet": None}
    return fc


def verifier(chain, **kw):
    return Verifier(registries={8453: IdentityRegistry(transport=chain)}, clock=lambda: NOW, **kw)


def request(key, agent, chain_tokens, nonce="r" * 20, url=URL, method="POST"):
    h = sign_request(key, agent, method, url, BODY, timestamp=NOW, nonce=nonce)
    if chain_tokens:
        h["ERC8004-Delegation"] = join_chain(chain_tokens)
    return h


def delegate(key, frm, to, **kw):
    kw.setdefault("now", NOW)
    return sign_delegation(key, frm, to, **kw)


A, B, C = "eip155:8453:1203", "eip155:8453:77", "eip155:8453:55"


def test_one_hop(chain):
    d = delegate(AGENT_KEY, A, B, scope="https://api.example.com/v1/", methods="POST")
    r = verifier(chain).verify(request(OWNER_KEY, B, [d]), "POST", URL, BODY)
    assert r.ok and r.principal == A and r.delegation_chain == [A, B]
    assert any("acting for" in c for c in r.checks)


def test_two_hops(chain):
    d1 = delegate(AGENT_KEY, A, B)
    d2 = delegate(OWNER_KEY, B, C)
    r = verifier(chain).verify(request(C_KEY, C, [d1, d2]), "POST", URL, BODY)
    assert r.ok and r.principal == A and r.delegation_chain == [A, B, C]


def test_without_delegation_principal_is_empty(chain):
    r = verifier(chain).verify(request(AGENT_KEY, A, []), "POST", URL, BODY)
    assert r.ok and r.principal is None and r.delegation_chain == []


@pytest.mark.parametrize("make, reason", [
    (lambda: [delegate(AGENT_KEY, A, C)], "next agent"),                                    # delegated to someone else
    (lambda: [delegate(AGENT_KEY, A, B, not_after=NOW - 1)], "expired"),
    (lambda: [delegate(AGENT_KEY, A, B, scope="https://other.example.com/")], "does not cover"),
    (lambda: [delegate(AGENT_KEY, A, B, scope="https://api.example.com/v1/pa")], "does not cover"),  # not a path boundary
    (lambda: [delegate(AGENT_KEY, A, B, methods="GET")], "does not allow POST"),
    (lambda: [delegate(STRANGER_KEY, A, B)], "not signed by"),                                # forged
    (lambda: [delegate(AGENT_KEY, "eip155:8453:5", B)], "does not exist"),
    (lambda: [delegate(AGENT_KEY, A, B)] * (MAX_CHAIN + 1), "limited"),
    (lambda: ["not-a-token!"], "malformed"),
])
def test_bad_chains_are_refused(chain, make, reason):
    r = verifier(chain).verify(request(OWNER_KEY, B, make()), "POST", URL, BODY)
    assert not r.ok and reason in r.reason and r.reason.startswith("delegation:")


def test_tampered_token_is_refused(chain):
    d = json.loads(base64.urlsafe_b64decode(delegate(AGENT_KEY, A, B, scope="https://api.example.com/v1/") + "=="))
    d["scope"] = "*"                                         # widen it after signing
    forged = base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    r = verifier(chain).verify(request(OWNER_KEY, B, [forged]), "POST", URL, BODY)
    assert not r.ok and "not signed by" in r.reason


def test_loops_and_self_delegation_are_refused(chain):
    r = verifier(chain).verify(request(OWNER_KEY, B, [delegate(OWNER_KEY, B, B)]), "POST", URL, BODY)
    assert not r.ok and "itself" in r.reason
    loop = [delegate(OWNER_KEY, B, A), delegate(AGENT_KEY, A, B)]
    r = verifier(chain).verify(request(OWNER_KEY, B, loop), "POST", URL, BODY)
    assert not r.ok and "twice" in r.reason


def test_revocation_hook(chain):
    d = delegate(AGENT_KEY, A, B, nonce="revoked-nonce-0001")
    v = verifier(chain, is_revoked=lambda dd: dd["nonce"] == "revoked-nonce-0001")
    r = v.verify(request(OWNER_KEY, B, [d]), "POST", URL, BODY)
    assert not r.ok and "revoked" in r.reason


def test_failed_delegation_does_not_burn_the_request_nonce(chain):
    v = verifier(chain)
    assert not v.verify(request(OWNER_KEY, B, [delegate(STRANGER_KEY, A, B)]), "POST", URL, BODY).ok
    assert v.verify(request(OWNER_KEY, B, [delegate(AGENT_KEY, A, B)]), "POST", URL, BODY).ok


def test_lifetime_and_field_validation():
    with pytest.raises(AuthError):
        sign_delegation(AGENT_KEY, A, B, lifetime=31 * 86_400, now=NOW)
    with pytest.raises(AuthError):
        sign_delegation(AGENT_KEY, A, B, scope="https://a.io/x?y=1", now=NOW)
    with pytest.raises(AuthError):
        sign_delegation(AGENT_KEY, A, B, methods="G3T", now=NOW)
    d = decode_token(sign_delegation(AGENT_KEY, A, B, methods=["post", "get"], now=NOW))
    assert d["methods"] == "GET,POST" and d["from"] == A and d["to"] == B


def test_scope_matching():
    assert scope_allows("*", URL)
    assert scope_allows("https://api.example.com/v1/", "https://API.example.com:443/v1/pay?x=1")
    assert scope_allows("https://api.example.com/v1", "https://api.example.com/v1/pay")
    assert scope_allows("https://api.example.com/v1", "https://api.example.com/v1?x=1")
    assert not scope_allows("https://api.example.com/v1", "https://api.example.com/v10")
    assert not scope_allows("https://api.example.com/", "http://api.example.com/v1")
