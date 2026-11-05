"""Delegation chains (erc8004-delegation/1): when agent A hands work to agent B, B can prove it acts for A.

A delegation is a short statement signed by the delegating agent's registered wallet (or owner):

    erc8004-delegation/1
    from: eip155:8453:1203
    to: eip155:8453:77
    scope: https://api.example.com/v1/
    methods: GET,POST
    not-after: 1767229200
    nonce: 9cQ2…

B sends its request signed as usual (ERC8004-* headers) plus ERC8004-Delegation: one token per hop, root first,
comma-separated. The verifier checks every hop against the Identity Registry of that hop's chain.
"""
from __future__ import annotations

import base64
import json
import re
import secrets
import time

from eth_account import Account
from eth_account.messages import encode_defunct

from .message import NONCE_RE, AuthError, agent_ref, normalize_url, parse_agent

DELEGATION_PROTOCOL = "erc8004-delegation/1"
DELEGATION_HEADER = "ERC8004-Delegation"
MAX_CHAIN = 4                    # hops; longer chains are refused
MAX_LIFETIME = 30 * 86_400       # a delegation may last at most 30 days
MAX_TOKEN_CHARS = 2048
METHOD_RE = re.compile(r"^[A-Z]{1,16}$")
FIELDS = ("from", "to", "scope", "methods", "not_after", "nonce", "signature")


def normalize_scope(scope: str) -> str:
    """'*' or an http(s) URL prefix (normalized like request URLs, without query)."""
    scope = str(scope or "").strip()
    if scope == "*":
        return scope
    norm = normalize_url(scope)
    if "?" in norm:
        raise AuthError("a delegation scope is a URL prefix without a query string")
    return norm


def normalize_methods(methods) -> str:
    if methods in (None, "", "*", ["*"]):
        return "*"
    items = methods.split(",") if isinstance(methods, str) else list(methods)
    out = sorted({str(m).strip().upper() for m in items if str(m).strip()})
    if not out or not all(METHOD_RE.match(m) for m in out):
        raise AuthError("methods must be HTTP methods such as GET,POST or *")
    return ",".join(out)


def delegation_message(d: dict) -> str:
    frm, to = agent_ref(*parse_agent(d["from"])), agent_ref(*parse_agent(d["to"]))
    if not NONCE_RE.match(str(d.get("nonce") or "")):
        raise AuthError("delegation nonce must be 16-128 characters from A-Z a-z 0-9 - _")
    if not str(d.get("not_after", "")).isdigit():
        raise AuthError("not_after must be unix seconds")
    return "\n".join([
        DELEGATION_PROTOCOL,
        f"from: {frm}",
        f"to: {to}",
        f"scope: {normalize_scope(d['scope'])}",
        f"methods: {normalize_methods(d['methods'])}",
        f"not-after: {int(d['not_after'])}",
        f"nonce: {d['nonce']}",
    ])


def encode_token(d: dict) -> str:
    body = json.dumps({k: d[k] for k in FIELDS}, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(body).decode().rstrip("=")


def decode_token(token: str) -> dict:
    token = str(token or "").strip()
    if not token or len(token) > MAX_TOKEN_CHARS or not re.fullmatch(r"[A-Za-z0-9_-]+", token):
        raise AuthError("malformed delegation token")
    try:
        d = json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))
    except ValueError:
        raise AuthError("malformed delegation token") from None
    if not isinstance(d, dict) or set(d) != set(FIELDS):
        raise AuthError("delegation token must hold exactly: " + ", ".join(FIELDS))
    if not isinstance(d["not_after"], int) or not isinstance(d["signature"], str):
        raise AuthError("malformed delegation token")
    return d


def sign_delegation(private_key, from_agent: str, to_agent: str, scope: str = "*", methods="*",
                    lifetime: int = 3600, *, not_after: int | None = None, nonce: str | None = None,
                    now: int | None = None) -> str:
    """A delegation token from `from_agent` (signed by its registered wallet or owner) to `to_agent`."""
    now = int(now if now is not None else time.time())
    not_after = int(not_after if not_after is not None else now + int(lifetime))
    if not_after - now > MAX_LIFETIME:
        raise AuthError("a delegation may last at most 30 days")
    d = {"from": agent_ref(*parse_agent(from_agent)), "to": agent_ref(*parse_agent(to_agent)),
         "scope": normalize_scope(scope), "methods": normalize_methods(methods), "not_after": not_after,
         "nonce": nonce or secrets.token_urlsafe(18)}
    sig = Account.sign_message(encode_defunct(text=delegation_message(d)), private_key).signature.hex()
    d["signature"] = sig if sig.startswith("0x") else "0x" + sig
    return encode_token(d)


def join_chain(tokens) -> str:
    """Header value for a chain of tokens, root first."""
    return ",".join(tokens)


def scope_allows(scope: str, url: str) -> bool:
    if scope == "*":
        return True
    target = normalize_url(url)
    if not target.startswith(scope):
        return False
    rest = target[len(scope):]
    return scope.endswith("/") or rest == "" or rest[0] in "/?"
