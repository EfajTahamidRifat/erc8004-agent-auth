"""Signing (agent side) and verification (server side)."""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field

from eth_account import Account
from eth_account.messages import _hash_eip191_message, encode_defunct
from eth_utils import to_checksum_address

from .message import (HEADERS, MAX_SKEW, NONCE_RE, NONCE_TTL, PROTOCOL, SIG_RE, AuthError, agent_ref,
                      body_sha256, canonical_message, parse_agent)
from .registry import IdentityRegistry, RpcError


# ── agent side ──────────────────────────────────────────────────────
def sign_request(private_key, agent: str, method: str, url: str, body=b"", *, timestamp: int | None = None,
                 nonce: str | None = None) -> dict:
    """The four headers an agent adds to a request. Never send the private key anywhere."""
    chain_id, agent_id = parse_agent(agent)
    ref = agent_ref(chain_id, agent_id)
    timestamp = int(timestamp if timestamp is not None else time.time())
    nonce = nonce or secrets.token_urlsafe(18)
    message = canonical_message(ref, method, url, timestamp, nonce, body_sha256(body))
    sig = Account.sign_message(encode_defunct(text=message), private_key).signature.hex()
    return {HEADERS["agent"]: ref, HEADERS["timestamp"]: str(timestamp), HEADERS["nonce"]: nonce,
            HEADERS["signature"]: sig if sig.startswith("0x") else "0x" + sig}


# ── replay protection ───────────────────────────────────────────────
class MemoryNonceStore:
    """Remembers nonces in memory for NONCE_TTL seconds. Fine for one process; for several servers, implement
    `use(key, now) -> bool` on top of Redis (SET NX EX) or a database unique index."""

    def __init__(self, ttl: int = NONCE_TTL, max_entries: int = 1_000_000):
        self.ttl, self.max_entries = ttl, max_entries
        self._seen: dict[str, int] = {}
        self._lock = threading.Lock()

    def use(self, key: str, now: int) -> bool:
        """Record the nonce; False if it was already used within the TTL."""
        with self._lock:
            if len(self._seen) >= self.max_entries:
                self._seen = {k: t for k, t in self._seen.items() if now - t < self.ttl}
                if len(self._seen) >= self.max_entries:        # still full: refuse rather than forget
                    return False
            seen = self._seen.get(key)
            if seen is not None and now - seen < self.ttl:
                return False
            self._seen[key] = now
            return True


# ── server side ─────────────────────────────────────────────────────
@dataclass
class Result:
    ok: bool
    reason: str
    agent: str | None = None
    chain_id: int | None = None
    agent_id: int | None = None
    signer: str | None = None
    role: str | None = None              # "agent_wallet" | "owner"
    checks: list = field(default_factory=list)

    def __bool__(self):
        return self.ok


def read_headers(headers) -> dict:
    """Case-insensitive lookup of the four headers from any mapping (dict, Flask/Django/Starlette headers)."""
    lower = {str(k).lower(): v for k, v in dict(headers or {}).items()}
    return {key: (str(lower[name.lower()]) if name.lower() in lower else None) for key, name in HEADERS.items()}


class Verifier:
    """Verifies v1 signed requests against one chain's canonical Identity Registry.

        verifier = Verifier({8453: "https://base-mainnet.example/rpc"})
        result = verifier.verify(request.headers, request.method, request.url, request.get_data())
        if not result:
            return 401, result.reason
    """

    def __init__(self, rpc_urls: dict | None = None, *, registries: dict | None = None, nonce_store=None,
                 allow_owner: bool = True, max_skew: int = MAX_SKEW, protocol: str = PROTOCOL, clock=time.time):
        self.registries = dict(registries or {})
        for chain_id, url in (rpc_urls or {}).items():
            self.registries.setdefault(int(chain_id), IdentityRegistry(url))
        self.nonces = nonce_store or MemoryNonceStore()
        self.allow_owner = allow_owner
        self.max_skew = min(int(max_skew), MAX_SKEW)
        self.protocol = protocol
        self.clock = clock

    def verify(self, headers, method: str, url: str, body=b"") -> Result:
        h = read_headers(headers)
        missing = [HEADERS[k] for k, v in h.items() if not v]
        if missing:
            return Result(False, f"missing header(s): {', '.join(missing)}")
        try:
            chain_id, agent_id = parse_agent(h["agent"])
        except AuthError as exc:
            return Result(False, str(exc))
        ref = agent_ref(chain_id, agent_id)
        base = {"agent": ref, "chain_id": chain_id, "agent_id": agent_id}
        checks = []
        if not h["timestamp"].isdigit() or len(h["timestamp"]) > 12:
            return Result(False, "timestamp must be unix seconds", **base)
        if not NONCE_RE.match(h["nonce"]):
            return Result(False, "nonce must be 16-128 characters from A-Z a-z 0-9 - _", **base)
        if not SIG_RE.match(h["signature"]) or len(h["signature"]) > 2 + 2 * 4096 or len(h["signature"]) % 2:
            return Result(False, "signature must be 0x-prefixed hex", **base)
        now = int(self.clock())
        skew = abs(now - int(h["timestamp"]))
        if skew > self.max_skew:
            return Result(False, f"request was signed {skew}s from now (limit {self.max_skew}s): clock skew or replay",
                          **base)
        checks.append("timestamp is fresh")
        try:
            message = canonical_message(ref, method, url, int(h["timestamp"]), h["nonce"], body_sha256(body),
                                        protocol=self.protocol)
        except AuthError as exc:
            return Result(False, str(exc), **base)
        registry = self.registries.get(chain_id)
        if registry is None:
            return Result(False, f"no RPC configured for chain {chain_id}", **base)
        try:
            owner = registry.owner_of(agent_id)
            if owner is None:
                return Result(False, "this agent does not exist in the Identity Registry", **base, checks=checks)
            wallet = registry.agent_wallet(agent_id)
            signer, role = self._match(registry, message, h["signature"], wallet, owner)
        except RpcError as exc:
            return Result(False, f"could not read the registry: {exc}", **base, checks=checks)
        if not role:
            return Result(False, "signature was not made by the agent's registered wallet"
                          + (" or owner" if self.allow_owner else ""), **base, signer=signer, checks=checks)
        checks.append("signed by the agent's " + ("verified agent wallet" if role == "agent_wallet" else "owner"))
        if not self.nonces.use(f"{ref}|{h['nonce']}", now):
            return Result(False, "nonce already used (replay blocked)", **base, signer=signer, role=role, checks=checks)
        checks.append("nonce is new")
        return Result(True, "verified", **base, signer=signer, role=role, checks=checks)

    def _match(self, registry, message: str, signature: str, wallet, owner):
        candidates = [("agent_wallet", wallet)] + ([("owner", owner)] if self.allow_owner else [])
        candidates = [(role, to_checksum_address(addr)) for role, addr in candidates if addr]
        sig = bytes.fromhex(signature[2:])
        signer = None
        if len(sig) == 65:
            try:
                signer = to_checksum_address(Account.recover_message(encode_defunct(text=message), signature=sig))
            except Exception:  # noqa: BLE001 — malformed signature: fall through to ERC-1271
                signer = None
            for role, addr in candidates:
                if signer == addr:
                    return signer, role
        # Smart-contract wallets (ERC-1271): ask the wallet itself.
        digest = _hash_eip191_message(encode_defunct(text=message))
        for role, addr in candidates:
            if registry.erc1271_valid(addr, digest, sig):
                return addr, role
        return signer, None
