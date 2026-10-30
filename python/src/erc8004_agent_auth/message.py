"""The v1 signed message: agent reference, URL normalization, body hash and the canonical text."""
from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit, urlunsplit

PROTOCOL = "erc8004-agent-auth/1"
HEADERS = {"agent": "ERC8004-Agent", "timestamp": "ERC8004-Timestamp", "nonce": "ERC8004-Nonce",
           "signature": "ERC8004-Signature"}
IDENTITY_REGISTRY = "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432"
MAX_SKEW = 300                 # seconds
NONCE_TTL = 15 * 60            # seconds a nonce must be remembered
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
SIG_RE = re.compile(r"^0x[0-9a-fA-F]+$")
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class AuthError(ValueError):
    """A request or argument that can't be part of a valid v1 signature."""


def parse_agent(ref: str) -> tuple[int, int]:
    """'eip155:8453:1203' → (8453, 1203)."""
    parts = str(ref or "").strip().split(":")
    if len(parts) != 3 or parts[0] != "eip155" or not all(p.isdigit() and len(p) <= 78 for p in parts[1:]):
        raise AuthError("agent must look like eip155:<chainId>:<agentId>, for example eip155:8453:1203")
    chain_id, agent_id = int(parts[1]), int(parts[2])
    if chain_id <= 0 or agent_id >= 2 ** 256:
        raise AuthError("chain id or agent id out of range")
    return chain_id, agent_id


def agent_ref(chain_id: int, agent_id: int) -> str:
    return f"eip155:{int(chain_id)}:{int(agent_id)}"


def normalize_url(url: str) -> str:
    """Lower-case scheme and host, drop default ports and fragments; keep path and query exactly."""
    parts = urlsplit(str(url or "").strip())
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname:
        raise AuthError("url must be the full http(s) URL of the request")
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:
        raise AuthError("url has an invalid port") from None
    netloc = host if port is None or (scheme, port) in (("https", 443), ("http", 80)) else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def body_sha256(body) -> str:
    """Lower-case hex SHA-256 of the raw body (bytes or str; None means empty)."""
    if body is None:
        body = b""
    if isinstance(body, str):
        body = body.encode("utf-8")
    if not isinstance(body, (bytes, bytearray, memoryview)):
        raise AuthError("body must be the raw request body (bytes or str)")
    return hashlib.sha256(bytes(body)).hexdigest()


def canonical_message(agent: str, method: str, url: str, timestamp: int, nonce: str, body_hash: str,
                      protocol: str = PROTOCOL) -> str:
    chain_id, agent_id = parse_agent(agent)
    method = str(method or "").upper()
    if not method.isalpha():
        raise AuthError("method must be an HTTP method such as GET or POST")
    if not NONCE_RE.match(str(nonce or "")):
        raise AuthError("nonce must be 16-128 characters from A-Z a-z 0-9 - _")
    if not re.fullmatch(r"[0-9a-f]{64}", str(body_hash or "")):
        raise AuthError("body hash must be lower-case hex SHA-256")
    return "\n".join([
        protocol,
        f"agent: {agent_ref(chain_id, agent_id)}",
        f"method: {method}",
        f"url: {normalize_url(url)}",
        f"timestamp: {int(timestamp)}",
        f"nonce: {nonce}",
        f"body-sha256: {body_hash}",
    ])
