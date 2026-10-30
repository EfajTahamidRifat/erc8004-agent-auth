"""Sign and verify HTTP requests from ERC-8004 AI agents against the canonical on-chain Identity Registry.

    from erc8004_agent_auth import sign_request, Verifier
"""
from .core import MemoryNonceStore, Result, Verifier, read_headers, sign_request
from .message import (HEADERS, IDENTITY_REGISTRY, MAX_SKEW, PROTOCOL, AuthError, agent_ref, body_sha256,
                      canonical_message, normalize_url, parse_agent)
from .registry import IdentityRegistry, RpcError

__all__ = ["sign_request", "Verifier", "Result", "MemoryNonceStore", "read_headers", "IdentityRegistry", "RpcError",
           "AuthError", "canonical_message", "normalize_url", "body_sha256", "parse_agent", "agent_ref", "HEADERS",
           "PROTOCOL", "IDENTITY_REGISTRY", "MAX_SKEW"]
__version__ = "0.1.0"
