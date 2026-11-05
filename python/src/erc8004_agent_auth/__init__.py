"""Sign and verify HTTP requests from ERC-8004 AI agents against the canonical on-chain Identity Registry.

    from erc8004_agent_auth import sign_request, Verifier
"""
from .core import MemoryNonceStore, Result, Verifier, read_delegation, read_headers, sign_request
from .delegation import DELEGATION_HEADER, DELEGATION_PROTOCOL, decode_token, join_chain, sign_delegation
from .message import (HEADERS, IDENTITY_REGISTRY, MAX_SKEW, PROTOCOL, AuthError, agent_ref, body_sha256,
                      canonical_message, normalize_url, parse_agent)
from .registry import IdentityRegistry, RpcError

__all__ = ["sign_request", "sign_delegation", "join_chain", "decode_token", "read_delegation",
           "DELEGATION_HEADER", "DELEGATION_PROTOCOL", "Verifier", "Result", "MemoryNonceStore", "read_headers", "IdentityRegistry", "RpcError",
           "AuthError", "canonical_message", "normalize_url", "body_sha256", "parse_agent", "agent_ref", "HEADERS",
           "PROTOCOL", "IDENTITY_REGISTRY", "MAX_SKEW"]
__version__ = "0.2.0"
