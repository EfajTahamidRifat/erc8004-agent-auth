"""Read an agent's owner and wallet straight from the canonical ERC-8004 Identity Registry over JSON-RPC.

Only the Python standard library is used for HTTP, so the package works anywhere. Pass your own `transport`
(a function taking a JSON-RPC payload dict and returning the parsed response) to use another HTTP client.
"""
from __future__ import annotations

import json
import urllib.request

from eth_abi import decode, encode
from eth_utils import keccak, to_checksum_address

from .message import IDENTITY_REGISTRY

OWNER_OF = keccak(text="ownerOf(uint256)")[:4]
GET_AGENT_WALLET = keccak(text="getAgentWallet(uint256)")[:4]
IS_VALID_SIGNATURE = keccak(text="isValidSignature(bytes32,bytes)")[:4]
ERC1271_MAGIC = bytes.fromhex("1626ba7e")
ZERO = "0x" + "00" * 20


class RpcError(Exception):
    """The RPC endpoint failed or answered with something unexpected (not an on-chain revert)."""


class Reverted(Exception):
    """The contract call reverted (for ownerOf: the agent does not exist)."""


def http_transport(url: str, timeout: float = 10.0):
    def send(payload: dict) -> dict:
        req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": "erc8004-agent-auth/0.1"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:   # noqa: S310 — URL is the caller's RPC
                return json.loads(resp.read(5_000_000))
        except Exception as exc:  # noqa: BLE001
            raise RpcError(f"RPC request failed: {exc}") from exc
    return send


class IdentityRegistry:
    def __init__(self, rpc_url: str | None = None, *, transport=None, address: str = IDENTITY_REGISTRY):
        if not (rpc_url or transport):
            raise ValueError("give an rpc_url or a transport")
        self.send = transport or http_transport(rpc_url)
        self.address = to_checksum_address(address)
        self._id = 0

    def _call(self, to: str, data: bytes) -> bytes:
        self._id += 1
        reply = self.send({"jsonrpc": "2.0", "id": self._id, "method": "eth_call",
                           "params": [{"to": to, "data": "0x" + data.hex()}, "latest"]})
        if not isinstance(reply, dict):
            raise RpcError("unexpected RPC reply")
        if reply.get("error"):
            err = reply["error"]
            message = str(err.get("message", err) if isinstance(err, dict) else err)
            if "revert" in message.lower() or (isinstance(err, dict) and err.get("code") == 3):
                raise Reverted(message)
            raise RpcError(message[:300])
        result = reply.get("result")
        if not isinstance(result, str) or not result.startswith("0x"):
            raise RpcError("unexpected eth_call result")
        return bytes.fromhex(result[2:])

    def owner_of(self, agent_id: int) -> str | None:
        """The agent NFT's owner, or None if the agent doesn't exist."""
        try:
            raw = self._call(self.address, OWNER_OF + encode(["uint256"], [int(agent_id)]))
        except Reverted:
            return None
        if len(raw) < 32:
            return None
        owner = to_checksum_address(decode(["address"], raw[:32])[0])
        return None if owner == to_checksum_address(ZERO) else owner

    def agent_wallet(self, agent_id: int) -> str | None:
        """The verified agent wallet, or None if none is set (it is cleared when the agent is transferred)."""
        try:
            raw = self._call(self.address, GET_AGENT_WALLET + encode(["uint256"], [int(agent_id)]))
        except Reverted:
            return None
        if len(raw) < 32:
            return None
        wallet = to_checksum_address(decode(["address"], raw[:32])[0])
        return None if wallet == to_checksum_address(ZERO) else wallet

    def erc1271_valid(self, wallet: str, digest: bytes, signature: bytes) -> bool:
        """True if `wallet` is a smart-contract wallet that accepts this signature for this hash."""
        try:
            raw = self._call(to_checksum_address(wallet),
                             IS_VALID_SIGNATURE + encode(["bytes32", "bytes"], [digest, signature]))
        except Reverted:
            return False
        return len(raw) >= 4 and raw[:4] == ERC1271_MAGIC
