// Sign and verify HTTP requests from ERC-8004 AI agents against the canonical on-chain Identity Registry.
// Spec: ../SPEC.md (erc8004-agent-auth/1). Works in Node 18+, Deno, Bun, browsers and edge runtimes.
import { AbiCoder, Wallet, decodeBase64, encodeBase64, getAddress, getBytes, hashMessage, hexlify, id, randomBytes,
  recoverAddress, sha256, toUtf8Bytes, toUtf8String, ZeroAddress } from "ethers";

export const PROTOCOL = "erc8004-agent-auth/1";
export const HEADERS = { agent: "ERC8004-Agent", timestamp: "ERC8004-Timestamp", nonce: "ERC8004-Nonce",
  signature: "ERC8004-Signature" };
export const IDENTITY_REGISTRY = "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432";
export const MAX_SKEW = 300;
export const NONCE_TTL = 15 * 60;
const NONCE_RE = /^[A-Za-z0-9_-]{16,128}$/;
const SIG_RE = /^0x[0-9a-fA-F]+$/;
const abi = AbiCoder.defaultAbiCoder();
const sel = (sig) => id(sig).slice(0, 10);
const OWNER_OF = sel("ownerOf(uint256)");
const GET_AGENT_WALLET = sel("getAgentWallet(uint256)");
const IS_VALID_SIGNATURE = sel("isValidSignature(bytes32,bytes)");
const ERC1271_MAGIC = "0x1626ba7e";

export class AuthError extends Error {}
export class RpcError extends Error {}
class Reverted extends Error {}

// ── message ──────────────────────────────────────────────────────────
export function parseAgent(ref) {
  const parts = String(ref ?? "").trim().split(":");
  if (parts.length !== 3 || parts[0] !== "eip155" || !parts.slice(1).every((p) => /^\d{1,78}$/.test(p))) {
    throw new AuthError("agent must look like eip155:<chainId>:<agentId>, for example eip155:8453:1203");
  }
  const chainId = BigInt(parts[1]), agentId = BigInt(parts[2]);
  if (chainId <= 0n || agentId >= 2n ** 256n) throw new AuthError("chain id or agent id out of range");
  return { chainId, agentId };
}

export const agentRef = (chainId, agentId) => `eip155:${BigInt(chainId)}:${BigInt(agentId)}`;

export function normalizeUrl(url) {
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)([^?#]*)(?:\?([^#]*))?(?:#.*)?$/s.exec(String(url ?? "").trim());
  const scheme = m ? m[1].toLowerCase() : "";
  if (!m || (scheme !== "http" && scheme !== "https")) throw new AuthError("url must be the full http(s) URL of the request");
  const authority = m[2].slice(m[2].lastIndexOf("@") + 1);           // userinfo is never part of the signed URL
  const hm = /^(\[[^\]]*\]|[^:]*)(?::(.*))?$/.exec(authority);
  let host = (hm?.[1] ?? "").toLowerCase();
  const rawPort = hm?.[2] ?? "";
  if (host.startsWith("[")) host = host.slice(1, -1);
  if (!host) throw new AuthError("url must be the full http(s) URL of the request");
  if (host.includes(":")) host = `[${host}]`;
  let port = null;
  if (rawPort !== "") {
    if (!/^\d+$/.test(rawPort) || Number(rawPort) > 65535) throw new AuthError("url has an invalid port");
    port = Number(rawPort);
  }
  const isDefault = port === null || (scheme === "https" && port === 443) || (scheme === "http" && port === 80);
  const query = m[4] ? `?${m[4]}` : "";
  return `${scheme}://${isDefault ? host : `${host}:${port}`}${m[3] || "/"}${query}`;
}

export function bodySha256(body) {
  if (body === undefined || body === null) body = new Uint8Array();
  if (typeof body === "string") body = toUtf8Bytes(body);
  if (!(body instanceof Uint8Array)) throw new AuthError("body must be the raw request body (Uint8Array or string)");
  return sha256(body).slice(2);
}

export function canonicalMessage(agent, method, url, timestamp, nonce, bodyHash, protocol = PROTOCOL) {
  const { chainId, agentId } = parseAgent(agent);
  method = String(method ?? "").toUpperCase();
  if (!/^[A-Z]+$/.test(method)) throw new AuthError("method must be an HTTP method such as GET or POST");
  if (!NONCE_RE.test(String(nonce ?? ""))) throw new AuthError("nonce must be 16-128 characters from A-Z a-z 0-9 - _");
  if (!/^[0-9a-f]{64}$/.test(String(bodyHash ?? ""))) throw new AuthError("body hash must be lower-case hex SHA-256");
  return [protocol, `agent: ${agentRef(chainId, agentId)}`, `method: ${method}`, `url: ${normalizeUrl(url)}`,
    `timestamp: ${Math.trunc(Number(timestamp))}`, `nonce: ${nonce}`, `body-sha256: ${bodyHash}`].join("\n");
}

// ── agent side ───────────────────────────────────────────────────────
const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const randomNonce = () => Array.from(randomBytes(24), (b) => B64URL[b & 63]).join("");

/** The four headers an agent adds to a request. `signer` is an ethers Signer or a private key string. */
export async function signRequest(signer, agent, method, url, body = "", { timestamp, nonce } = {}) {
  const { chainId, agentId } = parseAgent(agent);
  const ref = agentRef(chainId, agentId);
  const ts = Math.trunc(timestamp ?? Date.now() / 1000);
  const n = nonce ?? randomNonce();
  const message = canonicalMessage(ref, method, url, ts, n, bodySha256(body));
  const wallet = typeof signer === "string" ? new Wallet(signer) : signer;
  const signature = await wallet.signMessage(message);
  return { [HEADERS.agent]: ref, [HEADERS.timestamp]: String(ts), [HEADERS.nonce]: n, [HEADERS.signature]: signature };
}

// ── registry ─────────────────────────────────────────────────────────
export function httpTransport(rpcUrl, { timeoutMs = 10_000, fetchImpl = globalThis.fetch } = {}) {
  return async (payload) => {
    try {
      const res = await fetchImpl(rpcUrl, { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify(payload), signal: AbortSignal.timeout(timeoutMs) });
      return await res.json();
    } catch (err) {
      throw new RpcError(`RPC request failed: ${err.message}`);
    }
  };
}

export class IdentityRegistry {
  constructor({ rpcUrl, transport, address = IDENTITY_REGISTRY } = {}) {
    if (!rpcUrl && !transport) throw new Error("give an rpcUrl or a transport");
    this.send = transport ?? httpTransport(rpcUrl);
    this.address = getAddress(address);
    this.id = 0;
  }

  async #call(to, data) {
    const reply = await this.send({ jsonrpc: "2.0", id: ++this.id, method: "eth_call", params: [{ to, data }, "latest"] });
    if (!reply || typeof reply !== "object") throw new RpcError("unexpected RPC reply");
    if (reply.error) {
      const err = reply.error, message = String(err?.message ?? err);
      if (/revert/i.test(message) || err?.code === 3) throw new Reverted(message);
      throw new RpcError(message.slice(0, 300));
    }
    if (typeof reply.result !== "string" || !reply.result.startsWith("0x")) throw new RpcError("unexpected eth_call result");
    return reply.result;
  }

  async #address(selector, agentId) {
    let raw;
    try {
      raw = await this.#call(this.address, selector + abi.encode(["uint256"], [agentId]).slice(2));
    } catch (err) {
      if (err instanceof Reverted) return null;
      throw err;
    }
    if (raw.length < 66) return null;
    const addr = getAddress(abi.decode(["address"], "0x" + raw.slice(2, 66))[0]);
    return addr === ZeroAddress ? null : addr;
  }

  /** The agent NFT's owner, or null if the agent doesn't exist. */
  ownerOf(agentId) { return this.#address(OWNER_OF, agentId); }

  /** The verified agent wallet, or null if none is set. */
  agentWallet(agentId) { return this.#address(GET_AGENT_WALLET, agentId); }

  async erc1271Valid(wallet, digest, signature) {
    try {
      const raw = await this.#call(getAddress(wallet),
        IS_VALID_SIGNATURE + abi.encode(["bytes32", "bytes"], [digest, signature]).slice(2));
      return raw.slice(0, 10).toLowerCase() === ERC1271_MAGIC;
    } catch (err) {
      if (err instanceof Reverted) return false;
      throw err;
    }
  }
}

// ── replay protection ────────────────────────────────────────────────
export class MemoryNonceStore {
  constructor({ ttl = NONCE_TTL, maxEntries = 1_000_000 } = {}) {
    this.ttl = ttl; this.maxEntries = maxEntries; this.seen = new Map();
  }

  /** Record the nonce; false if it was already used within the TTL. Async so Redis/DB stores fit the same shape. */
  async use(key, now) {
    if (this.seen.size >= this.maxEntries) {
      for (const [k, t] of this.seen) if (now - t >= this.ttl) this.seen.delete(k);
      if (this.seen.size >= this.maxEntries) return false;
    }
    const t = this.seen.get(key);
    if (t !== undefined && now - t < this.ttl) return false;
    this.seen.set(key, now);
    return true;
  }
}

// ── server side ──────────────────────────────────────────────────────
export function readHeaders(headers) {
  const get = typeof headers?.get === "function"
    ? (name) => headers.get(name)
    : (() => {
      const lower = Object.fromEntries(Object.entries(headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
      return (name) => lower[name.toLowerCase()];
    })();
  return Object.fromEntries(Object.entries(HEADERS).map(([key, name]) => {
    const v = get(name);
    return [key, v === undefined || v === null ? null : String(Array.isArray(v) ? v[0] : v)];
  }));
}

export function readDelegation(headers) {
  const v = typeof headers?.get === "function" ? headers.get(DELEGATION_HEADER)
    : Object.entries(headers ?? {}).find(([k]) => k.toLowerCase() === DELEGATION_HEADER.toLowerCase())?.[1];
  if (v === undefined || v === null || v === "") return null;
  return String(Array.isArray(v) ? v.join(",") : v);
}

// ── delegation chains (erc8004-delegation/1) ─────────────────────────
export const DELEGATION_PROTOCOL = "erc8004-delegation/1";
export const DELEGATION_HEADER = "ERC8004-Delegation";
export const MAX_CHAIN = 4;
export const MAX_LIFETIME = 30 * 86400;
const TOKEN_FIELDS = ["from", "methods", "nonce", "not_after", "scope", "signature", "to"];   // sorted

export function normalizeScope(scope) {
  scope = String(scope ?? "").trim();
  if (scope === "*") return scope;
  const norm = normalizeUrl(scope);
  if (norm.includes("?")) throw new AuthError("a delegation scope is a URL prefix without a query string");
  return norm;
}

export function normalizeMethods(methods) {
  if (methods === undefined || methods === null || methods === "" || methods === "*" ||
      (Array.isArray(methods) && methods.length === 1 && methods[0] === "*")) return "*";
  const items = Array.isArray(methods) ? methods : String(methods).split(",");
  const out = [...new Set(items.map((m) => String(m).trim().toUpperCase()).filter(Boolean))].sort();
  if (!out.length || !out.every((m) => /^[A-Z]{1,16}$/.test(m))) throw new AuthError("methods must be HTTP methods such as GET,POST or *");
  return out.join(",");
}

export function delegationMessage(d) {
  const frm = parseAgent(d.from), to = parseAgent(d.to);
  if (!NONCE_RE.test(String(d.nonce ?? ""))) throw new AuthError("delegation nonce must be 16-128 characters from A-Z a-z 0-9 - _");
  if (!Number.isSafeInteger(d.not_after) || d.not_after < 0) throw new AuthError("not_after must be unix seconds");
  return [DELEGATION_PROTOCOL, `from: ${agentRef(frm.chainId, frm.agentId)}`, `to: ${agentRef(to.chainId, to.agentId)}`,
    `scope: ${normalizeScope(d.scope)}`, `methods: ${normalizeMethods(d.methods)}`, `not-after: ${d.not_after}`,
    `nonce: ${d.nonce}`].join("\n");
}

const b64url = (bytes) => encodeBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

export function encodeToken(d) {
  // Sorted keys, compact JSON: byte-identical to the Python library.
  const body = "{" + TOKEN_FIELDS.map((k) => JSON.stringify(k) + ":" + JSON.stringify(d[k])).join(",") + "}";
  return b64url(toUtf8Bytes(body));
}

export function decodeToken(token) {
  token = String(token ?? "").trim();
  if (!token || token.length > 2048 || !/^[A-Za-z0-9_-]+$/.test(token)) throw new AuthError("malformed delegation token");
  let d;
  try {
    const b64 = token.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (token.length % 4)) % 4);
    d = JSON.parse(toUtf8String(decodeBase64(b64)));
  } catch { throw new AuthError("malformed delegation token"); }
  if (!d || typeof d !== "object" || Array.isArray(d) || Object.keys(d).sort().join() !== TOKEN_FIELDS.join()) {
    throw new AuthError("delegation token must hold exactly: from, to, scope, methods, not_after, nonce, signature");
  }
  if (!Number.isSafeInteger(d.not_after) || typeof d.signature !== "string") throw new AuthError("malformed delegation token");
  return d;
}

/** A delegation token from `fromAgent` (signed by its registered wallet or owner) to `toAgent`. */
export async function signDelegation(signer, fromAgent, toAgent, { scope = "*", methods = "*", lifetime = 3600, notAfter,
  nonce, now } = {}) {
  now = Math.trunc(now ?? Date.now() / 1000);
  const notAfterS = Math.trunc(notAfter ?? now + lifetime);
  if (notAfterS - now > MAX_LIFETIME) throw new AuthError("a delegation may last at most 30 days");
  const f = parseAgent(fromAgent), t = parseAgent(toAgent);
  const d = { from: agentRef(f.chainId, f.agentId), to: agentRef(t.chainId, t.agentId), scope: normalizeScope(scope),
    methods: normalizeMethods(methods), not_after: notAfterS, nonce: nonce ?? randomNonce() };
  const wallet = typeof signer === "string" ? new Wallet(signer) : signer;
  d.signature = await wallet.signMessage(delegationMessage(d));
  return encodeToken(d);
}

export const joinChain = (tokens) => tokens.join(",");

export function scopeAllows(scope, url) {
  if (scope === "*") return true;
  const target = normalizeUrl(url);
  if (!target.startsWith(scope)) return false;
  const rest = target.slice(scope.length);
  return scope.endsWith("/") || rest === "" || rest[0] === "/" || rest[0] === "?";
}

const fail = (reason, extra = {}) => ({ ok: false, reason, checks: [], ...extra });

export class Verifier {
  /**
   * new Verifier({ rpcUrls: { 8453: "https://..." } })
   * const result = await verifier.verify(req.headers, req.method, fullUrl, rawBody)
   */
  constructor({ rpcUrls = {}, registries = {}, nonceStore, allowOwner = true, maxSkew = MAX_SKEW, protocol = PROTOCOL,
    clock = () => Date.now() / 1000, isRevoked } = {}) {
    this.registries = new Map(Object.entries(registries).map(([c, r]) => [String(BigInt(c)), r]));
    for (const [c, url] of Object.entries(rpcUrls)) {
      if (!this.registries.has(String(BigInt(c)))) this.registries.set(String(BigInt(c)), new IdentityRegistry({ rpcUrl: url }));
    }
    this.nonces = nonceStore ?? new MemoryNonceStore();
    this.allowOwner = allowOwner;
    this.maxSkew = Math.min(Math.trunc(maxSkew), MAX_SKEW);
    this.protocol = protocol;
    this.clock = clock;
    this.isRevoked = isRevoked;   // optional: (delegation) => boolean | Promise<boolean>
  }

  async verify(headers, method, url, body = "") {
    const h = readHeaders(headers);
    const missing = Object.entries(h).filter(([, v]) => !v).map(([k]) => HEADERS[k]);
    if (missing.length) return fail(`missing header(s): ${missing.join(", ")}`);
    let parsed;
    try { parsed = parseAgent(h.agent); } catch (err) { return fail(err.message); }
    const ref = agentRef(parsed.chainId, parsed.agentId);
    const base = { agent: ref, chainId: Number(parsed.chainId), agentId: parsed.agentId.toString() };
    const checks = [];
    if (!/^\d{1,12}$/.test(h.timestamp)) return fail("timestamp must be unix seconds", base);
    if (!NONCE_RE.test(h.nonce)) return fail("nonce must be 16-128 characters from A-Z a-z 0-9 - _", base);
    if (!SIG_RE.test(h.signature) || h.signature.length > 2 + 2 * 4096 || h.signature.length % 2) {
      return fail("signature must be 0x-prefixed hex", base);
    }
    const now = Math.trunc(this.clock());
    const skew = Math.abs(now - Number(h.timestamp));
    if (skew > this.maxSkew) return fail(`request was signed ${skew}s from now (limit ${this.maxSkew}s): clock skew or replay`, base);
    checks.push("timestamp is fresh");
    let message;
    try {
      message = canonicalMessage(ref, method, url, Number(h.timestamp), h.nonce, bodySha256(body), this.protocol);
    } catch (err) { return fail(err.message, base); }
    const registry = this.registries.get(parsed.chainId.toString());
    if (!registry) return fail(`no RPC configured for chain ${parsed.chainId}`, base);
    let signer, role;
    try {
      const owner = await registry.ownerOf(parsed.agentId);
      if (!owner) return fail("this agent does not exist in the Identity Registry", { ...base, checks });
      const wallet = await registry.agentWallet(parsed.agentId);
      ({ signer, role } = await this.#match(registry, message, h.signature, wallet, owner));
    } catch (err) {
      if (err instanceof RpcError) return fail(`could not read the registry: ${err.message}`, { ...base, checks });
      throw err;
    }
    if (!role) {
      return fail(`signature was not made by the agent's registered wallet${this.allowOwner ? " or owner" : ""}`,
        { ...base, signer, checks });
    }
    checks.push(`signed by the agent's ${role === "agent_wallet" ? "verified agent wallet" : "owner"}`);
    let principal = null, delegationChain = [];
    const chainHeader = readDelegation(headers);
    if (chainHeader) {
      try {
        ({ principal, path: delegationChain } = await this.#verifyChain(chainHeader, ref, method, url, now));
      } catch (err) {
        if (err instanceof AuthError) return fail(`delegation: ${err.message}`, { ...base, signer, role, checks });
        if (err instanceof RpcError) return fail(`could not read the registry: ${err.message}`, { ...base, signer, role, checks });
        throw err;
      }
      checks.push(`acting for ${principal} through ${delegationChain.length - 1} signed delegation(s)`);
    }
    if (!(await this.nonces.use(`${ref}|${h.nonce}`, now))) {
      return fail("nonce already used (replay blocked)", { ...base, signer, role, checks });
    }
    checks.push("nonce is new");
    return { ok: true, reason: "verified", ...base, signer, role, checks, principal, delegationChain };
  }

  async #verifyChain(header, requester, method, url, now) {
    const tokens = header.split(",").map((t) => t.trim()).filter(Boolean);
    if (!tokens.length) throw new AuthError("empty delegation header");
    if (tokens.length > MAX_CHAIN) throw new AuthError(`chains are limited to ${MAX_CHAIN} delegations`);
    const hops = tokens.map(decodeToken);
    method = String(method ?? "").toUpperCase();
    const ref = (s) => { const p = parseAgent(s); return agentRef(p.chainId, p.agentId); };
    for (let i = 0; i < hops.length; i++) {
      const d = hops[i], n = i + 1;
      const message = delegationMessage(d);
      const frm = ref(d.from), to = ref(d.to);
      const next = i === hops.length - 1 ? requester : ref(hops[i + 1].from);
      if (to !== next) throw new AuthError(`hop ${n} delegates to ${to}, but the next agent is ${next}`);
      if (frm === to) throw new AuthError(`hop ${n} delegates an agent to itself`);
      if (d.not_after < now) throw new AuthError(`hop ${n} expired`);
      if (d.not_after - now > MAX_LIFETIME) throw new AuthError(`hop ${n} lasts longer than 30 days`);
      if (!scopeAllows(normalizeScope(d.scope), url)) throw new AuthError(`hop ${n} does not cover this URL`);
      const methods = normalizeMethods(d.methods);
      if (methods !== "*" && !methods.split(",").includes(method)) throw new AuthError(`hop ${n} does not allow ${method}`);
      if (this.isRevoked && (await this.isRevoked(d))) throw new AuthError(`hop ${n} was revoked`);
      const p = parseAgent(frm);
      const registry = this.registries.get(p.chainId.toString());
      if (!registry) throw new AuthError(`no RPC configured for chain ${p.chainId}`);
      const owner = await registry.ownerOf(p.agentId);
      if (!owner) throw new AuthError(`hop ${n}: ${frm} does not exist in the Identity Registry`);
      if (!SIG_RE.test(d.signature) || d.signature.length % 2 || d.signature.length > 2 + 2 * 4096) {
        throw new AuthError(`hop ${n}: malformed signature`);
      }
      const { role } = await this.#match(registry, message, d.signature, await registry.agentWallet(p.agentId), owner);
      if (!role) throw new AuthError(`hop ${n} was not signed by ${frm}'s registered wallet${this.allowOwner ? " or owner" : ""}`);
    }
    const path = [...hops.map((d) => ref(d.from)), requester];
    if (new Set(path).size !== path.length) throw new AuthError("the chain visits the same agent twice");
    return { principal: path[0], path };
  }

  async #match(registry, message, signature, wallet, owner) {
    const candidates = [["agent_wallet", wallet], ...(this.allowOwner ? [["owner", owner]] : [])]
      .filter(([, a]) => a).map(([r, a]) => [r, getAddress(a)]);
    const digest = hashMessage(message);
    let signer = null;
    if (getBytes(signature).length === 65) {
      try { signer = recoverAddress(digest, signature); } catch { signer = null; }
      for (const [role, addr] of candidates) if (signer === addr) return { signer, role };
    }
    for (const [role, addr] of candidates) {   // smart-contract wallets (ERC-1271)
      if (await registry.erc1271Valid(addr, digest, hexlify(signature))) return { signer: addr, role };
    }
    return { signer, role: null };
  }
}
