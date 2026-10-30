import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { AbiCoder, Wallet, hashMessage, getBytes } from "ethers";
import { AuthError, IdentityRegistry, MemoryNonceStore, RpcError, Verifier, bodySha256, canonicalMessage,
  normalizeUrl, parseAgent, signRequest } from "../src/index.js";

const vectors = JSON.parse(readFileSync(new URL("../../vectors/v1.json", import.meta.url), "utf8"));
const abi = AbiCoder.defaultAbiCoder();
const REG = "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432".toLowerCase();
const agentKey = "0x" + "11".repeat(32), ownerKey = "0x" + "22".repeat(32), strangerKey = "0x" + "33".repeat(32);
const SAFE = "0x" + "5a".repeat(20);
const NOW = 1_800_000_000, URL_ = "https://api.example.com/v1/pay", BODY = '{"amount":"5"}';
const addr = (k) => new Wallet(k).address;

function fakeChain() {
  const agents = { 1203n: { owner: addr(ownerKey), wallet: addr(agentKey) }, 77n: { owner: addr(ownerKey) },
    88n: { owner: addr(ownerKey), wallet: SAFE } };
  const chain = { calls: 0, down: false, safeAccepts: new Set() };
  chain.transport = async ({ params: [call] }) => {
    chain.calls++;
    if (chain.down) throw new RpcError("connection refused");
    const sel = call.data.slice(0, 10), args = "0x" + call.data.slice(10);
    const ok = (result) => ({ jsonrpc: "2.0", id: 1, result });
    if (call.to.toLowerCase() === REG) {
      const [agentId] = abi.decode(["uint256"], args);
      const a = agents[agentId];
      if (sel === "0x6352211e") return a ? ok(abi.encode(["address"], [a.owner])) : { error: { code: 3, message: "execution reverted" } };
      return ok(abi.encode(["address"], [a?.wallet ?? "0x" + "00".repeat(20)]));
    }
    if (call.to.toLowerCase() === SAFE) {
      const [digest, sig] = abi.decode(["bytes32", "bytes"], args);
      return ok((chain.safeAccepts.has(digest + sig) ? "0x1626ba7e" : "0x00000000").padEnd(66, "0"));
    }
    return { error: { code: -32000, message: "execution reverted" } };
  };
  return chain;
}
const verifier = (chain, opts = {}) =>
  new Verifier({ registries: { 8453: new IdentityRegistry({ transport: chain.transport }) }, clock: () => NOW, ...opts });
const signed = ({ key = agentKey, agent = "eip155:8453:1203", method = "POST", url = URL_, body = BODY, ts = NOW,
  nonce = "n".repeat(20) } = {}) => signRequest(key, agent, method, url, body, { timestamp: ts, nonce });

test("matches every shared test vector", async () => {
  for (const c of vectors.requests) {
    assert.equal(bodySha256(c.body), c.body_sha256);
    assert.equal(canonicalMessage(c.agent, c.method, c.url, c.timestamp, c.nonce, c.body_sha256), c.message);
    assert.deepEqual(await signRequest(c.private_key, c.agent, c.method, c.url, c.body,
      { timestamp: c.timestamp, nonce: c.nonce }), c.headers);
  }
  for (const p of vectors.url_normalization) assert.equal(normalizeUrl(p.input), p.output);
});

test("rejects malformed agents and URLs", () => {
  for (const bad of ["", "8453:1", "eip155:0:1", "eip155:x:1", "eip155:1:1:1", `eip155:1:${2n ** 256n}`]) {
    assert.throws(() => parseAgent(bad), AuthError);
  }
  for (const bad of ["ftp://a.io/x", "/relative", "https://", "https://a.io:99999/"]) assert.throws(() => normalizeUrl(bad), AuthError);
});

test("random nonces are valid", async () => {
  const h = await signRequest(agentKey, "eip155:8453:1", "GET", URL_);
  assert.match(h["ERC8004-Nonce"], /^[A-Za-z0-9_-]{24}$/);
});

test("agent wallet and owner signatures verify; strangers don't", async () => {
  const chain = fakeChain(), v = verifier(chain);
  let r = await v.verify(await signed(), "POST", URL_, BODY);
  assert.equal(r.ok, true); assert.equal(r.role, "agent_wallet"); assert.equal(r.signer, addr(agentKey));
  r = await v.verify(await signed({ key: ownerKey, nonce: "o".repeat(20) }), "POST", URL_, BODY);
  assert.equal(r.role, "owner");
  r = await v.verify(await signed({ key: strangerKey, nonce: "s".repeat(20) }), "POST", URL_, BODY);
  assert.equal(r.ok, false); assert.equal(r.signer, addr(strangerKey));
  r = await verifier(chain, { allowOwner: false }).verify(await signed({ key: ownerKey }), "POST", URL_, BODY);
  assert.equal(r.ok, false);
});

test("works with fetch Headers and URL variants", async () => {
  const h = new Headers(await signed());
  assert.equal((await verifier(fakeChain()).verify(h, "post", "HTTPS://API.EXAMPLE.COM:443/v1/pay", BODY)).ok, true);
});

test("tampering, unknown agents and unknown chains fail", async () => {
  const chain = fakeChain();
  for (const [m, u, b] of [["GET", URL_, BODY], ["POST", URL_ + "?x=1", BODY], ["POST", URL_, '{"amount":"500"}']]) {
    assert.equal((await verifier(chain).verify(await signed(), m, u, b)).ok, false);
  }
  assert.match((await verifier(chain).verify(await signed({ agent: "eip155:8453:5" }), "POST", URL_, BODY)).reason, /does not exist/);
  assert.match((await verifier(chain).verify(await signed({ agent: "eip155:1:1" }), "POST", URL_, BODY)).reason, /chain 1/);
});

test("replays are blocked and failed attempts don't burn the nonce", async () => {
  const v = verifier(fakeChain());
  assert.equal((await v.verify(await signed({ key: strangerKey }), "POST", URL_, BODY)).ok, false);
  const h = await signed();
  assert.equal((await v.verify(h, "POST", URL_, BODY)).ok, true);
  assert.match((await v.verify(h, "POST", URL_, BODY)).reason, /replay/);
});

test("stale timestamps and malformed headers fail before any RPC call", async () => {
  const chain = fakeChain(), v = verifier(chain);
  for (const ts of [NOW - 301, NOW + 301]) assert.match((await v.verify(await signed({ ts }), "POST", URL_, BODY)).reason, /clock skew/);
  for (const [k, val] of [["ERC8004-Timestamp", "soon"], ["ERC8004-Nonce", "bad nonce!"], ["ERC8004-Signature", "0xabc"]]) {
    const h = await signed(); h[k] = val;
    assert.equal((await v.verify(h, "POST", URL_, BODY)).ok, false);
  }
  const h = await signed(); delete h["ERC8004-Signature"];
  assert.match((await v.verify(h, "POST", URL_, BODY)).reason, /missing header/);
  assert.equal(chain.calls, 0);
  assert.equal(verifier(chain, { maxSkew: 10_000 }).maxSkew, 300);
});

test("fails closed when the RPC is down", async () => {
  const chain = fakeChain(); chain.down = true;
  assert.match((await verifier(chain).verify(await signed(), "POST", URL_, BODY)).reason, /could not read the registry/);
});

test("ERC-1271 smart-contract agent wallets", async () => {
  const chain = fakeChain(), v = verifier(chain);
  const h = await signed({ key: strangerKey, agent: "eip155:8453:88", nonce: "w".repeat(20) });
  assert.equal((await v.verify(h, "POST", URL_, BODY)).ok, false);
  const msg = canonicalMessage("eip155:8453:88", "POST", URL_, NOW, "w".repeat(20), bodySha256(BODY));
  chain.safeAccepts.add(hashMessage(msg) + h["ERC8004-Signature"].toLowerCase());
  const r = await v.verify(h, "POST", URL_, BODY);
  assert.equal(r.ok, true); assert.equal(r.signer.toLowerCase(), SAFE);
});

test("nonce store TTL and capacity", async () => {
  const s = new MemoryNonceStore({ ttl: 10, maxEntries: 2 });
  assert.equal(await s.use("a", 0), true); assert.equal(await s.use("a", 5), false); assert.equal(await s.use("a", 11), true);
  assert.equal(await s.use("b", 11), true); assert.equal(await s.use("c", 12), false); assert.equal(await s.use("c", 30), true);
});

test("byte bodies hash the same as strings", () => {
  assert.equal(bodySha256(new TextEncoder().encode(BODY)), bodySha256(BODY));
  assert.equal(getBytes("0x" + bodySha256(null)).length, 32);
});
