import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { AbiCoder, Wallet } from "ethers";
import { AuthError, IdentityRegistry, Verifier, decodeToken, delegationMessage, joinChain, scopeAllows,
  signDelegation, signRequest } from "../src/index.js";

const vectors = JSON.parse(readFileSync(new URL("../../vectors/delegation-v1.json", import.meta.url), "utf8"));
const abi = AbiCoder.defaultAbiCoder();
const REG = "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432".toLowerCase();
const aKey = "0x" + "11".repeat(32), bKey = "0x" + "22".repeat(32), cKey = "0x" + "44".repeat(32), xKey = "0x" + "33".repeat(32);
const addr = (k) => new Wallet(k).address;
const NOW = 1_800_000_000, URL_ = "https://api.example.com/v1/pay", BODY = '{"amount":"5"}';
const A = "eip155:8453:1203", B = "eip155:8453:77", C = "eip155:8453:55";

function chain() {
  const agents = { 1203n: { owner: addr(bKey), wallet: addr(aKey) }, 77n: { owner: addr(bKey) }, 55n: { owner: addr(cKey) } };
  return async ({ params: [call] }) => {
    const sel = call.data.slice(0, 10), args = "0x" + call.data.slice(10);
    if (call.to.toLowerCase() !== REG) return { error: { code: -32000, message: "execution reverted" } };
    const [id] = abi.decode(["uint256"], args); const a = agents[id];
    if (sel === "0x6352211e") return a ? { result: abi.encode(["address"], [a.owner]) } : { error: { code: 3, message: "execution reverted" } };
    return { result: abi.encode(["address"], [a?.wallet ?? "0x" + "00".repeat(20)]) };
  };
}
const verifier = (opts = {}) => new Verifier({ registries: { 8453: new IdentityRegistry({ transport: chain() }) }, clock: () => NOW, ...opts });
const req = async (key, agent, tokens, nonce = "r".repeat(20)) => {
  const h = await signRequest(key, agent, "POST", URL_, BODY, { timestamp: NOW, nonce });
  if (tokens.length) h["ERC8004-Delegation"] = joinChain(tokens);
  return h;
};
const del = (key, f, t, o = {}) => signDelegation(key, f, t, { now: NOW, ...o });

test("matches the shared delegation vectors byte for byte", async () => {
  for (const v of vectors.delegations) {
    const tok = await signDelegation(v.private_key, v.input.frm, v.input.to, { scope: v.input.scope, methods: v.input.methods,
      notAfter: v.input.not_after, nonce: v.input.nonce, now: v.input.not_after - 3600 });
    assert.equal(tok, v.token);
    assert.deepEqual(decodeToken(v.token), v.decoded);
    assert.equal(delegationMessage(v.decoded), v.message);
  }
});

test("one and two hops verify, with the principal", async () => {
  let r = await verifier().verify(await req(bKey, B, [await del(aKey, A, B, { scope: "https://api.example.com/v1/", methods: "POST" })]), "POST", URL_, BODY);
  assert.equal(r.ok, true); assert.equal(r.principal, A); assert.deepEqual(r.delegationChain, [A, B]);
  r = await verifier().verify(await req(cKey, C, [await del(aKey, A, B), await del(bKey, B, C)]), "POST", URL_, BODY);
  assert.equal(r.ok, true); assert.deepEqual(r.delegationChain, [A, B, C]);
  r = await verifier().verify(await req(aKey, A, []), "POST", URL_, BODY);
  assert.equal(r.ok, true); assert.equal(r.principal, null);
});

test("bad chains are refused", async () => {
  const cases = [
    [[await del(aKey, A, C)], /next agent/], [[await del(aKey, A, B, { notAfter: NOW - 1 })], /expired/],
    [[await del(aKey, A, B, { scope: "https://other.example.com/" })], /does not cover/],
    [[await del(aKey, A, B, { scope: "https://api.example.com/v1/pa" })], /does not cover/],
    [[await del(aKey, A, B, { methods: "GET" })], /does not allow POST/], [[await del(xKey, A, B)], /not signed by/],
    [[await del(aKey, "eip155:8453:5", B)], /does not exist/], [Array(5).fill(await del(aKey, A, B)), /limited/],
    [["not-a-token!"], /malformed/], [[await del(bKey, B, B)], /itself/],
    [[await del(bKey, B, A), await del(aKey, A, B)], /twice/],
  ];
  for (const [tokens, why] of cases) {
    const r = await verifier().verify(await req(bKey, B, tokens), "POST", URL_, BODY);
    assert.equal(r.ok, false); assert.match(r.reason, why); assert.match(r.reason, /^delegation:/);
  }
});

test("tampering, revocation and nonce safety", async () => {
  const tok = await del(aKey, A, B, { scope: "https://api.example.com/v1/", nonce: "revoked-nonce-0001" });
  const d = decodeToken(tok); d.scope = "*";
  const forged = Buffer.from(JSON.stringify(d)).toString("base64url");
  let r = await verifier().verify(await req(bKey, B, [forged]), "POST", URL_, BODY);
  assert.match(r.reason, /not signed by/);
  r = await verifier({ isRevoked: (x) => x.nonce === "revoked-nonce-0001" }).verify(await req(bKey, B, [tok]), "POST", URL_, BODY);
  assert.match(r.reason, /revoked/);
  const v = verifier();
  assert.equal((await v.verify(await req(bKey, B, [await del(xKey, A, B)]), "POST", URL_, BODY)).ok, false);
  assert.equal((await v.verify(await req(bKey, B, [tok]), "POST", URL_, BODY)).ok, true);
});

test("limits and scope matching", async () => {
  await assert.rejects(del(aKey, A, B, { lifetime: 31 * 86400 }), AuthError);
  await assert.rejects(del(aKey, A, B, { scope: "https://a.io/x?y=1" }), AuthError);
  assert.equal(decodeToken(await del(aKey, A, B, { methods: ["post", "get"] })).methods, "GET,POST");
  assert.ok(scopeAllows("https://api.example.com/v1/", "https://API.example.com:443/v1/pay?x=1"));
  assert.ok(scopeAllows("https://api.example.com/v1", "https://api.example.com/v1?x=1"));
  assert.ok(!scopeAllows("https://api.example.com/v1", "https://api.example.com/v10"));
});
