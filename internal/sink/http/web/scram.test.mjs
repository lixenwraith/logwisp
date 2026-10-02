import { test } from "node:test";
import assert from "node:assert/strict";
import { argon2id, _proofForTest, login, logout, stream } from "./scram.js";

const hex = (b) => Buffer.from(b).toString("hex");
const unhex = (s) => new Uint8Array(Buffer.from(s, "hex"));

test("Argon2id matches RFC 9106 section 5.3", async () => {
  const tag = await argon2id(new Uint8Array(32).fill(1), new Uint8Array(16).fill(2), 3, 32, 4, 32,
    { secret: new Uint8Array(8).fill(3), data: new Uint8Array(12).fill(4) });
  assert.equal(hex(tag), "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
});

// From golang.org/x/crypto/argon2.IDKey; m=1020 and m=37 exercise lane rounding,
// keyLen 100 the long form of H'.
test("Argon2id matches Go's argon2.IDKey", async () => {
  const vectors = [
    { pw: "70617373776f7264", salt: "736f6d6573616c74", t: 1, m: 8, p: 1, keyLen: 32, want: "f137f8e186a403a679ccd0606e5ab5dcdafe43c1640855ac8c6e33e9bd63eeb3" },
    { pw: "", salt: "01080f161d242b323940474e555c636a", t: 2, m: 64, p: 2, keyLen: 32, want: "044879f042c4211727f27afa4e8fd18f95c199373cd03402f1f3dc4f07622d28" },
    { pw: "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8", salt: "050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7de", t: 3, m: 256, p: 4, keyLen: 32, want: "a71f8b4acd16b613a2706aafb7ec23b1ddf1790b3aec1911f52152083dda79c9" },
    { pw: "70c3a4737377c3b6726420e29c93", salt: "0910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2", t: 1, m: 1024, p: 3, keyLen: 32, want: "b069833fc8b42b81ad8c0baad6fa131f498fc2787a549809afe7459847029bc9" },
    { pw: "636f727265637420686f727365206261747465727920737461706c65", salt: "0b121920272e353c434a51585f666d74", t: 2, m: 4096, p: 1, keyLen: 32, want: "7d4729ce2bb0a9113eb50b1517b19172c47a61cf9b2c5c0bc6724997ecc52ad7" },
    { pw: "78", salt: "0d141b222930373e454c535a61686f767d848b92", t: 3, m: 37, p: 1, keyLen: 32, want: "f98a0cfc10228157b77cac1d45816f36447239e88bb5ed37e5a4f269f470607e" },
    { pw: "6c6f6e67206f7574707574", salt: "11181f262d343b424950575e656c737a", t: 1, m: 128, p: 2, keyLen: 100, want: "436511e64b4986f59fe6b2e86166a2cd2d543c2f221816780a7698284e0a81529fa25000a5da5fefc062ef70f0f8a94d87dbec1f292091e5fc14fdd7f155f29f4dd0073b604e3a7c5b77433e482337761a9c1dd454872e0e00cc22483b8b0513fbda54e4" },
  ];
  for (const v of vectors) {
    const key = await argon2id(unhex(v.pw), unhex(v.salt), v.t, v.m, v.p, v.keyLen);
    assert.equal(hex(key), v.want, `t=${v.t} m=${v.m} p=${v.p} keyLen=${v.keyLen}`);
  }
});

// lixenwraith/auth's unbound known answer; the server signature comes from the
// same AuthMessage under Go's DeriveCredential.
test("proof and server signature match lixenwraith/auth", async () => {
  const challenge = {
    full_nonce: "client-nonceserver-nonce", salt: Buffer.alloc(16, 7).toString("base64"),
    argon_time: 1, argon_memory: 8, argon_threads: 1,
  };
  const got = await _proofForTest("alice", "password123", "client-nonce", challenge, 1, 8);
  assert.deepEqual(got, {
    client_proof: "JCVOdKAYwVu3YZx+6nfRfBUcnsTCgydOchnQq1G7Ry0=",
    server_signature: "0HKxosIZvdoAzstS4dEkNgoYvcDpFnOgwBjyhiSsK00=",
  });
});

const STREAM = "https://site.test/logs/stream";

// A fetch answering with an event stream sent in the given chunks
function sseFetch(t, chunks, { status = 200, type = "text/event-stream" } = {}) {
  return t.mock.method(globalThis, "fetch", async () => new Response(new ReadableStream({
    start(c) {
      for (const chunk of chunks) c.enqueue(new TextEncoder().encode(chunk));
      c.close();
    },
  }), { status, headers: { "Content-Type": type } }));
}

async function events(t, chunks) {
  sseFetch(t, chunks);
  const got = [];
  const end = await stream(STREAM, { onEvent: (e) => got.push(e) });
  return { got, end };
}

// A split CRLF is one break, so "d" and "e" stay one event; a kept BOM would
// rename the first field and drop "a".
test("stream splits lines at CRLF, LF and a lone CR, across chunks", async (t) => {
  const { got } = await events(t, ["﻿data: a\r\ndata: b\rdata: c\n\r", "\n", "data: d\r", "\ndata: e\r", "\r\n"]);
  assert.deepEqual(got, [
    { type: "message", data: "a\nb\nc", lastEventId: "" },
    { type: "message", data: "d\ne", lastEventId: "" },
  ]);
});

test("stream interprets fields as the HTML standard does", async (t) => {
  const { got, end } = await events(t, [
    ": comment\nevent: connected\ndata:{\"a\":1}\nid: 7\n\n",
    "data\n\n",
    "event: no-data\n\n",
    "data:  one space kept\nunknown: x\nid: 8\0\nretry: 15x\nretry: 3000\n\n",
    "id\ndata: never ended\n",
  ]);
  assert.deepEqual(got, [
    { type: "connected", data: "{\"a\":1}", lastEventId: "7" },
    { type: "message", data: "", lastEventId: "7" },
    { type: "message", data: " one space kept", lastEventId: "7" },
  ]);
  assert.deepEqual(end, { lastEventId: "7", retry: 3000 });
});

test("stream presents the bearer and refuses anything but a 200 event stream", async (t) => {
  const fetch = sseFetch(t, []);
  await stream(STREAM, { token: "tok" });
  const init = fetch.mock.calls[0].arguments[1];
  assert.equal(init.headers.Authorization, "Bearer tok");
  assert.equal(init.redirect, "error");
  fetch.mock.restore();
  sseFetch(t, [], { status: 401 });
  await assert.rejects(stream(STREAM, { token: "tok" }), { status: 401 });
  sseFetch(t, [], { type: "text/html" });
  await assert.rejects(stream(STREAM), { message: "not an event stream" });
});

test("stream rejects with the AbortError once its signal aborts", async (t) => {
  t.mock.method(globalThis, "fetch", async (url, { signal }) => new Response(new ReadableStream({
    start(c) {
      c.enqueue(new TextEncoder().encode("data: first\n\n"));
      signal.addEventListener("abort", () => c.error(signal.reason));
    },
  }), { headers: { "Content-Type": "text/event-stream" } }));
  const ac = new AbortController();
  await assert.rejects(stream(STREAM, { signal: ac.signal, onEvent: () => ac.abort() }), { name: "AbortError" });
});

// The mock server signs with the client's own derivation at the Argon2 floor
test("token mode returns the token, and logout presents it", async (t) => {
  const challenge = { salt: Buffer.alloc(16, 9).toString("base64"), argon_time: 3, argon_memory: 65536, argon_threads: 1 };
  const sent = [];
  t.mock.method(globalThis, "fetch", async (url, init) => {
    const body = JSON.parse(init.body);
    sent.push({ body, headers: init.headers });
    if (body.scram) {
      challenge.client_nonce = body.scram.client_nonce;
      challenge.full_nonce = body.scram.client_nonce + "server-nonce";
      return Response.json({ challenge });
    }
    if (body.proof) {
      const want = await _proofForTest("alice", "password123", challenge.client_nonce, challenge, 3, 65536);
      challenge.proof_ok = body.proof.client_proof === want.client_proof;
      return Response.json({ final: { username: "alice", server_signature: want.server_signature }, token: "tok", expires_in: 900 });
    }
    return new Response(null, { status: 204 });
  });
  const base = "https://site.test/logs/";
  assert.deepEqual(await login(base, "alice", "password123", { session: "token" }),
    { username: "alice", expiresIn: 900, token: "tok" });
  assert.ok(challenge.proof_ok);
  assert.equal("session" in sent[1].body, false);
  await logout(base, { token: "tok" });
  assert.equal(sent[2].headers.Authorization, "Bearer tok");
});
