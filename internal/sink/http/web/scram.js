const MAX_USERNAME = 256;
const MAX_PASSWORD = 1024;
const MAX_FULL_NONCE = 512;
const MIN_SALT = 16;
const MAX_SALT = 64;
// lixenwraith/auth's budget for an Argon2 profile it did not choose
const MAX_TIME = 16;
const MAX_MEMORY = 256 * 1024;
const MAX_THREADS = 16;
const MAX_WORK = 4 * 64 * 1024 * 3;
// The Go dialer's floor: a hostile server must not obtain a cheaply guessable proof
const MIN_TIME = 3;
const MIN_MEMORY = 64 * 1024;

const encoder = new TextEncoder();

/**
 * Logs in to the logwisp http sink mounted at base (a URL ending in "/"), per
 * the wire protocol in logwisp's doc/scram-auth-plan.md. The session arrives as
 * an HttpOnly cookie; the promise resolves only once the server has proved it
 * holds this user's verifier. onProgress(fraction) follows the Argon2 pass.
 */
export async function login(base, username, password, { onProgress } = {}) {
  const pw = checkCredentials(username, password);
  subtle(); // an insecure page fails before anything is sent
  const url = new URL("auth", base);
  const clientNonce = base64(crypto.getRandomValues(new Uint8Array(24)))
    .replace(/\+/g, "-").replace(/\//g, "_");
  const first = await post(url, { logwisp: 1, scram: { username, client_nonce: clientNonce } });
  const { proof, serverSignature } = await prove(username, pw, clientNonce, first.challenge,
    MIN_TIME, MIN_MEMORY, onProgress);
  const step = await post(url, { proof, session: "cookie" });
  const final = step.final;
  if (!final || typeof final !== "object") {
    throw new Error("server sent no final message");
  }
  const name = final.username ?? "";
  const signature = decodeBase64(final.server_signature, 32);
  if ((name !== "" && name !== username) || !signature || !equal(signature, serverSignature)) {
    throw new Error("server could not prove it holds this user's verifier");
  }
  const expiresIn = Number.isSafeInteger(step.expires_in) && step.expires_in > 0 ? step.expires_in : 0;
  return { username, expiresIn };
}

// Logout posts to auth itself: a clearing cookie from any other path would
// get another default path and miss the session cookie
export async function logout(base) {
  const res = await send(new URL("auth", base), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ logout: true }),
  });
  if (res.status !== 200 && res.status !== 204) {
    throw new Error(`logout failed: ${res.status}`);
  }
}

// Test hook: the proof for a fixed client nonce, under an explicit Argon2 floor
export async function _proofForTest(username, password, clientNonce, challenge, minTime, minMemory) {
  const { proof, serverSignature } = await prove(username, checkCredentials(username, password),
    clientNonce, challenge, minTime, minMemory);
  return { client_proof: proof.client_proof, server_signature: base64(serverSignature) };
}

function checkCredentials(username, password) {
  if (typeof username !== "string" || typeof password !== "string") {
    throw new Error("username and password must be text");
  }
  const name = encoder.encode(username);
  if (name.length === 0 || name.length > MAX_USERNAME || /[,=\p{Cc}\p{Cs}]/u.test(username)) {
    throw new Error("invalid username");
  }
  // TextEncoder would silently turn a lone surrogate into U+FFFD
  if (/\p{Cs}/u.test(password)) {
    throw new Error("password contains invalid characters");
  }
  const pw = encoder.encode(password);
  if (pw.length === 0 || pw.length > MAX_PASSWORD) {
    throw new Error(`password must be 1-${MAX_PASSWORD} bytes`);
  }
  return pw;
}

// Everything the challenge says is checked before Argon2 runs on it
async function prove(username, pw, clientNonce, challenge, minTime, minMemory, onProgress) {
  if (!challenge || typeof challenge !== "object") {
    throw new Error("server sent no challenge");
  }
  const { full_nonce: fullNonce, salt, argon_time: t, argon_memory: m, argon_threads: p } = challenge;
  if (typeof fullNonce !== "string" || fullNonce.length > MAX_FULL_NONCE || !/^[\x21-\x2b\x2d-\x7e]+$/.test(fullNonce) ||
    !fullNonce.startsWith(clientNonce) || fullNonce.length <= clientNonce.length) {
    throw new Error("invalid server nonce");
  }
  const saltBytes = decodeBase64(salt, MAX_SALT);
  if (!saltBytes || saltBytes.length < MIN_SALT) {
    throw new Error("invalid salt");
  }
  if (![t, m, p].every(Number.isSafeInteger) || t < 1 || p < 1 || m < 8 * p ||
    t > MAX_TIME || m > MAX_MEMORY || p > MAX_THREADS || m * t > MAX_WORK) {
    throw new Error("invalid Argon2 parameters");
  }
  if (t < minTime || m < minMemory) {
    throw new Error("server asked for a weaker Argon2 cost than allowed");
  }
  const salted = await argon2id(pw, saltBytes, t, m, p, 32, { onProgress });
  const clientKey = await hmac(salted, "Client Key");
  const serverKey = await hmac(salted, "Server Key");
  const storedKey = new Uint8Array(await subtle().digest("SHA-256", clientKey));
  salted.fill(0);
  // Unbound: the browser cannot see the certificate, so no c= part
  const authMessage = `u=${username},n=${clientNonce},r=${fullNonce},s=${salt},t=${t},m=${m},p=${p},r=${fullNonce}`;
  const proof = await hmac(storedKey, authMessage);
  for (let i = 0; i < proof.length; i++) proof[i] ^= clientKey[i];
  clientKey.fill(0);
  return {
    proof: { full_nonce: fullNonce, client_proof: base64(proof) },
    serverSignature: await hmac(serverKey, authMessage),
  };
}

async function post(url, body) {
  const res = await send(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const step = (await res.json().catch(() => null)) ?? {};
  if (res.status === 404 || res.status === 405) {
    throw new Error("no SCRAM login at this address");
  }
  if (res.status !== 200) {
    throw new Error(`login refused: ${typeof step.error === "string" ? step.error : res.status}`);
  }
  return step;
}

// A redirect would replay the proof to wherever it points
async function send(url, init) {
  try {
    return await fetch(url, { ...init, credentials: "same-origin", cache: "no-store", redirect: "error" });
  } catch {
    throw new Error(`cannot reach ${url.pathname}`);
  }
}

function subtle() {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new Error("WebCrypto unavailable: the page must be served over HTTPS");
  return s;
}

async function hmac(key, message) {
  const k = await subtle().importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle().sign("HMAC", k, encoder.encode(message)));
}

function equal(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

function base64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

// Strict like Go's base64.StdEncoding.Strict(): the round trip rejects stray padding bits
function decodeBase64(s, maxBytes) {
  if (typeof s !== "string" || s.length > 4 * Math.ceil(maxBytes / 3) ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s)) {
    return null;
  }
  const out = Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  return out.length <= maxBytes && base64(out) === s ? out : null;
}

// --- Argon2id (RFC 9106, version 0x13) ---
// Uint64s are (lo, hi) pairs of uint32 words; a 1 KiB block is 256 words.

const BLAKE2B_IV = new Uint32Array([
  0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85, 0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
  0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c, 0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19,
]);

const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
].map((row) => row.map((i) => 2 * i));

/**
 * Argon2id over a password (string or bytes) and salt, as Uint8Array of keyLen
 * bytes. Yields to the event loop every ~50 ms, so a page stays responsive.
 */
export async function argon2id(password, salt, time, memoryKiB, threads, keyLen,
  { secret = new Uint8Array(0), data = new Uint8Array(0), onProgress } = {}) {
  const pw = typeof password === "string" ? encoder.encode(password) : password;
  if (![time, memoryKiB, threads, keyLen].every(Number.isSafeInteger) || time < 1 || threads < 1 ||
    threads > 0xffffff || memoryKiB < 8 * threads || memoryKiB > 0xffffffff || keyLen < 4 || keyLen > 0xffffffff) {
    throw new Error("invalid Argon2 parameters");
  }
  const h0 = new Uint8Array(72);
  h0.set(blake2b(concat(le32(threads), le32(keyLen), le32(memoryKiB), le32(time), le32(0x13), le32(2),
    le32(pw.length), pw, le32(salt.length), salt, le32(secret.length), secret, le32(data.length), data), 64));

  const laneLen = Math.floor(memoryKiB / (4 * threads)) * 4;
  const st = {
    mem: new Uint32Array(laneLen * threads * 256), lanes: threads, laneLen, segLen: laneLen / 4,
    blocks: laneLen * threads, time, r: new Uint32Array(256), q: new Uint32Array(256),
    input: new Uint32Array(256), addr: new Uint32Array(256),
  };
  for (let lane = 0; lane < threads; lane++) {
    h0.set(le32(lane), 68);
    for (let i = 0; i < 2; i++) {
      h0.set(le32(i), 64);
      const block = hprime(h0, 1024);
      for (let w = 0; w < 256; w++) st.mem[(lane * laneLen + i) * 256 + w] = readLE32(block, 4 * w);
    }
  }
  let done = 0, yielded = Date.now();
  for (let pass = 0; pass < time; pass++) {
    for (let slice = 0; slice < 4; slice++) {
      for (let lane = 0; lane < threads; lane++) {
        fillSegment(st, pass, slice, lane);
        done++;
        if (Date.now() - yielded > 50) {
          onProgress?.(done / (time * 4 * threads));
          await new Promise((resolve) => setTimeout(resolve, 0));
          yielded = Date.now();
        }
      }
    }
  }

  const last = st.mem.slice((laneLen - 1) * 256, laneLen * 256);
  for (let lane = 1; lane < threads; lane++) {
    const o = (lane * laneLen + laneLen - 1) * 256;
    for (let w = 0; w < 256; w++) last[w] ^= st.mem[o + w];
  }
  const bytes = new Uint8Array(1024);
  for (let w = 0; w < 256; w++) writeLE32(bytes, 4 * w, last[w]);
  return hprime(bytes, keyLen);
}

function fillSegment(st, pass, slice, lane) {
  const { mem, lanes, laneLen, segLen, r, q, input, addr } = st;
  const independent = pass === 0 && slice < 2;
  let index = pass === 0 && slice === 0 ? 2 : 0;
  if (independent) {
    input.fill(0);
    input[0] = pass;
    input[2] = lane;
    input[4] = slice;
    input[6] = st.blocks;
    input[8] = st.time;
    input[10] = 2;
    if (index !== 0) nextAddresses(input, addr, q);
  }
  for (let cur = lane * laneLen + slice * segLen + index; index < segLen; index++, cur++) {
    const prev = index === 0 && slice === 0 ? cur + laneLen - 1 : cur - 1;
    let j1, j2;
    if (independent) {
      if (index % 128 === 0) nextAddresses(input, addr, q);
      j1 = addr[2 * (index % 128)];
      j2 = addr[2 * (index % 128) + 1];
    } else {
      j1 = mem[prev * 256];
      j2 = mem[prev * 256 + 1];
    }
    const refLane = pass === 0 && slice === 0 ? lane : j2 % lanes;
    const same = refLane === lane;
    let area, start = 0;
    if (pass === 0) {
      area = slice * segLen + (slice === 0 || same ? index : 0);
    } else {
      area = 3 * segLen + (same ? index : 0);
      start = ((slice + 1) % 4) * segLen;
    }
    if (index === 0 || same) area--;
    const ref = refLane * laneLen + (start + area - 1 - mulHi(mulHi(j1, j1), area)) % laneLen;

    const c = cur * 256, x = prev * 256, y = ref * 256;
    for (let i = 0; i < 256; i++) r[i] = mem[x + i] ^ mem[y + i];
    q.set(r);
    permute(q);
    for (let i = 0; i < 256; i++) mem[c + i] ^= r[i] ^ q[i];
  }
}

// Data-independent addressing: two compressions of the counter block against zero
function nextAddresses(input, addr, q) {
  input[12]++;
  for (const src of [input, addr]) {
    q.set(src);
    permute(q);
    for (let i = 0; i < 256; i++) addr[i] = src[i] ^ q[i];
  }
}

function permute(v) {
  for (let x = 0; x < 256; x += 32) {
    blamka(v, x, x + 8, x + 16, x + 24);
    blamka(v, x + 2, x + 10, x + 18, x + 26);
    blamka(v, x + 4, x + 12, x + 20, x + 28);
    blamka(v, x + 6, x + 14, x + 22, x + 30);
    blamka(v, x, x + 10, x + 20, x + 30);
    blamka(v, x + 2, x + 12, x + 22, x + 24);
    blamka(v, x + 4, x + 14, x + 16, x + 26);
    blamka(v, x + 6, x + 8, x + 18, x + 28);
  }
  for (let w = 0; w < 32; w += 4) {
    blamka(v, w, w + 64, w + 128, w + 192);
    blamka(v, w + 2, w + 66, w + 130, w + 194);
    blamka(v, w + 32, w + 96, w + 160, w + 224);
    blamka(v, w + 34, w + 98, w + 162, w + 226);
    blamka(v, w, w + 66, w + 160, w + 226);
    blamka(v, w + 2, w + 96, w + 162, w + 192);
    blamka(v, w + 32, w + 98, w + 128, w + 194);
    blamka(v, w + 34, w + 64, w + 130, w + 224);
  }
}

// G of Argon2's P on four uint64s, in locals; the products are split so
// every intermediate stays exact in a double
function blamka(v, a, b, c, d) {
  let al = v[a], ah = v[a + 1], bl = v[b], bh = v[b + 1];
  let cl = v[c], ch = v[c + 1], dl = v[d], dh = v[d + 1];
  let pl, ph, s, xl, xh;

  pl = Math.imul(al, bl); ph = mulHi(al, bl);
  s = al + bl + ((pl << 1) >>> 0);
  ah = (ah + bh + ((ph << 1) | (pl >>> 31)) + Math.floor(s / 4294967296)) >>> 0; al = s >>> 0;
  xl = dl ^ al; dl = (dh ^ ah) >>> 0; dh = xl >>> 0;

  pl = Math.imul(cl, dl); ph = mulHi(cl, dl);
  s = cl + dl + ((pl << 1) >>> 0);
  ch = (ch + dh + ((ph << 1) | (pl >>> 31)) + Math.floor(s / 4294967296)) >>> 0; cl = s >>> 0;
  xl = bl ^ cl; xh = bh ^ ch; bl = ((xl >>> 24) | (xh << 8)) >>> 0; bh = ((xh >>> 24) | (xl << 8)) >>> 0;

  pl = Math.imul(al, bl); ph = mulHi(al, bl);
  s = al + bl + ((pl << 1) >>> 0);
  ah = (ah + bh + ((ph << 1) | (pl >>> 31)) + Math.floor(s / 4294967296)) >>> 0; al = s >>> 0;
  xl = dl ^ al; xh = dh ^ ah; dl = ((xl >>> 16) | (xh << 16)) >>> 0; dh = ((xh >>> 16) | (xl << 16)) >>> 0;

  pl = Math.imul(cl, dl); ph = mulHi(cl, dl);
  s = cl + dl + ((pl << 1) >>> 0);
  ch = (ch + dh + ((ph << 1) | (pl >>> 31)) + Math.floor(s / 4294967296)) >>> 0; cl = s >>> 0;
  xl = bl ^ cl; xh = bh ^ ch; bl = (xl << 1) | (xh >>> 31); bh = (xh << 1) | (xl >>> 31);

  v[a] = al; v[a + 1] = ah; v[b] = bl; v[b + 1] = bh;
  v[c] = cl; v[c + 1] = ch; v[d] = dl; v[d + 1] = dh;
}

// High word of the 64-bit product of two uint32s
function mulHi(a, b) {
  const a0 = a & 0xffff, a1 = a >>> 16, b0 = b & 0xffff, b1 = b >>> 16;
  const m01 = a0 * b1, m10 = a1 * b0;
  const carry = ((a0 * b0) >>> 16) + (m01 & 0xffff) + (m10 & 0xffff);
  return a1 * b1 + (m01 >>> 16) + (m10 >>> 16) + (carry >>> 16);
}

function xorRotr(v, d, s, n) {
  const lo = v[d] ^ v[s], hi = v[d + 1] ^ v[s + 1];
  if (n === 32) {
    v[d] = hi;
    v[d + 1] = lo;
  } else if (n === 63) {
    v[d] = (lo << 1) | (hi >>> 31);
    v[d + 1] = (hi << 1) | (lo >>> 31);
  } else {
    v[d] = (lo >>> n) | (hi << (32 - n));
    v[d + 1] = (hi >>> n) | (lo << (32 - n));
  }
}

// H' of RFC 9106: BLAKE2b stretched to any length
function hprime(input, outLen) {
  const x = concat(le32(outLen), input);
  if (outLen <= 64) return blake2b(x, outLen);
  const out = new Uint8Array(outLen);
  let v = blake2b(x, 64), pos = 32;
  out.set(v.subarray(0, 32));
  for (; outLen - pos > 64; pos += 32) {
    v = blake2b(v, 64);
    out.set(v.subarray(0, 32), pos);
  }
  out.set(blake2b(v, outLen - pos), pos);
  return out;
}

// Unkeyed BLAKE2b (RFC 7693) of a short input
function blake2b(input, outLen) {
  const h = BLAKE2B_IV.slice();
  h[0] ^= 0x01010000 ^ outLen;
  const v = new Uint32Array(32), m = new Uint32Array(32), block = new Uint8Array(128);
  const blocks = Math.max(1, Math.ceil(input.length / 128));
  for (let b = 0; b < blocks; b++) {
    const last = b === blocks - 1;
    block.fill(0);
    block.set(input.subarray(b * 128, b * 128 + 128));
    for (let w = 0; w < 32; w++) m[w] = readLE32(block, 4 * w);
    const count = last ? input.length : (b + 1) * 128;
    v.set(h);
    v.set(BLAKE2B_IV, 16);
    v[24] ^= count;
    v[25] ^= count / 4294967296;
    if (last) {
      v[28] = ~v[28];
      v[29] = ~v[29];
    }
    for (let round = 0; round < 12; round++) {
      const s = SIGMA[round % 10];
      b2mix(v, m, 0, 8, 16, 24, s[0], s[1]);
      b2mix(v, m, 2, 10, 18, 26, s[2], s[3]);
      b2mix(v, m, 4, 12, 20, 28, s[4], s[5]);
      b2mix(v, m, 6, 14, 22, 30, s[6], s[7]);
      b2mix(v, m, 0, 10, 20, 30, s[8], s[9]);
      b2mix(v, m, 2, 12, 22, 24, s[10], s[11]);
      b2mix(v, m, 4, 14, 16, 26, s[12], s[13]);
      b2mix(v, m, 6, 8, 18, 28, s[14], s[15]);
    }
    for (let w = 0; w < 16; w++) h[w] ^= v[w] ^ v[w + 16];
  }
  const out = new Uint8Array(64);
  for (let w = 0; w < 16; w++) writeLE32(out, 4 * w, h[w]);
  return out.slice(0, outLen);
}

function b2mix(v, m, a, b, c, d, x, y) {
  add64(v, a, v, b);
  add64(v, a, m, x);
  xorRotr(v, d, a, 32);
  add64(v, c, v, d);
  xorRotr(v, b, c, 24);
  add64(v, a, v, b);
  add64(v, a, m, y);
  xorRotr(v, d, a, 16);
  add64(v, c, v, d);
  xorRotr(v, b, c, 63);
}

function add64(v, x, w, y) {
  const lo = v[x] + w[y];
  v[x + 1] = v[x + 1] + w[y + 1] + (lo > 0xffffffff ? 1 : 0);
  v[x] = lo;
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function le32(n) {
  const b = new Uint8Array(4);
  writeLE32(b, 0, n);
  return b;
}

function readLE32(b, i) {
  return (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0;
}

function writeLE32(b, i, n) {
  b[i] = n;
  b[i + 1] = n >>> 8;
  b[i + 2] = n >>> 16;
  b[i + 3] = n >>> 24;
}
