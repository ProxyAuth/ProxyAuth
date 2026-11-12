// Proof-of-work search, synchronous: one worker keeps its core busy at
// 100 %, with no await per hash. SHA-256 uses a midstate: the challenge
// is exactly 64 bytes, one block, hashed once; each nonce only costs the
// second block. SHA-512 fits challenge + nonce in a single block.
const K256 = new Int32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
const W = new Int32Array(64);
function c256(st, out) {
  for (let i = 16; i < 64; i++) {
    const a = W[i - 15], b = W[i - 2];
    const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
    const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
    W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
  }
  let A = st[0], B = st[1], C = st[2], D = st[3], E = st[4], F = st[5], G = st[6], H = st[7];
  for (let i = 0; i < 64; i++) {
    const S1 = ((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7));
    const t1 = (H + S1 + ((E & F) ^ (~E & G)) + K256[i] + W[i]) | 0;
    const S0 = ((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10));
    const t2 = (S0 + ((A & B) ^ (A & C) ^ (B & C))) | 0;
    H = G; G = F; F = E; E = (D + t1) | 0; D = C; C = B; B = A; A = (t1 + t2) | 0;
  }
  out[0] = (st[0] + A) | 0; out[1] = (st[1] + B) | 0; out[2] = (st[2] + C) | 0; out[3] = (st[3] + D) | 0;
  out[4] = (st[4] + E) | 0; out[5] = (st[5] + F) | 0; out[6] = (st[6] + G) | 0; out[7] = (st[7] + H) | 0;
}
const IV256 = new Int32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
function words(bytes, n) { for (let i = 0; i < n; i++) W[i] = (bytes[4 * i] << 24) | (bytes[4 * i + 1] << 16) | (bytes[4 * i + 2] << 8) | bytes[4 * i + 3]; }
function ascii(s) { const b = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i); return b; }

// SHA-256 of challenge (64 bytes) + decimal nonce; first word in out[0].
function sha256Searcher(challenge) {
  const mid = new Int32Array(8);
  words(ascii(challenge), 16); c256(IV256, mid);
  const blk = new Uint8Array(64), out = new Int32Array(8);
  return function (nonce) {
    const s = String(nonce), L = s.length;
    blk.fill(0);
    for (let i = 0; i < L; i++) blk[i] = s.charCodeAt(i);
    blk[L] = 0x80;
    const bits = (64 + L) * 8;
    blk[62] = (bits >>> 8) & 0xff; blk[63] = bits & 0xff;
    words(blk, 16); c256(mid, out);
    return out;
  };
}

// SHA-512 with 32-bit halves (hi, lo).
const K512 = new Int32Array([
  0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc, 0x3956c25b, 0xf348b538,
  0x59f111f1, 0xb605d019, 0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118, 0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe,
  0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2, 0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235,
  0xc19bf174, 0xcf692694, 0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, 0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
  0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5, 0x983e5152, 0xee66dfab,
  0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4, 0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725,
  0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70, 0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed,
  0x53380d13, 0x9d95b3df, 0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
  0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001, 0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30, 0xd192e819, 0xd6ef5218,
  0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8, 0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53,
  0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8, 0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb, 0x5b9cca4f, 0x7763e373,
  0x682e6ff3, 0xd6b2b8a3, 0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
  0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b, 0xca273ece, 0xea26619c,
  0xd186b8c7, 0x21c0c207, 0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178, 0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6,
  0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b, 0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc,
  0x431d67c4, 0x9c100d4c, 0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a, 0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817]);
const IV512 = new Int32Array([0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
  0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179]);
const W5 = new Int32Array(160);
function c512(st, out) {
  const w = W5;
  for (let i = 16; i < 80; i++) {
    let xh = w[(i - 15) * 2], xl = w[(i - 15) * 2 + 1];
    const s0h = ((xh >>> 1) | (xl << 31)) ^ ((xh >>> 8) | (xl << 24)) ^ (xh >>> 7);
    const s0l = ((xl >>> 1) | (xh << 31)) ^ ((xl >>> 8) | (xh << 24)) ^ ((xl >>> 7) | (xh << 25));
    xh = w[(i - 2) * 2]; xl = w[(i - 2) * 2 + 1];
    const s1h = ((xh >>> 19) | (xl << 13)) ^ ((xl >>> 29) | (xh << 3)) ^ (xh >>> 6);
    const s1l = ((xl >>> 19) | (xh << 13)) ^ ((xh >>> 29) | (xl << 3)) ^ ((xl >>> 6) | (xh << 26));
    let l = (s0l >>> 0) + (s1l >>> 0) + (w[(i - 7) * 2 + 1] >>> 0) + (w[(i - 16) * 2 + 1] >>> 0);
    const h = s0h + s1h + w[(i - 7) * 2] + w[(i - 16) * 2] + ((l / 0x100000000) | 0);
    w[i * 2] = h | 0; w[i * 2 + 1] = l | 0;
  }
  let ah = st[0], al = st[1], bh = st[2], bl = st[3], ch = st[4], cl = st[5], dh = st[6], dl = st[7];
  let eh = st[8], el = st[9], fh = st[10], fl = st[11], gh = st[12], gl = st[13], hh = st[14], hl = st[15];
  for (let i = 0; i < 80; i++) {
    const S1h = ((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((el >>> 9) | (eh << 23));
    const S1l = ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((eh >>> 9) | (el << 23));
    const chh = (eh & fh) ^ (~eh & gh), chl = (el & fl) ^ (~el & gl);
    let l = (hl >>> 0) + (S1l >>> 0) + (chl >>> 0) + (K512[i * 2 + 1] >>> 0) + (W5[i * 2 + 1] >>> 0);
    const t1h = hh + S1h + chh + K512[i * 2] + W5[i * 2] + ((l / 0x100000000) | 0);
    const t1l = l | 0;
    const S0h = ((ah >>> 28) | (al << 4)) ^ ((al >>> 2) | (ah << 30)) ^ ((al >>> 7) | (ah << 25));
    const S0l = ((al >>> 28) | (ah << 4)) ^ ((ah >>> 2) | (al << 30)) ^ ((ah >>> 7) | (al << 25));
    const mjh = (ah & bh) ^ (ah & ch) ^ (bh & ch), mjl = (al & bl) ^ (al & cl) ^ (bl & cl);
    l = (S0l >>> 0) + (mjl >>> 0);
    const t2h = S0h + mjh + ((l / 0x100000000) | 0), t2l = l | 0;
    hh = gh; hl = gl; gh = fh; gl = fl; fh = eh; fl = el;
    l = (dl >>> 0) + (t1l >>> 0); eh = (dh + t1h + ((l / 0x100000000) | 0)) | 0; el = l | 0;
    dh = ch; dl = cl; ch = bh; cl = bl; bh = ah; bl = al;
    l = (t1l >>> 0) + (t2l >>> 0); ah = (t1h + t2h + ((l / 0x100000000) | 0)) | 0; al = l | 0;
  }
  const v = [ah, al, bh, bl, ch, cl, dh, dl, eh, el, fh, fl, gh, gl, hh, hl];
  for (let i = 0; i < 16; i += 2) {
    const l = (st[i + 1] >>> 0) + (v[i + 1] >>> 0);
    out[i] = (st[i] + v[i] + ((l / 0x100000000) | 0)) | 0; out[i + 1] = l | 0;
  }
}
function sha512Searcher(challenge) {
  const pre = ascii(challenge), blk = new Uint8Array(128), out = new Int32Array(16);
  return function (nonce) {
    const s = String(nonce), L = pre.length + s.length;
    blk.fill(0); blk.set(pre);
    for (let i = 0; i < s.length; i++) blk[pre.length + i] = s.charCodeAt(i);
    blk[L] = 0x80;
    const bits = L * 8;
    blk[126] = (bits >>> 8) & 0xff; blk[127] = bits & 0xff;
    for (let i = 0; i < 32; i++) W5[i] = (blk[4 * i] << 24) | (blk[4 * i + 1] << 16) | (blk[4 * i + 2] << 8) | blk[4 * i + 3];
    c512(IV512, out);
    return out;
  };
}

// difficulty hex zeros = the top 4*d bits of the first 32-bit word (d ≤ 8).
function meets(h, bits) {
  // The top `bits` bits are zero, across as many 32-bit words as needed.
  let i = 0;
  while (bits >= 32) { if (h[i] !== 0) return false; bits -= 32; i++; }
  return bits === 0 || (h[i] >>> (32 - bits)) === 0;
}


onmessage = (e) => {
  const { challenge, bits, a, start, step } = e.data;
  const hash = a === "sha512" ? sha512Searcher(challenge) : sha256Searcher(challenge);
  let nonce = start, done = 0;
  for (;;) {
    const h = hash(nonce);
    done++;
    if (meets(h, bits)) { postMessage({ found: nonce, done }); return; }
    nonce += step;
    if (done === 50000) { postMessage({ progress: done }); done = 0; }
  }
};
