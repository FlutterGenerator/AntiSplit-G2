package com.tilks.apkmirror;

/**
 * Pure-Java replacement for the parts of libsodium used by .apkm decryption: Argon2 (i / id, v1.3, 1 lane), HChaCha20, ChaCha20, Poly1305 and crypto_secretstream_xchacha20poly1305 (pull side only). No external libraries.
 */
final class Crypto {
  private Crypto() {
  }

  // ---------------------------------------------------------------- Blake2b
  private static final long[] IV = { 0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL,
      0xa54ff53a5f1d36f1L, 0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL,
      0x5be0cd19137e2179L };
  private static final byte[][] SIGMA = { { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
      { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
      { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
      { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
      { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
      { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
      { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
      { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
      { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
      { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 } };

  private static long le64(byte[] b, int o) {
    long r = 0;
    for (int i = 7; i >= 0; i--)
      r = (r << 8) | (b[o + i] & 0xFFL);
    return r;
  }

  private static void put64(byte[] b, int o, long v) {
    for (int i = 0; i < 8; i++) {
      b[o + i] = (byte) v;
      v >>>= 8;
    }
  }

  private static void g(long[] v, long[] m, int r, int i, int a, int b, int c, int d) {
    v[a] = v[a] + v[b] + m[SIGMA[r][2 * i]];
    v[d] = Long.rotateRight(v[d] ^ v[a], 32);
    v[c] = v[c] + v[d];
    v[b] = Long.rotateRight(v[b] ^ v[c], 24);
    v[a] = v[a] + v[b] + m[SIGMA[r][2 * i + 1]];
    v[d] = Long.rotateRight(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = Long.rotateRight(v[b] ^ v[c], 63);
  }

  static byte[] blake2b(byte[] in, int outLen) {
    long[] h = IV.clone();
    h[0] ^= 0x01010000L ^ outLen;
    long[] m = new long[16];
    long[] v = new long[16];
    byte[] blk = new byte[128];
    long t = 0;
    int pos = 0;
    int len = in.length;
    do {
      int n = Math.min(128, len - pos);
      boolean last = pos + n >= len;
      java.util.Arrays.fill(blk, (byte) 0);
      System.arraycopy(in, pos, blk, 0, n);
      t += n;
      for (int i = 0; i < 16; i++)
        m[i] = le64(blk, i * 8);
      System.arraycopy(h, 0, v, 0, 8);
      System.arraycopy(IV, 0, v, 8, 8);
      v[12] ^= t;
      if (last)
        v[14] = ~v[14];
      for (int r = 0; r < 12; r++) {
        int s = r % 10;
        g(v, m, s, 0, 0, 4, 8, 12);
        g(v, m, s, 1, 1, 5, 9, 13);
        g(v, m, s, 2, 2, 6, 10, 14);
        g(v, m, s, 3, 3, 7, 11, 15);
        g(v, m, s, 4, 0, 5, 10, 15);
        g(v, m, s, 5, 1, 6, 11, 12);
        g(v, m, s, 6, 2, 7, 8, 13);
        g(v, m, s, 7, 3, 4, 9, 14);
      }
      for (int i = 0; i < 8; i++)
        h[i] ^= v[i] ^ v[i + 8];
      pos += n;
    } while (pos < len);
    byte[] out = new byte[64];
    for (int i = 0; i < 8; i++)
      put64(out, i * 8, h[i]);
    return java.util.Arrays.copyOf(out, outLen);
  }

  // ----------------------------------------------------------------- Argon2
  private static byte[] cat(byte[]... parts) {
    int n = 0;
    for (byte[] p : parts)
      n += p.length;
    byte[] r = new byte[n];
    int o = 0;
    for (byte[] p : parts) {
      System.arraycopy(p, 0, r, o, p.length);
      o += p.length;
    }
    return r;
  }

  private static byte[] le32(long v) {
    return new byte[] { (byte) v, (byte) (v >>> 8), (byte) (v >>> 16), (byte) (v >>> 24) };
  }

  private static byte[] hPrime(byte[] x, int outLen) {
    byte[] in = cat(le32(outLen), x);
    if (outLen <= 64)
      return blake2b(in, outLen);
    byte[] out = new byte[outLen];
    int r = (outLen + 31) / 32 - 2;
    byte[] v = blake2b(in, 64);
    System.arraycopy(v, 0, out, 0, 32);
    int o = 32;
    for (int i = 2; i <= r; i++) {
      v = blake2b(v, 64);
      System.arraycopy(v, 0, out, o, 32);
      o += 32;
    }
    v = blake2b(v, outLen - 32 * r);
    System.arraycopy(v, 0, out, o, outLen - 32 * r);
    return out;
  }

  private static long fBla(long x, long y) {
    return x + y + 2L * (x & 0xFFFFFFFFL) * (y & 0xFFFFFFFFL);
  }

  private static void gb(long[] v, int a, int b, int c, int d) {
    v[a] = fBla(v[a], v[b]);
    v[d] = Long.rotateRight(v[d] ^ v[a], 32);
    v[c] = fBla(v[c], v[d]);
    v[b] = Long.rotateRight(v[b] ^ v[c], 24);
    v[a] = fBla(v[a], v[b]);
    v[d] = Long.rotateRight(v[d] ^ v[a], 16);
    v[c] = fBla(v[c], v[d]);
    v[b] = Long.rotateRight(v[b] ^ v[c], 63);
  }

  /** next = G(x, y) (xored into next when xor is true); all blocks are 128 longs. */
  private static void fill(long[] x, long[] y, long[] next, boolean xor) {
    long[] r = new long[128];
    long[] z = new long[128];
    for (int i = 0; i < 128; i++) {
      r[i] = x[i] ^ y[i];
      z[i] = r[i];
    }
    long[] v = new long[16];
    for (int row = 0; row < 8; row++) {
      for (int k = 0; k < 16; k++)
        v[k] = z[16 * row + k];
      round(v);
      for (int k = 0; k < 16; k++)
        z[16 * row + k] = v[k];
    }
    for (int col = 0; col < 8; col++) {
      for (int k = 0; k < 8; k++) {
        v[2 * k] = z[2 * col + 16 * k];
        v[2 * k + 1] = z[2 * col + 16 * k + 1];
      }
      round(v);
      for (int k = 0; k < 8; k++) {
        z[2 * col + 16 * k] = v[2 * k];
        z[2 * col + 16 * k + 1] = v[2 * k + 1];
      }
    }
    for (int i = 0; i < 128; i++) {
      long o = z[i] ^ r[i];
      next[i] = xor ? next[i] ^ o : o;
    }
  }

  private static void round(long[] v) {
    gb(v, 0, 4, 8, 12);
    gb(v, 1, 5, 9, 13);
    gb(v, 2, 6, 10, 14);
    gb(v, 3, 7, 11, 15);
    gb(v, 0, 5, 10, 15);
    gb(v, 1, 6, 11, 12);
    gb(v, 2, 7, 8, 13);
    gb(v, 3, 4, 9, 14);
  }

  /**
   * Argon2 raw hash, one lane, no secret / associated data (what libsodium's crypto_pwhash does).
   *
   * @param type 1 = Argon2i, 2 = Argon2id
   */
  static byte[] argon2(int type, byte[] pw, byte[] salt, long passes, long memBytes, int outLen) {
    final int version = 0x13;
    long mKib = memBytes / 1024L;
    if (mKib < 8)
      mKib = 8;
    int laneLen = (int) (mKib / 4 * 4);
    int seg = laneLen / 4;
    byte[] h0 = blake2b(cat(le32(1), le32(outLen), le32(mKib), le32(passes), le32(version),
        le32(type), le32(pw.length), pw, le32(salt.length), salt, le32(0), le32(0)), 64);
    long[][] mem = new long[laneLen][];
    for (int b = 0; b < 2; b++) {
      byte[] blk = hPrime(cat(h0, le32(b), le32(0)), 1024);
      long[] w = new long[128];
      for (int i = 0; i < 128; i++)
        w[i] = le64(blk, i * 8);
      mem[b] = w;
    }
    long[] zero = new long[128];
    long[] input = new long[128];
    long[] addr = new long[128];
    for (int pass = 0; pass < passes; pass++) {
      for (int slice = 0; slice < 4; slice++) {
        boolean indep = type == 1 || (type == 2 && pass == 0 && slice < 2);
        int start = 0;
        if (indep) {
          java.util.Arrays.fill(input, 0);
          input[0] = pass;
          input[1] = 0;
          input[2] = slice;
          input[3] = laneLen;
          input[4] = passes;
          input[5] = type;
        }
        if (pass == 0 && slice == 0) {
          start = 2;
          if (indep)
            nextAddr(input, addr, zero);
        }
        for (int i = start; i < seg; i++) {
          int cur = slice * seg + i;
          int prev = cur == 0 ? laneLen - 1 : cur - 1;
          long rnd;
          if (indep) {
            if (i % 128 == 0)
              nextAddr(input, addr, zero);
            rnd = addr[i % 128];
          } else {
            rnd = mem[prev][0];
          }
          long j1 = rnd & 0xFFFFFFFFL;
          long area;
          if (pass == 0) {
            area = slice == 0 ? i - 1 : (long) slice * seg + i - 1;
          } else {
            area = laneLen - seg + i - 1;
          }
          long rp = (j1 * j1) >>> 32;
          rp = area - 1 - ((area * rp) >>> 32);
          long s0 = pass == 0 ? 0 : (slice == 3 ? 0 : (long) (slice + 1) * seg);
          int ref = (int) ((s0 + rp) % laneLen);
          if (mem[cur] == null)
            mem[cur] = new long[128];
          fill(mem[prev], mem[ref], mem[cur], pass != 0);
        }
      }
    }
    long[] fin = mem[laneLen - 1].clone();
    byte[] c = new byte[1024];
    for (int i = 0; i < 128; i++)
      put64(c, i * 8, fin[i]);
    return hPrime(c, outLen);
  }

  private static void nextAddr(long[] input, long[] addr, long[] zero) {
    input[6]++;
    fill(zero, input, addr, false);
    fill(zero, addr, addr, false);
  }

  // --------------------------------------------------------------- ChaCha20
  private static int rotl(int v, int c) {
    return (v << c) | (v >>> (32 - c));
  }

  private static void qr(int[] x, int a, int b, int c, int d) {
    x[a] += x[b];
    x[d] = rotl(x[d] ^ x[a], 16);
    x[c] += x[d];
    x[b] = rotl(x[b] ^ x[c], 12);
    x[a] += x[b];
    x[d] = rotl(x[d] ^ x[a], 8);
    x[c] += x[d];
    x[b] = rotl(x[b] ^ x[c], 7);
  }

  private static int le32i(byte[] b, int o) {
    return (b[o] & 0xFF) | (b[o + 1] & 0xFF) << 8 | (b[o + 2] & 0xFF) << 16
        | (b[o + 3] & 0xFF) << 24;
  }

  private static void rounds(int[] x) {
    for (int i = 0; i < 10; i++) {
      qr(x, 0, 4, 8, 12);
      qr(x, 1, 5, 9, 13);
      qr(x, 2, 6, 10, 14);
      qr(x, 3, 7, 11, 15);
      qr(x, 0, 5, 10, 15);
      qr(x, 1, 6, 11, 12);
      qr(x, 2, 7, 8, 13);
      qr(x, 3, 4, 9, 14);
    }
  }

  static byte[] hchacha20(byte[] key, byte[] in16) {
    int[] x = new int[16];
    x[0] = 0x61707865;
    x[1] = 0x3320646e;
    x[2] = 0x79622d32;
    x[3] = 0x6b206574;
    for (int i = 0; i < 8; i++)
      x[4 + i] = le32i(key, 4 * i);
    for (int i = 0; i < 4; i++)
      x[12 + i] = le32i(in16, 4 * i);
    rounds(x);
    byte[] out = new byte[32];
    int[] idx = { 0, 1, 2, 3, 12, 13, 14, 15 };
    for (int i = 0; i < 8; i++) {
      int v = x[idx[i]];
      out[4 * i] = (byte) v;
      out[4 * i + 1] = (byte) (v >>> 8);
      out[4 * i + 2] = (byte) (v >>> 16);
      out[4 * i + 3] = (byte) (v >>> 24);
    }
    return out;
  }

  /** XORs the IETF ChaCha20 keystream (96-bit nonce) starting at block counter ic into buf[off..off+len). */
  static void chacha20Xor(byte[] key, byte[] nonce12, int ic, byte[] src, int so, byte[] dst,
      int dof, int len) {
    int[] st = new int[16];
    st[0] = 0x61707865;
    st[1] = 0x3320646e;
    st[2] = 0x79622d32;
    st[3] = 0x6b206574;
    for (int i = 0; i < 8; i++)
      st[4 + i] = le32i(key, 4 * i);
    st[13] = le32i(nonce12, 0);
    st[14] = le32i(nonce12, 4);
    st[15] = le32i(nonce12, 8);
    int[] x = new int[16];
    int done = 0;
    int ctr = ic;
    while (done < len) {
      st[12] = ctr++;
      System.arraycopy(st, 0, x, 0, 16);
      rounds(x);
      int n = Math.min(64, len - done);
      for (int i = 0; i < n; i++) {
        int w = x[i >> 2] + st[i >> 2];
        byte ks = (byte) (w >>> (8 * (i & 3)));
        dst[dof + done + i] = (byte) ((src == null ? 0 : src[so + done + i]) ^ ks);
      }
      done += n;
    }
  }

  // --------------------------------------------------------------- Poly1305
  private static final class Poly {
    private final long r0, r1, r2, r3, r4, s1, s2, s3, s4;
    private final int[] pad = new int[4];
    private long h0, h1, h2, h3, h4;
    private final byte[] buf = new byte[16];
    private int fill;

    Poly(byte[] k) {
      r0 = (le32i(k, 0)) & 0x3ffffffL;
      r1 = ((le32i(k, 3) >>> 2)) & 0x3ffff03L;
      r2 = ((le32i(k, 6) >>> 4)) & 0x3ffc0ffL;
      r3 = ((le32i(k, 9) >>> 6)) & 0x3f03fffL;
      r4 = ((le32i(k, 12) >>> 8)) & 0x00fffffL;
      s1 = r1 * 5;
      s2 = r2 * 5;
      s3 = r3 * 5;
      s4 = r4 * 5;
      for (int i = 0; i < 4; i++)
        pad[i] = le32i(k, 16 + 4 * i);
    }

    private void block(byte[] m, int o, long hibit) {
      long t0 = le32i(m, o) & 0xFFFFFFFFL;
      long t1 = le32i(m, o + 4) & 0xFFFFFFFFL;
      long t2 = le32i(m, o + 8) & 0xFFFFFFFFL;
      long t3 = le32i(m, o + 12) & 0xFFFFFFFFL;
      h0 += t0 & 0x3ffffffL;
      h1 += ((t1 << 32 | t0) >>> 26) & 0x3ffffffL;
      h2 += ((t2 << 32 | t1) >>> 20) & 0x3ffffffL;
      h3 += ((t3 << 32 | t2) >>> 14) & 0x3ffffffL;
      h4 += (t3 >>> 8) | hibit;
      long d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
      long d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
      long d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
      long d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
      long d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
      long c = d0 >>> 26;
      h0 = d0 & 0x3ffffffL;
      d1 += c;
      c = d1 >>> 26;
      h1 = d1 & 0x3ffffffL;
      d2 += c;
      c = d2 >>> 26;
      h2 = d2 & 0x3ffffffL;
      d3 += c;
      c = d3 >>> 26;
      h3 = d3 & 0x3ffffffL;
      d4 += c;
      c = d4 >>> 26;
      h4 = d4 & 0x3ffffffL;
      h0 += c * 5;
      c = h0 >>> 26;
      h0 &= 0x3ffffffL;
      h1 += c;
    }

    void update(byte[] m, int off, int len) {
      while (len > 0) {
        if (fill == 0 && len >= 16) {
          block(m, off, 1L << 24);
          off += 16;
          len -= 16;
        } else {
          int n = Math.min(16 - fill, len);
          System.arraycopy(m, off, buf, fill, n);
          fill += n;
          off += n;
          len -= n;
          if (fill == 16) {
            block(buf, 0, 1L << 24);
            fill = 0;
          }
        }
      }
    }

    byte[] finish() {
      if (fill > 0) {
        buf[fill] = 1;
        for (int i = fill + 1; i < 16; i++)
          buf[i] = 0;
        block(buf, 0, 0);
      }
      long c = h1 >>> 26;
      h1 &= 0x3ffffffL;
      h2 += c;
      c = h2 >>> 26;
      h2 &= 0x3ffffffL;
      h3 += c;
      c = h3 >>> 26;
      h3 &= 0x3ffffffL;
      h4 += c;
      c = h4 >>> 26;
      h4 &= 0x3ffffffL;
      h0 += c * 5;
      c = h0 >>> 26;
      h0 &= 0x3ffffffL;
      h1 += c;
      long g0 = h0 + 5;
      c = g0 >>> 26;
      g0 &= 0x3ffffffL;
      long g1 = h1 + c;
      c = g1 >>> 26;
      g1 &= 0x3ffffffL;
      long g2 = h2 + c;
      c = g2 >>> 26;
      g2 &= 0x3ffffffL;
      long g3 = h3 + c;
      c = g3 >>> 26;
      g3 &= 0x3ffffffL;
      long g4 = h4 + c - (1L << 26);
      long mask = (g4 >>> 63) - 1;
      g0 &= mask;
      g1 &= mask;
      g2 &= mask;
      g3 &= mask;
      g4 &= mask;
      mask = ~mask;
      h0 = (h0 & mask) | g0;
      h1 = (h1 & mask) | g1;
      h2 = (h2 & mask) | g2;
      h3 = (h3 & mask) | g3;
      h4 = (h4 & mask) | g4;
      long w0 = ((h0) | (h1 << 26)) & 0xFFFFFFFFL;
      long w1 = ((h1 >>> 6) | (h2 << 20)) & 0xFFFFFFFFL;
      long w2 = ((h2 >>> 12) | (h3 << 14)) & 0xFFFFFFFFL;
      long w3 = ((h3 >>> 18) | (h4 << 8)) & 0xFFFFFFFFL;
      w0 += pad[0] & 0xFFFFFFFFL;
      w1 += (pad[1] & 0xFFFFFFFFL) + (w0 >>> 32);
      w2 += (pad[2] & 0xFFFFFFFFL) + (w1 >>> 32);
      w3 += (pad[3] & 0xFFFFFFFFL) + (w2 >>> 32);
      byte[] t = new byte[16];
      long[] w = { w0, w1, w2, w3 };
      for (int i = 0; i < 4; i++) {
        t[4 * i] = (byte) w[i];
        t[4 * i + 1] = (byte) (w[i] >>> 8);
        t[4 * i + 2] = (byte) (w[i] >>> 16);
        t[4 * i + 3] = (byte) (w[i] >>> 24);
      }
      return t;
    }
  }

  // ----------------------------------- crypto_secretstream_xchacha20poly1305
  static final int ABYTES = 17;
  static final byte TAG_REKEY = 2;
  static final byte TAG_FINAL = 3;

  static final class Stream {
    private byte[] key;
    private final byte[] nonce = new byte[12];

    Stream(byte[] key, byte[] header24) {
      this.key = hchacha20(key, java.util.Arrays.copyOfRange(header24, 0, 16));
      nonce[0] = 1;
      System.arraycopy(header24, 16, nonce, 4, 8);
    }

    /**
     * Decrypts one message. in = tag(1) + ciphertext(n) + mac(16), length inLen. Plaintext (inLen - 17 bytes) is written to out; returns the tag or -1 on authentication failure.
     */
    int pull(byte[] in, int inLen, byte[] out) {
      int mlen = inLen - ABYTES;
      if (mlen < 0)
        return -1;
      byte[] block = new byte[64];
      chacha20Xor(key, nonce, 0, null, 0, block, 0, 64);
      Poly p = new Poly(java.util.Arrays.copyOf(block, 32));
      java.util.Arrays.fill(block, (byte) 0);
      block[0] = in[0];
      chacha20Xor(key, nonce, 1, block, 0, block, 0, 64);
      byte tag = block[0];
      block[0] = in[0];
      p.update(block, 0, 64);
      p.update(in, 1, mlen);
      int pad = (0x10 - 64 + mlen) & 0xf;
      if (pad > 0)
        p.update(new byte[pad], 0, pad);
      byte[] lens = new byte[16];
      put64(lens, 8, 64L + mlen);
      p.update(lens, 0, 16);
      byte[] mac = p.finish();
      int diff = 0;
      for (int i = 0; i < 16; i++)
        diff |= mac[i] ^ in[1 + mlen + i];
      if (diff != 0)
        return -1;
      chacha20Xor(key, nonce, 2, in, 1, out, 0, mlen);
      for (int i = 0; i < 8; i++)
        nonce[4 + i] ^= mac[i];
      boolean wrap = true;
      for (int i = 0; i < 4; i++) {
        if (++nonce[i] != 0) {
          wrap = false;
          break;
        }
      }
      if ((tag & TAG_REKEY) != 0 || wrap)
        rekey();
      return tag & 0xFF;
    }

    private void rekey() {
      byte[] ki = new byte[40];
      System.arraycopy(key, 0, ki, 0, 32);
      System.arraycopy(nonce, 4, ki, 32, 8);
      chacha20Xor(key, nonce, 0, ki, 0, ki, 0, 40);
      key = java.util.Arrays.copyOf(ki, 32);
      System.arraycopy(ki, 32, nonce, 4, 8);
      nonce[0] = 1;
      nonce[1] = nonce[2] = nonce[3] = 0;
    }
  }
}
