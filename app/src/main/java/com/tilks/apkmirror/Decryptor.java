package com.tilks.apkmirror;

import android.app.PendingIntent;
import android.content.Intent;
import java.io.*;
import java.nio.charset.StandardCharsets;

/**
 * Decrypts an ApkMirror .apkm bundle into a plain .apks (zip) next to it.
 *
 * File layout (all integers little-endian): 1 byte version (1..126) 1 byte pwhash alg (1 = Argon2i13, 2 = Argon2id13) 8 bytes opslimit 8 bytes memlimit (1..512 MiB) 8 bytes chunk size 16 bytes salt 24 bytes secretstream header then chunks of (chunkSize + 17) bytes, XChaCha20-Poly1305 secretstream.
 */
class Decryptor {
  static final int CODE_LOG = 100;
  static final int CODE_DONE = 101;

  private static final String PASSWORD = "#$%@#dfas4d00fFSDF9GSD56$^53$%7WRGF3dzzqasD!@";
  private static final long MAX_MEM = 536870912L;

  private final String path;
  private final PendingIntent pi;
  private final android.content.Context ctx;

  private static final class Header {
    final byte[] key;
    final byte[] streamHeader;
    final int chunk;

    Header(byte[] key, byte[] streamHeader, int chunk) {
      this.key = key;
      this.streamHeader = streamHeader;
      this.chunk = chunk;
    }
  }

  Decryptor(android.content.Context ctx, String path, PendingIntent pi) {
    this.ctx = ctx;
    this.path = path;
    this.pi = pi;
  }

  private void log(String s) {
    if (pi == null)
      return;
    try {
      Intent i = new Intent();
      i.putExtra("result", s);
      pi.send(ctx, CODE_LOG, i);
    } catch (Exception ignored) {
    }
  }

  private void done() {
    if (pi == null)
      return;
    try {
      pi.send(CODE_DONE);
    } catch (Exception ignored) {
    }
  }

  private static byte[] read(InputStream in, int n) throws Exception {
    byte[] b = new byte[n];
    int got = 0;
    while (got < n) {
      int r = in.read(b, got, n - got);
      if (r < 0)
        break;
      got += r;
    }
    if (got != n)
      throw new Exception("Couldn't read requested number of bytes");
    return b;
  }

  private Header readHeader(InputStream in) throws Exception {
    byte[] ver = read(in, 1);
    byte[] alg = read(in, 1);
    byte[] ops = read(in, 8);
    byte[] mem = read(in, 8);
    byte[] chunk = read(in, 8);
    byte[] salt = read(in, 16);
    byte[] hdr = read(in, 24);

    int v = ver[0] & 0xFF;
    if (v > 126 || v == 0)
      throw new Exception("Version not supported");
    int a = alg[0] & 0xFF;
    if (a < 1 || a > 2)
      throw new Exception("Alg value not supported");
    long memLimit = Fmt.le(mem);
    if (memLimit <= 0 || memLimit > MAX_MEM)
      throw new Exception("Memory Limit out of bounds");
    long opsLimit = Fmt.le(ops);
    int chunkSize = (int) Fmt.le(chunk);

    byte[] pw = PASSWORD.getBytes(StandardCharsets.UTF_8);
    byte[] key;
    try {
      key = Crypto.argon2(a, pw, salt, opsLimit, memLimit, 32);
    } catch (OutOfMemoryError e) {
      throw new Exception("Generated status returned false");
    }
    return new Header(key, hdr, chunkSize);
  }

  void run() {
    long t0 = System.currentTimeMillis();
    log(String.format("%nStarting decrypt%n%n"));
    File src = new File(path);
    String parent = src.getParent();
    String name = src.getName();
    File out = null;
    FileInputStream in = null;
    FileOutputStream fos = null;
    try {
      if (!src.isFile()) {
        log(String.format("Error! File not found%n"));
        return;
      }
      log(String.format("File: %s(size: %s)%nfolder: %s%n", name, Fmt.size(src.length()), parent));
      if (!name.toLowerCase(java.util.Locale.US).endsWith(".apkm")) {
        log(String.format("Error! Only works with .apkm%n"));
        return;
      }
      out = new File(parent, name.substring(0, name.length() - 5) + ".apks");
      if (out.exists()) {
        log(String.format("File exist! Please delete file%n%s%c%s%n", parent, File.separatorChar,
            out.getName()));
        return;
      }
      if (!out.createNewFile()) {
        log(String.format("CreateFile Error! Exit!%n"));
        return;
      }
      in = new FileInputStream(src);
      Header h = readHeader(in);
      if (h.chunk <= 0)
        throw new Exception("Unable to decode file, status returned false");
      Crypto.Stream state = new Crypto.Stream(h.key, h.streamHeader);
      fos = new FileOutputStream(out);
      byte[] cipher = new byte[h.chunk + Crypto.ABYTES];
      byte[] plain = new byte[h.chunk];
      boolean finished = false;
      while (!finished) {
        int got = 0;
        while (got < cipher.length) {
          int r = in.read(cipher, got, cipher.length - got);
          if (r < 0)
            break;
          got += r;
        }
        if (got == 0)
          break;
        int tag = state.pull(cipher, got, plain);
        if (tag < 0) {
          log(String.format("Unable to decode file, status returned false%n"));
          throw new Exception("Unable to decode file, status returned false");
        }
        fos.write(plain, 0, got - Crypto.ABYTES);
        if (tag == Crypto.TAG_FINAL)
          finished = true;
      }
      fos.flush();
      log(String.format("%nDecrypt OK%n"));
      log(String.format("Create Apks File: %s%c%s%n", parent, File.separatorChar, out.getName()));
      log(String.format("%nCompleted successfully in %s%n",
          Fmt.time(System.currentTimeMillis() - t0)));
    } catch (Exception e) {
      e.printStackTrace();
      if (out != null && out.exists()
          && !(e.getMessage() != null && e.getMessage().startsWith("File exist"))) {
        // do not leave a half-written file behind
        try {
          if (fos != null)
            fos.close();
        } catch (IOException ignored) {
        }
        fos = null;
        out.delete();
      }
      log(String.format("Cannot decrypt selected file with specified values%n"));
    } finally {
      try {
        if (in != null)
          in.close();
      } catch (IOException ignored) {
      }
      try {
        if (fos != null)
          fos.close();
      } catch (IOException ignored) {
      }
      done();
    }
  }
}
