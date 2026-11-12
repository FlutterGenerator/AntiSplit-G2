package com.tilks.arsc.merge;

import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Map;

/**
 * JAR (v1) signer. The PKCS#7 block is the bundled template (testkey.past: everything except the final 256-byte RSA signature) followed by a fresh SHA1withRSA signature over CERT.SF made with testkey.pk8.
 */
public final class PseudoApkSigner {
  public static final String CREATED_BY = "PseudoApkSigner 1.6 (AntiSplit-G2)";

  private static byte[] sha1(byte[] d) throws Exception {
    return MessageDigest.getInstance("SHA-1").digest(d);
  }

  private static String b64(byte[] d) {
    final String t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < d.length; i += 3) {
      int v = (d[i] & 0xff) << 16;
      if (i + 1 < d.length)
        v |= (d[i + 1] & 0xff) << 8;
      if (i + 2 < d.length)
        v |= (d[i + 2] & 0xff);
      sb.append(t.charAt((v >> 18) & 63)).append(t.charAt((v >> 12) & 63));
      sb.append(i + 1 < d.length ? t.charAt((v >> 6) & 63) : '=');
      sb.append(i + 2 < d.length ? t.charAt(v & 63) : '=');
    }
    return sb.toString();
  }

  private static void line(ByteArrayOutputStream o, String l) throws Exception {
    byte[] b = l.getBytes("UTF-8");
    int pos = 0;
    int max = 72;
    while (b.length - pos > max) {
      o.write(b, pos, max);
      o.write('\r');
      o.write('\n');
      pos += max;
      o.write(' ');
      max = 71;
    }
    o.write(b, pos, b.length - pos);
    o.write('\r');
    o.write('\n');
  }

  /** Returns {MANIFEST.MF, CERT.SF, CERT.RSA}. */
  public static byte[][] sign(Map<String, byte[]> digests, byte[] template, byte[] pk8)
      throws Exception {
    ByteArrayOutputStream mf = new ByteArrayOutputStream();
    line(mf, "Manifest-Version: 1.0");
    line(mf, "Created-By: " + CREATED_BY);
    line(mf, "");
    ByteArrayOutputStream sf = new ByteArrayOutputStream();
    ByteArrayOutputStream sections = new ByteArrayOutputStream();
    for (Map.Entry<String, byte[]> e : digests.entrySet()) {
      ByteArrayOutputStream sec = new ByteArrayOutputStream();
      line(sec, "Name: " + e.getKey());
      line(sec, "SHA1-Digest: " + b64(e.getValue()));
      line(sec, "");
      byte[] s = sec.toByteArray();
      mf.write(s, 0, s.length);
      ByteArrayOutputStream ss = new ByteArrayOutputStream();
      line(ss, "Name: " + e.getKey());
      line(ss, "SHA1-Digest: " + b64(sha1(s)));
      line(ss, "");
      byte[] sb = ss.toByteArray();
      sections.write(sb, 0, sb.length);
    }
    byte[] mfb = mf.toByteArray();
    line(sf, "Signature-Version: 1.0");
    line(sf, "Created-By: " + CREATED_BY);
    line(sf, "SHA1-Digest-Manifest: " + b64(sha1(mfb)));
    line(sf, "");
    byte[] sec = sections.toByteArray();
    sf.write(sec, 0, sec.length);
    byte[] sfb = sf.toByteArray();

    PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pk8));
    Signature sig = Signature.getInstance("SHA1withRSA");
    sig.initSign(key);
    sig.update(sfb);
    byte[] sigBytes = sig.sign();
    byte[] rsa = new byte[template.length + sigBytes.length];
    System.arraycopy(template, 0, rsa, 0, template.length);
    System.arraycopy(sigBytes, 0, rsa, template.length, sigBytes.length);
    return new byte[][] { mfb, sfb, rsa };
  }
}
