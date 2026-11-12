package com.tilks.arsc.merge;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Android binary string pool (RES_STRING_POOL_TYPE) with optional styles. */
public final class StringPool {
  public static final int FLAG_SORTED = 0x1;
  public static final int FLAG_UTF8 = 0x100;

  public int flags;
  public final List<String> strings = new ArrayList<>();
  /** styles.get(i) = spans of string i, each span = {nameIdx, firstChar, lastChar}. size() <= strings.size(). */
  public final List<List<int[]>> styles = new ArrayList<>();
  private final Map<String, Integer> plain = new HashMap<>();
  public int chunkSize;

  public StringPool(boolean utf8) {
    flags = utf8 ? FLAG_UTF8 : 0;
  }

  public boolean isUtf8() {
    return (flags & FLAG_UTF8) != 0;
  }

  public static StringPool parse(byte[] d, int pos) {
    ByteBuffer b = ByteBuffer.wrap(d).order(ByteOrder.LITTLE_ENDIAN);
    int type = b.getShort(pos) & 0xffff;
    if (type != 0x0001)
      throw new IllegalStateException("Not a string pool chunk at " + pos);
    int hs = b.getShort(pos + 2) & 0xffff;
    int size = b.getInt(pos + 4);
    int sc = b.getInt(pos + 8);
    int stc = b.getInt(pos + 12);
    int flags = b.getInt(pos + 16);
    int ss = b.getInt(pos + 20);
    int sts = b.getInt(pos + 24);
    StringPool p = new StringPool((flags & FLAG_UTF8) != 0);
    p.flags = flags;
    p.chunkSize = size;
    boolean utf8 = p.isUtf8();
    int offsPos = pos + hs;
    for (int i = 0; i < sc; i++) {
      int off = b.getInt(offsPos + 4 * i);
      int q = pos + ss + off;
      String s;
      if (utf8) {
        int l = d[q++] & 0xff;
        if ((l & 0x80) != 0)
          q++;
        int bl = d[q++] & 0xff;
        if ((bl & 0x80) != 0) {
          bl = ((bl & 0x7f) << 8) | (d[q++] & 0xff);
        }
        s = new String(d, q, bl, StandardCharsets.UTF_8);
      } else {
        int l = b.getShort(q) & 0xffff;
        q += 2;
        if ((l & 0x8000) != 0) {
          l = ((l & 0x7fff) << 16) | (b.getShort(q) & 0xffff);
          q += 2;
        }
        s = new String(d, q, l * 2, StandardCharsets.UTF_16LE);
      }
      p.strings.add(s);
    }
    int styOffsPos = offsPos + 4 * sc;
    for (int i = 0; i < stc; i++) {
      int off = b.getInt(styOffsPos + 4 * i);
      int q = pos + sts + off;
      List<int[]> spans = new ArrayList<>();
      while (true) {
        int name = b.getInt(q);
        if (name == -1)
          break;
        spans.add(new int[] { name, b.getInt(q + 4), b.getInt(q + 8) });
        q += 12;
      }
      p.styles.add(spans);
    }
    for (int i = 0; i < p.strings.size(); i++) {
      if (i >= p.styles.size() || p.styles.get(i).isEmpty()) {
        p.plain.putIfAbsent(p.strings.get(i), i);
      }
    }
    return p;
  }

  /** Index of a plain (unstyled) string, appending it if missing. */
  public int add(String s) {
    Integer i = plain.get(s);
    if (i != null)
      return i;
    int idx = strings.size();
    strings.add(s);
    plain.put(s, idx);
    return idx;
  }

  /** Appends a styled string (never deduplicated). */
  public int addStyled(String s, List<int[]> spans) {
    while (styles.size() < strings.size())
      styles.add(new ArrayList<int[]>());
    int idx = strings.size();
    strings.add(s);
    styles.add(spans);
    return idx;
  }

  public List<int[]> spansOf(int idx) {
    if (idx < styles.size())
      return styles.get(idx);
    return new ArrayList<>();
  }

  private void encode(String s, ByteArrayOutputStream o) {
    if (isUtf8()) {
      byte[] u = s.getBytes(StandardCharsets.UTF_8);
      writeLen8(o, s.length());
      writeLen8(o, u.length);
      o.write(u, 0, u.length);
      o.write(0);
    } else {
      int l = s.length();
      if (l > 0x7fff) {
        int hi = (l >> 16) | 0x8000;
        o.write(hi & 0xff);
        o.write((hi >> 8) & 0xff);
        o.write(l & 0xff);
        o.write((l >> 8) & 0xff);
      } else {
        o.write(l & 0xff);
        o.write((l >> 8) & 0xff);
      }
      byte[] u = s.getBytes(StandardCharsets.UTF_16LE);
      o.write(u, 0, u.length);
      o.write(0);
      o.write(0);
    }
  }

  private static void writeLen8(ByteArrayOutputStream o, int l) {
    if (l > 0x7f) {
      o.write((l >> 8) | 0x80);
      o.write(l & 0xff);
    } else {
      o.write(l);
    }
  }

  private static void putInt(ByteArrayOutputStream o, int v) {
    o.write(v & 0xff);
    o.write((v >> 8) & 0xff);
    o.write((v >> 16) & 0xff);
    o.write((v >>> 24) & 0xff);
  }

  public byte[] write() {
    int n = strings.size();
    int sn = styles.size();
    ByteArrayOutputStream sb = new ByteArrayOutputStream();
    int[] offs = new int[n];
    for (int i = 0; i < n; i++) {
      offs[i] = sb.size();
      encode(strings.get(i), sb);
    }
    while (sb.size() % 4 != 0)
      sb.write(0);
    ByteArrayOutputStream yb = new ByteArrayOutputStream();
    int[] yoffs = new int[sn];
    for (int i = 0; i < sn; i++) {
      yoffs[i] = yb.size();
      for (int[] sp : styles.get(i)) {
        putInt(yb, sp[0]);
        putInt(yb, sp[1]);
        putInt(yb, sp[2]);
      }
      putInt(yb, -1);
    }
    if (sn > 0) {
      putInt(yb, -1);
      putInt(yb, -1);
    }
    int hs = 28;
    int stringsStart = hs + 4 * n + 4 * sn;
    int stylesStart = sn > 0 ? stringsStart + sb.size() : 0;
    int size = stringsStart + sb.size() + yb.size();
    ByteArrayOutputStream o = new ByteArrayOutputStream(size);
    o.write(0x01);
    o.write(0x00);
    o.write(hs & 0xff);
    o.write((hs >> 8) & 0xff);
    putInt(o, size);
    putInt(o, n);
    putInt(o, sn);
    putInt(o, flags & ~FLAG_SORTED);
    putInt(o, stringsStart);
    putInt(o, stylesStart);
    for (int i = 0; i < n; i++)
      putInt(o, offs[i]);
    for (int i = 0; i < sn; i++)
      putInt(o, yoffs[i]);
    byte[] sbb = sb.toByteArray();
    o.write(sbb, 0, sbb.length);
    byte[] ybb = yb.toByteArray();
    o.write(ybb, 0, ybb.length);
    return o.toByteArray();
  }
}
