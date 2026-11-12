package com.tilks.arsc.merge;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

/** Parses resources.arsc and merges the configuration chunks of split APK tables into a base table. */
public final class ArscMerger {
  static final int RES_TABLE = 0x0002;
  static final int RES_POOL = 0x0001;
  static final int RES_PKG = 0x0200;
  static final int RES_TYPE = 0x0201;
  static final int RES_SPEC = 0x0202;

  public static final class Chunk {
    public int type;
    public int typeId = -1;
    public byte[] cfg;
    public byte[] data;
  }

  public static final class Pkg {
    public int id;
    public byte[] header;
    public byte[] typePoolRaw;
    public StringPool keyPool;
    public final List<Chunk> chunks = new ArrayList<>();
  }

  public static final class Table {
    public StringPool global;
    public final List<Pkg> pkgs = new ArrayList<>();

    Pkg find(int id) {
      for (Pkg p : pkgs)
        if (p.id == id)
          return p;
      return null;
    }
  }

  private static ByteBuffer buf(byte[] d) {
    return ByteBuffer.wrap(d).order(ByteOrder.LITTLE_ENDIAN);
  }

  public static Table parse(byte[] d) {
    ByteBuffer b = buf(d);
    if ((b.getShort(0) & 0xffff) != RES_TABLE)
      throw new IllegalStateException("Not a resource table");
    int hs = b.getShort(2) & 0xffff;
    int total = Math.min(b.getInt(4), d.length);
    Table t = new Table();
    int pos = hs;
    while (pos + 8 <= total) {
      int type = b.getShort(pos) & 0xffff;
      int size = b.getInt(pos + 4);
      if (size <= 0)
        break;
      if (type == RES_POOL) {
        if (t.global != null)
          throw new IllegalStateException("Multiple string pools not supported");
        t.global = StringPool.parse(d, pos);
      } else if (type == RES_PKG) {
        t.pkgs.add(parsePkg(d, pos));
      }
      pos += size;
    }
    if (t.global == null)
      throw new IllegalStateException("No global string pool");
    return t;
  }

  private static Pkg parsePkg(byte[] d, int pos) {
    ByteBuffer b = buf(d);
    int hs = b.getShort(pos + 2) & 0xffff;
    int size = b.getInt(pos + 4);
    Pkg p = new Pkg();
    p.id = b.getInt(pos + 8);
    p.header = Arrays.copyOfRange(d, pos, pos + hs);
    int typeOff = b.getInt(pos + 268);
    int keyOff = b.getInt(pos + 276);
    int q = pos + hs;
    int end = pos + size;
    while (q + 8 <= end) {
      int type = b.getShort(q) & 0xffff;
      int chs = b.getShort(q + 2) & 0xffff;
      int csz = b.getInt(q + 4);
      if (csz <= 0)
        break;
      if (type == RES_POOL) {
        if (q - pos == typeOff) {
          p.typePoolRaw = Arrays.copyOfRange(d, q, q + csz);
        } else if (q - pos == keyOff) {
          p.keyPool = StringPool.parse(d, q);
        }
      } else {
        Chunk c = new Chunk();
        c.type = type;
        c.data = Arrays.copyOfRange(d, q, q + csz);
        if (type == RES_SPEC || type == RES_TYPE) {
          c.typeId = d[q + 8] & 0xff;
          if (type == RES_TYPE) {
            int cs = b.getInt(q + 20);
            c.cfg = Arrays.copyOfRange(d, q + 20, q + 20 + cs);
          }
        }
        p.chunks.add(c);
      }
      q += csz;
    }
    if (p.typePoolRaw == null || p.keyPool == null)
      throw new IllegalStateException("Package without type/key pool");
    return p;
  }

  private static void putInt(byte[] a, int off, int v) {
    a[off] = (byte) v;
    a[off + 1] = (byte) (v >> 8);
    a[off + 2] = (byte) (v >> 16);
    a[off + 3] = (byte) (v >>> 24);
  }

  private static void writeInt(ByteArrayOutputStream o, int v) {
    o.write(v & 0xff);
    o.write((v >> 8) & 0xff);
    o.write((v >> 16) & 0xff);
    o.write((v >>> 24) & 0xff);
  }

  public static byte[] write(Table t) {
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    byte[] g = t.global.write();
    body.write(g, 0, g.length);
    for (Pkg p : t.pkgs) {
      byte[] kp = p.keyPool.write();
      int hs = p.header.length;
      int size = hs + p.typePoolRaw.length + kp.length;
      for (Chunk c : p.chunks)
        size += c.data.length;
      byte[] h = p.header.clone();
      putInt(h, 4, size);
      putInt(h, 268, hs);
      putInt(h, 276, hs + p.typePoolRaw.length);
      body.write(h, 0, h.length);
      body.write(p.typePoolRaw, 0, p.typePoolRaw.length);
      body.write(kp, 0, kp.length);
      for (Chunk c : p.chunks)
        body.write(c.data, 0, c.data.length);
    }
    ByteArrayOutputStream o = new ByteArrayOutputStream();
    o.write(0x02);
    o.write(0x00);
    o.write(12);
    o.write(0x00);
    writeInt(o, 12 + body.size());
    writeInt(o, t.pkgs.size());
    byte[] bb = body.toByteArray();
    o.write(bb, 0, bb.length);
    return o.toByteArray();
  }

  private static String hex(byte[] a) {
    StringBuilder sb = new StringBuilder();
    for (byte x : a)
      sb.append(String.format("%02x", x));
    return sb.toString();
  }

  /** Remaps global-pool string indexes and key indexes from a split table into the target table. */
  private static final class Remap {
    final StringPool srcGlobal, dstGlobal, srcKeys, dstKeys;
    final Map<Integer, Integer> strCache = new HashMap<>();

    Remap(StringPool srcGlobal, StringPool dstGlobal, StringPool srcKeys, StringPool dstKeys) {
      this.srcGlobal = srcGlobal;
      this.dstGlobal = dstGlobal;
      this.srcKeys = srcKeys;
      this.dstKeys = dstKeys;
    }

    int str(int idx) {
      Integer c = strCache.get(idx);
      if (c != null)
        return c;
      String s = srcGlobal.strings.get(idx);
      List<int[]> spans = srcGlobal.spansOf(idx);
      int n;
      if (spans.isEmpty()) {
        n = dstGlobal.add(s);
      } else {
        List<int[]> ns = new ArrayList<>();
        for (int[] sp : spans) {
          ns.add(new int[] { dstGlobal.add(srcGlobal.strings.get(sp[0])), sp[1], sp[2] });
        }
        n = dstGlobal.addStyled(s, ns);
      }
      strCache.put(idx, n);
      return n;
    }

    int key(int idx) {
      return dstKeys == srcKeys ? idx : dstKeys.add(srcKeys.strings.get(idx));
    }
  }

  private static Chunk convertType(Chunk c, Remap r, int specCount) {
    byte[] d = c.data;
    ByteBuffer b = buf(d);
    int hs = b.getShort(2) & 0xffff;
    int flags = d[9] & 0xff;
    int entryCount = b.getInt(12);
    int entriesStart = b.getInt(16);
    boolean sparse = (flags & 0x01) != 0;
    int outCount = sparse ? Math.max(specCount, 0) : entryCount;
    int[] offs = new int[outCount];
    Arrays.fill(offs, -1);
    for (int i = 0; i < entryCount; i++) {
      int v = b.getInt(hs + 4 * i);
      if (sparse) {
        int idx = v & 0xffff;
        int off = (v >>> 16) * 4;
        if (idx < outCount)
          offs[idx] = off;
        else
          throw new IllegalStateException("Sparse entry index out of range");
      } else {
        offs[i] = v;
      }
    }
    ByteArrayOutputStream blob = new ByteArrayOutputStream();
    int[] newOffs = new int[outCount];
    for (int i = 0; i < outCount; i++) {
      if (offs[i] == -1) {
        newOffs[i] = -1;
        continue;
      }
      int e = entriesStart + offs[i];
      int esz = b.getShort(e) & 0xffff;
      int eflags = b.getShort(e + 2) & 0xffff;
      if ((eflags & 0x8) != 0)
        throw new UnsupportedOperationException("Compact resource entries are not supported");
      byte[] eb;
      if ((eflags & 0x1) != 0) {
        int count = b.getInt(e + 12);
        int len = 16 + 12 * count;
        eb = Arrays.copyOfRange(d, e, e + len);
        putInt(eb, 4, r.key(b.getInt(e + 4)));
        for (int k = 0; k < count; k++) {
          int vo = 16 + 12 * k;
          if ((eb[vo + 7] & 0xff) == 0x03) {
            putInt(eb, vo + 8, r.str(b.getInt(e + vo + 8)));
          }
        }
      } else {
        eb = Arrays.copyOfRange(d, e, e + esz + 8);
        putInt(eb, 4, r.key(b.getInt(e + 4)));
        if ((eb[esz + 3] & 0xff) == 0x03) {
          putInt(eb, esz + 4, r.str(b.getInt(e + esz + 4)));
        }
      }
      newOffs[i] = blob.size();
      blob.write(eb, 0, eb.length);
      while (blob.size() % 4 != 0)
        blob.write(0);
    }
    int newEntriesStart = hs + 4 * outCount;
    int size = newEntriesStart + blob.size();
    byte[] o = new byte[size];
    System.arraycopy(d, 0, o, 0, hs);
    putInt(o, 4, size);
    o[9] = (byte) (flags & ~0x01);
    putInt(o, 12, outCount);
    putInt(o, 16, newEntriesStart);
    for (int i = 0; i < outCount; i++)
      putInt(o, hs + 4 * i, newOffs[i]);
    byte[] bl = blob.toByteArray();
    System.arraycopy(bl, 0, o, newEntriesStart, bl.length);
    Chunk n = new Chunk();
    n.type = RES_TYPE;
    n.typeId = c.typeId;
    n.cfg = c.cfg;
    n.data = o;
    return n;
  }

  private static int specEntryCount(Pkg p, int typeId) {
    for (Chunk c : p.chunks) {
      if (c.type == RES_SPEC && c.typeId == typeId)
        return buf(c.data).getInt(12);
    }
    return 0;
  }

  private static void insertGrouped(Pkg p, Chunk n) {
    int last = -1;
    for (int i = 0; i < p.chunks.size(); i++) {
      if (p.chunks.get(i).typeId == n.typeId)
        last = i;
    }
    if (last < 0)
      p.chunks.add(n);
    else
      p.chunks.add(last + 1, n);
  }

  public interface Log {
    void log(String s);
  }

  /**
   * Merges every configuration of the split table that the base table does not have yet. Packages the base does not contain (feature splits) are adopted as a whole.
   * 
   * @return number of added TYPE chunks
   */
  public static int merge(Table base, Table split, Log log) {
    int added = 0;
    for (Pkg sp : split.pkgs) {
      Pkg bp = base.find(sp.id);
      if (bp == null) {
        Pkg np = new Pkg();
        np.id = sp.id;
        np.header = sp.header;
        np.typePoolRaw = sp.typePoolRaw;
        np.keyPool = sp.keyPool;
        Remap r = new Remap(split.global, base.global, sp.keyPool, sp.keyPool);
        for (Chunk c : sp.chunks) {
          if (c.type == RES_TYPE) {
            np.chunks.add(convertType(c, r, specEntryCount(sp, c.typeId)));
            added++;
          } else {
            np.chunks.add(c);
          }
        }
        base.pkgs.add(np);
        if (log != null)
          log.log("   -> new package 0x" + Integer.toHexString(sp.id));
        continue;
      }
      Set<String> have = new HashSet<>();
      Set<Integer> baseTypes = new HashSet<>();
      for (Chunk c : bp.chunks) {
        if (c.type == RES_TYPE)
          have.add(c.typeId + ":" + hex(c.cfg));
        if (c.typeId >= 0)
          baseTypes.add(c.typeId);
      }
      Remap r = new Remap(split.global, base.global, sp.keyPool, bp.keyPool);
      for (Chunk c : sp.chunks) {
        if (c.type == RES_SPEC) {
          if (!baseTypes.contains(c.typeId)) {
            bp.chunks.add(c);
            baseTypes.add(c.typeId);
          }
        } else if (c.type == RES_TYPE) {
          String k = c.typeId + ":" + hex(c.cfg);
          if (have.contains(k))
            continue;
          int sc = specEntryCount(bp, c.typeId);
          if (sc == 0)
            sc = specEntryCount(sp, c.typeId);
          insertGrouped(bp, convertType(c, r, sc));
          have.add(k);
          added++;
        }
      }
    }
    return added;
  }
}
