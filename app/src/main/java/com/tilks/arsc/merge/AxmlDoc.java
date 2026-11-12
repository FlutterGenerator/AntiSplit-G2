package com.tilks.arsc.merge;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

/** Minimal read/edit/write support for binary AndroidManifest.xml. */
public final class AxmlDoc {
  public static final String ANDROID_NS = "http://schemas.android.com/apk/res/android";
  static final int START_NS = 0x0100, END_NS = 0x0101, START_EL = 0x0102, END_EL = 0x0103,
      CDATA = 0x0104;

  public static final class Attr {
    public String ns;
    public String name;
    public int resId;
    public int type;
    public int data;
    public String str; // when type == 3

    public String valueString() {
      if (type == 3)
        return str;
      if (type == 0x12)
        return data != 0 ? "true" : "false";
      return String.valueOf(data);
    }
  }

  public static final class Node {
    public int kind;
    public int line;
    public String ns, name, prefix, uri, text;
    public byte[] typed;
    public List<Attr> attrs = new ArrayList<>();
  }

  private boolean utf8;
  public final List<Node> nodes = new ArrayList<>();

  private static ByteBuffer buf(byte[] d) {
    return ByteBuffer.wrap(d).order(ByteOrder.LITTLE_ENDIAN);
  }

  public static AxmlDoc parse(byte[] d) {
    ByteBuffer b = buf(d);
    if ((b.getShort(0) & 0xffff) != 0x0003)
      throw new IllegalStateException("No XML chunk in file");
    AxmlDoc doc = new AxmlDoc();
    int pos = (b.getShort(2) & 0xffff);
    StringPool pool = null;
    int[] resMap = new int[0];
    int total = Math.min(b.getInt(4), d.length);
    while (pos + 8 <= total) {
      int type = b.getShort(pos) & 0xffff;
      int hs = b.getShort(pos + 2) & 0xffff;
      int size = b.getInt(pos + 4);
      if (size <= 0)
        break;
      switch (type) {
        case 0x0001:
          pool = StringPool.parse(d, pos);
          doc.utf8 = pool.isUtf8();
          break;
        case 0x0180: {
          int n = (size - hs) / 4;
          resMap = new int[n];
          for (int i = 0; i < n; i++)
            resMap[i] = b.getInt(pos + hs + 4 * i);
          break;
        }
        case START_NS:
        case END_NS: {
          Node n = new Node();
          n.kind = type == START_NS ? 0 : 1;
          n.line = b.getInt(pos + 8);
          n.prefix = str(pool, b.getInt(pos + 16));
          n.uri = str(pool, b.getInt(pos + 20));
          doc.nodes.add(n);
          break;
        }
        case START_EL: {
          Node n = new Node();
          n.kind = 2;
          n.line = b.getInt(pos + 8);
          n.ns = str(pool, b.getInt(pos + 16));
          n.name = str(pool, b.getInt(pos + 20));
          int aStart = b.getShort(pos + 24) & 0xffff;
          int aSize = b.getShort(pos + 26) & 0xffff;
          int aCount = b.getShort(pos + 28) & 0xffff;
          int ap = pos + 16 + aStart;
          for (int i = 0; i < aCount; i++) {
            int o = ap + i * aSize;
            Attr a = new Attr();
            a.ns = str(pool, b.getInt(o));
            int nameIdx = b.getInt(o + 4);
            a.name = str(pool, nameIdx);
            a.resId = nameIdx >= 0 && nameIdx < resMap.length ? resMap[nameIdx] : 0;
            a.type = d[o + 15] & 0xff;
            a.data = b.getInt(o + 16);
            if (a.type == 3)
              a.str = str(pool, a.data);
            n.attrs.add(a);
          }
          doc.nodes.add(n);
          break;
        }
        case END_EL: {
          Node n = new Node();
          n.kind = 3;
          n.line = b.getInt(pos + 8);
          n.ns = str(pool, b.getInt(pos + 16));
          n.name = str(pool, b.getInt(pos + 20));
          doc.nodes.add(n);
          break;
        }
        case CDATA: {
          Node n = new Node();
          n.kind = 4;
          n.line = b.getInt(pos + 8);
          n.text = str(pool, b.getInt(pos + 16));
          n.typed = Arrays.copyOfRange(d, pos + 20, pos + 28);
          doc.nodes.add(n);
          break;
        }
        default:
          break;
      }
      pos += size;
    }
    return doc;
  }

  private static String str(StringPool p, int i) {
    return i < 0 || p == null || i >= p.strings.size() ? null : p.strings.get(i);
  }

  private Node element(String name) {
    for (Node n : nodes)
      if (n.kind == 2 && name.equals(n.name))
        return n;
    return null;
  }

  public String attr(String element, String attrName) {
    Node n = element(element);
    if (n == null)
      return null;
    for (Attr a : n.attrs)
      if (attrName.equals(a.name))
        return a.valueString();
    return null;
  }

  public void removeAttrs(String element, Set<String> names) {
    Node n = element(element);
    if (n == null)
      return;
    for (Iterator<Attr> it = n.attrs.iterator(); it.hasNext();) {
      if (names.contains(it.next().name))
        it.remove();
    }
  }

  public void removeMetaData(Set<String> metaNames) {
    for (int i = 0; i < nodes.size(); i++) {
      Node n = nodes.get(i);
      if (n.kind != 2 || !"meta-data".equals(n.name))
        continue;
      String name = null;
      for (Attr a : n.attrs)
        if ("name".equals(a.name))
          name = a.str;
      if (name == null || !metaNames.contains(name))
        continue;
      int depth = 0;
      int j = i;
      for (; j < nodes.size(); j++) {
        Node m = nodes.get(j);
        if (m.kind == 2)
          depth++;
        else if (m.kind == 3) {
          depth--;
          if (depth == 0)
            break;
        }
      }
      for (int k = j; k >= i; k--)
        nodes.remove(k);
      i--;
    }
  }

  public void setBooleanAttr(String element, String name, int resId, boolean value) {
    Node n = element(element);
    if (n == null)
      return;
    for (Iterator<Attr> it = n.attrs.iterator(); it.hasNext();) {
      if (name.equals(it.next().name))
        it.remove();
    }
    Attr a = new Attr();
    a.ns = ANDROID_NS;
    a.name = name;
    a.resId = resId;
    a.type = 0x12;
    a.data = value ? -1 : 0;
    int pos = n.attrs.size();
    for (int i = 0; i < n.attrs.size(); i++) {
      int r = n.attrs.get(i).resId;
      if (r == 0 || r > resId) {
        pos = i;
        break;
      }
    }
    n.attrs.add(pos, a);
  }

  public void setStringAttr(String element, String ns, String name, int resId, String value) {
    Node n = element(element);
    if (n == null)
      return;
    for (Iterator<Attr> it = n.attrs.iterator(); it.hasNext();) {
      if (name.equals(it.next().name))
        it.remove();
    }
    Attr a = new Attr();
    a.ns = ns;
    a.name = name;
    a.resId = resId;
    a.type = 3;
    a.str = value;
    int pos = n.attrs.size();
    if (resId != 0) {
      for (int i = 0; i < n.attrs.size(); i++) {
        int r = n.attrs.get(i).resId;
        if (r == 0 || r > resId) {
          pos = i;
          break;
        }
      }
    }
    n.attrs.add(pos, a);
  }

  private static void putInt(ByteArrayOutputStream o, int v) {
    o.write(v & 0xff);
    o.write((v >> 8) & 0xff);
    o.write((v >> 16) & 0xff);
    o.write((v >>> 24) & 0xff);
  }

  private static void putShort(ByteArrayOutputStream o, int v) {
    o.write(v & 0xff);
    o.write((v >> 8) & 0xff);
  }

  public byte[] write() {
    // Attribute names that carry a resource id must come first in the pool, in resource-map order.
    Map<Integer, String> byId = new java.util.TreeMap<>();
    for (Node n : nodes) {
      for (Attr a : n.attrs) {
        if (a.resId != 0 && a.name != null && !byId.containsKey(a.resId))
          byId.put(a.resId, a.name);
      }
    }
    StringPool pool = new StringPool(utf8);
    List<Integer> resIds = new ArrayList<>();
    Map<String, Integer> idx = new HashMap<>();
    for (Map.Entry<Integer, String> e : byId.entrySet()) {
      if (idx.containsKey(e.getValue()))
        continue;
      idx.put(e.getValue(), pool.strings.size());
      pool.strings.add(e.getValue());
      resIds.add(e.getKey());
    }
    for (Node n : nodes) {
      add(pool, idx, n.ns);
      add(pool, idx, n.name);
      add(pool, idx, n.prefix);
      add(pool, idx, n.uri);
      add(pool, idx, n.text);
      for (Attr a : n.attrs) {
        add(pool, idx, a.ns);
        add(pool, idx, a.name);
        if (a.type == 3)
          add(pool, idx, a.str);
      }
    }
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    byte[] pb = pool.write();
    body.write(pb, 0, pb.length);
    if (!resIds.isEmpty()) {
      putShort(body, 0x0180);
      putShort(body, 8);
      putInt(body, 8 + 4 * resIds.size());
      for (int id : resIds)
        putInt(body, id);
    }
    for (Node n : nodes) {
      switch (n.kind) {
        case 0:
        case 1:
          putShort(body, n.kind == 0 ? START_NS : END_NS);
          putShort(body, 16);
          putInt(body, 24);
          putInt(body, n.line);
          putInt(body, -1);
          putInt(body, ix(idx, n.prefix));
          putInt(body, ix(idx, n.uri));
          break;
        case 2: {
          int cnt = n.attrs.size();
          putShort(body, START_EL);
          putShort(body, 16);
          putInt(body, 36 + 20 * cnt);
          putInt(body, n.line);
          putInt(body, -1);
          putInt(body, ix(idx, n.ns));
          putInt(body, ix(idx, n.name));
          putShort(body, 0x14);
          putShort(body, 0x14);
          putShort(body, cnt);
          int idId = 0;
          for (int i = 0; i < cnt; i++) {
            Attr a = n.attrs.get(i);
            if (a.ns != null && "id".equals(a.name))
              idId = i + 1;
          }
          putShort(body, idId);
          putShort(body, 0);
          putShort(body, 0);
          for (Attr a : n.attrs) {
            putInt(body, ix(idx, a.ns));
            putInt(body, ix(idx, a.name));
            putInt(body, a.type == 3 ? ix(idx, a.str) : -1);
            putShort(body, 8);
            body.write(0);
            body.write(a.type);
            putInt(body, a.type == 3 ? ix(idx, a.str) : a.data);
          }
          break;
        }
        case 3:
          putShort(body, END_EL);
          putShort(body, 16);
          putInt(body, 24);
          putInt(body, n.line);
          putInt(body, -1);
          putInt(body, ix(idx, n.ns));
          putInt(body, ix(idx, n.name));
          break;
        case 4:
          putShort(body, CDATA);
          putShort(body, 16);
          putInt(body, 28);
          putInt(body, n.line);
          putInt(body, -1);
          putInt(body, ix(idx, n.text));
          body.write(n.typed, 0, 8);
          break;
        default:
          break;
      }
    }
    ByteArrayOutputStream o = new ByteArrayOutputStream();
    putShort(o, 0x0003);
    putShort(o, 8);
    putInt(o, 8 + body.size());
    byte[] bb = body.toByteArray();
    o.write(bb, 0, bb.length);
    return o.toByteArray();
  }

  private static void add(StringPool pool, Map<String, Integer> idx, String s) {
    if (s == null || idx.containsKey(s))
      return;
    idx.put(s, pool.strings.size());
    pool.strings.add(s);
  }

  private static int ix(Map<String, Integer> idx, String s) {
    return s == null ? -1 : idx.get(s);
  }
}
