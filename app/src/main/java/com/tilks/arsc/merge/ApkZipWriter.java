package com.tilks.arsc.merge;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Zip writer with zipalign-style padding of STORED entries and SHA-1 digest recording for JAR signing. */
public final class ApkZipWriter implements Closeable {
  private static final class Counting extends FilterOutputStream {
    long count;

    Counting(OutputStream o) {
      super(o);
    }

    @Override
    public void write(int b) throws IOException {
      out.write(b);
      count++;
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
      out.write(b, off, len);
      count += len;
    }
  }

  private final Counting counting;
  private final ZipOutputStream zos;
  private final Set<String> names = new HashSet<>();
  /** entry name -> raw SHA-1 digest of the uncompressed content */
  public final Map<String, byte[]> digests = new LinkedHashMap<>();
  private final boolean recordDigests;

  public ApkZipWriter(File f, boolean recordDigests) throws IOException {
    counting = new Counting(new java.io.BufferedOutputStream(new FileOutputStream(f), 1 << 16));
    zos = new ZipOutputStream(counting);
    this.recordDigests = recordDigests;
  }

  public boolean has(String name) {
    return names.contains(name);
  }

  private static MessageDigest sha1() {
    try {
      return MessageDigest.getInstance("SHA-1");
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  private void copy(InputStream in, MessageDigest md) throws IOException {
    byte[] buf = new byte[1 << 16];
    int n;
    while ((n = in.read(buf)) > 0) {
      zos.write(buf, 0, n);
      if (md != null)
        md.update(buf, 0, n);
    }
    in.close();
  }

  private ZipEntry storedEntry(String name, long size, long crc, int align) throws IOException {
    zos.closeEntry();
    ZipEntry e = new ZipEntry(name);
    e.setMethod(ZipEntry.STORED);
    e.setSize(size);
    e.setCompressedSize(size);
    e.setCrc(crc);
    e.setTime(System.currentTimeMillis());
    if (align > 1) {
      int nameLen = name.getBytes("UTF-8").length;
      long dataStart = counting.count + 30 + nameLen;
      int pad = (int) ((align - (dataStart % align)) % align);
      if (pad > 0 && pad < 4)
        pad += align;
      if (pad > 0) {
        byte[] extra = new byte[pad];
        extra[0] = (byte) 0x35;
        extra[1] = (byte) 0xD9;
        extra[2] = (byte) ((pad - 4) & 0xff);
        extra[3] = (byte) (((pad - 4) >> 8) & 0xff);
        e.setExtra(extra);
      }
    }
    return e;
  }

  /** Adds an entry stored without compression; size and crc must be those of the uncompressed data. */
  public void addStored(String name, long size, long crc, InputStream in, int align)
      throws IOException {
    if (!names.add(name)) {
      in.close();
      return;
    }
    zos.putNextEntry(storedEntry(name, size, crc, align));
    MessageDigest md = recordDigests ? sha1() : null;
    copy(in, md);
    zos.closeEntry();
    if (md != null)
      digests.put(name, md.digest());
  }

  public void addDeflated(String name, InputStream in) throws IOException {
    if (!names.add(name)) {
      in.close();
      return;
    }
    zos.closeEntry();
    ZipEntry e = new ZipEntry(name);
    e.setMethod(ZipEntry.DEFLATED);
    e.setTime(System.currentTimeMillis());
    zos.putNextEntry(e);
    MessageDigest md = recordDigests ? sha1() : null;
    copy(in, md);
    zos.closeEntry();
    if (md != null)
      digests.put(name, md.digest());
  }

  public void addBytes(String name, byte[] data, boolean stored, int align, boolean digest)
      throws IOException {
    if (!names.add(name))
      return;
    zos.closeEntry();
    if (stored) {
      CRC32 crc = new CRC32();
      crc.update(data, 0, data.length);
      zos.putNextEntry(storedEntry(name, data.length, crc.getValue(), align));
    } else {
      ZipEntry e = new ZipEntry(name);
      e.setMethod(ZipEntry.DEFLATED);
      e.setTime(System.currentTimeMillis());
      zos.putNextEntry(e);
    }
    zos.write(data, 0, data.length);
    zos.closeEntry();
    if (recordDigests && digest)
      digests.put(name, sha1().digest(data));
  }

  @Override
  public void close() throws IOException {
    zos.close();
  }
}
