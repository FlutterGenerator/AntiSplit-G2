package com.tilks.arsc.merge;

import java.io.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** AntiSplit engine: merges base + config splits of an .apks/.zip/.xapk bundle into one installable APK. */
public final class Merger {
  public interface Logger {
    void log(String s);
  }

  public static final class Options {
    public boolean sign = true;
    public boolean module = false;
    public boolean extractNativeLibs = false; // true = "Compression ON"
    public boolean mismatching = false;
    public boolean languageOnly = false;
    public String languageCode = "ru";
    public byte[] signTemplate; // testkey.past
    public byte[] signKey; // testkey.pk8
    public File cacheDir;
  }

  private static final Set<String> ABIS = new HashSet<>(Arrays.asList("arm64_v8a", "armeabi_v7a",
      "armeabi", "x86", "x86_64", "mips", "mips64", "riscv64"));
  private static final Set<String> DPIS = new HashSet<>(Arrays.asList("ldpi", "mdpi", "tvdpi",
      "hdpi", "xhdpi", "xxhdpi", "xxxhdpi", "nodpi", "anydpi"));
  private static final int RES_ID_EXTRACT_NATIVE_LIBS = 0x010104ea;

  private static final class Part {
    File file;
    ZipFile zip;
    AxmlDoc doc;
    String name;
    String pkg;
    String version;
    String versionName;
    String split;
    boolean feature;
    String kind; // base, abi, dpi, lang, feature
  }

  private final Logger log;

  public Merger(Logger log) {
    this.log = log;
  }

  private void p(String fmt, Object... a) {
    log.log(String.format(Locale.US, fmt, a));
  }

  private static String ext(String n) {
    int i = n.lastIndexOf('.');
    return i < 0 ? "" : n.substring(i).toLowerCase(Locale.US);
  }

  private static boolean isSignatureFile(String n) {
    String l = n.toLowerCase(Locale.US);
    if (!l.startsWith("meta-inf/"))
      return false;
    return l.equals("meta-inf/manifest.mf") || l.endsWith(".sf") || l.endsWith(".rsa")
        || l.endsWith(".dsa") || l.endsWith(".ec");
  }

  private static byte[] readAll(InputStream in) throws IOException {
    java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
    byte[] b = new byte[1 << 16];
    int n;
    while ((n = in.read(b)) > 0)
      o.write(b, 0, n);
    in.close();
    return o.toByteArray();
  }

  private static String fmtSize(long b) {
    if (b < 1024L)
      return b + " B";
    if (b < 1024L * 1024L)
      return String.format("%.1f KiB", b / 1024.0);
    if (b < 1024L * 1024L * 1024L)
      return String.format("%.1f MiB", b / 1048576.0);
    return String.format("%.1f GiB", b / 1073741824.0);
  }

  private static String fmtTime(long ms) {
    long h = TimeUnit.MILLISECONDS.toHours(ms);
    long m = TimeUnit.MILLISECONDS.toMinutes(ms) % 60;
    long s = TimeUnit.MILLISECONDS.toSeconds(ms) % 60;
    return String.format(Locale.US, "%02dh:%02dm:%02ds.%04dms", h, m, s, ms % 1000);
  }

  /** @return the produced file or null on failure (the reason is written to the log). */
  public File run(File src, Options o) {
    long t0 = System.currentTimeMillis();
    List<Part> parts = new ArrayList<>();
    List<File> temps = new ArrayList<>();
    try {
      p(o.languageOnly ? "\nStarting copying language (%s)\n\n"
          : "\nStarting merge splitted resources\n\n", o.languageCode);
      String abs = src.getAbsolutePath();
      String shown = src.getName().length() > 0 ? src.getName() : abs;
      int sl = abs.lastIndexOf(File.separatorChar);
      String folder = sl > 0 ? abs.substring(0, sl) : "";
      p("File: %s(size: %s)\nfolder: %s\n", shown, fmtSize(src.length()), folder);
      String ex = ext(src.getName());
      if (!(ex.equals(".apks") || ex.equals(".zip") || ex.equals(".xapk"))) {
        p("Error! Only works with .apks, .zip or .xapk file\n");
        return null;
      }
      // 1. unpack nested APKs
      ZipFile bundle = new ZipFile(src);
      try {
        Enumeration<? extends ZipEntry> en = bundle.entries();
        int i = 0;
        while (en.hasMoreElements()) {
          ZipEntry e = en.nextElement();
          if (e.isDirectory() || !ext(e.getName()).equals(".apk"))
            continue;
          File t = new File(o.cacheDir, "part" + (i++) + ".apk");
          OutputStream os = new FileOutputStream(t);
          InputStream is = bundle.getInputStream(e);
          byte[] b = new byte[1 << 16];
          int n;
          while ((n = is.read(b)) > 0)
            os.write(b, 0, n);
          is.close();
          os.close();
          temps.add(t);
          Part part = new Part();
          part.file = t;
          part.name = new File(e.getName()).getName();
          parts.add(part);
        }
      } finally {
        bundle.close();
      }
      if (parts.isEmpty()) {
        p("Source doesn't contain any APK files\n");
        return null;
      }
      // 2. read manifests
      Part base = null;
      for (Part pt : parts) {
        pt.zip = new ZipFile(pt.file);
        ZipEntry me = pt.zip.getEntry("AndroidManifest.xml");
        if (me == null) {
          p("AndroidManifest.xml not found in an APK\n");
          return null;
        }
        pt.doc = AxmlDoc.parse(readAll(pt.zip.getInputStream(me)));
        pt.pkg = pt.doc.attr("manifest", "package");
        pt.version = pt.doc.attr("manifest", "versionCode");
        pt.versionName = pt.doc.attr("manifest", "versionName");
        pt.split = pt.doc.attr("manifest", "split");
        pt.feature = "true".equals(pt.doc.attr("manifest", "isFeatureSplit"));
        if (pt.split == null) {
          if (base != null) {
            p("Found multiple base APK files\n");
            return null;
          }
          pt.kind = "base";
          base = pt;
        } else {
          String s = pt.split;
          String suffix = s.startsWith("config.") ? s.substring(7) : s;
          if (pt.feature)
            pt.kind = "feature";
          else if (!s.startsWith("config."))
            pt.kind = "feature";
          else if (ABIS.contains(suffix))
            pt.kind = "abi";
          else if (DPIS.contains(suffix))
            pt.kind = "dpi";
          else
            pt.kind = "lang";
        }
      }
      if (base == null) {
        p("Source doesn't contain base APK file\n");
        return null;
      }
      // 3. consistency
      for (Part pt : parts) {
        if (pt == base)
          continue;
        if (pt.pkg != null && !pt.pkg.equals(base.pkg) && !o.mismatching) {
          p("Split APK parts have mismatching packages\n");
          return null;
        }
        if (pt.version != null && !pt.version.equals(base.version) && !o.mismatching) {
          p("Split APK parts have mismatching versions\n");
          return null;
        }
      }
      p("\n");
      p("Base APK\nname: %s\nversion: %s\nId: %s\n\n", base.pkg, base.versionName, base.name);
      List<Part> unk = new ArrayList<>();
      List<Part> feat = new ArrayList<>();
      for (Part pt : parts) {
        if (pt == base)
          continue;
        (pt.kind.equals("feature") ? feat : unk).add(pt);
      }
      if (!unk.isEmpty()) {
        p("Unknown\n");
        for (Part pt : unk)
          p("name: %s\nId: %s\n", pt.split, pt.name);
        p("\n");
      }
      if (!feat.isEmpty()) {
        p("Dynamic features\n");
        for (Part pt : feat)
          p("name: %s\nId: %s\n", pt.split, pt.name);
        p("\n");
      }
      p("\n");
      // 4. choose parts
      List<Part> use = new ArrayList<>();
      for (Part pt : parts) {
        if (pt == base)
          continue;
        if (o.languageOnly) {
          String sfx = pt.split.startsWith("config.") ? pt.split.substring(7) : pt.split;
          if (pt.kind.equals("lang") && sfx.toLowerCase(Locale.US)
              .startsWith(o.languageCode.trim().toLowerCase(Locale.US))) {
            use.add(pt);
            p("  --> Lng code %s\n", o.languageCode);
          }
          continue;
        }
        if (pt.kind.equals("feature")) {
          if (o.module)
            use.add(pt);
          continue;
        }
        use.add(pt);
      }
      // 5. output file
      String baseName = src.getName().substring(0, src.getName().length() - ex.length());
      String suffix = (ex.equals(".apks") ? "_apks" : "") + (o.sign ? "_signed" : "_unsigned")
          + ".apk";
      File out = new File(src.getParentFile(), baseName + suffix);
      // 6. resources
      byte[] baseArsc = null;
      ZipEntry ae = base.zip.getEntry("resources.arsc");
      ArscMerger.Table table = null;
      if (ae != null) {
        baseArsc = readAll(base.zip.getInputStream(ae));
        table = ArscMerger.parse(baseArsc);
        for (Part pt : use) {
          ZipEntry se = pt.zip.getEntry("resources.arsc");
          if (se == null)
            continue;
          ArscMerger.Table st = ArscMerger.parse(readAll(pt.zip.getInputStream(se)));
          int n = ArscMerger.merge(table, st, new ArscMerger.Log() {
            @Override
            public void log(String s) {
              // detailed arsc messages are not shown in the log
            }
          });
        }
      }
      // 7. manifest
      AxmlDoc man = base.doc;
      man.removeAttrs("manifest", new HashSet<>(Arrays.asList("split", "configForSplit",
          "isFeatureSplit", "requiredSplitTypes", "splitTypes")));
      man.removeAttrs("application", new HashSet<>(Arrays.asList("isSplitRequired")));
      man.removeMetaData(new HashSet<>(Arrays.asList("com.android.vending.splits",
          "com.android.vending.splits.required", "com.android.vending.derived.apk.id")));
      man.setBooleanAttr("application", "extractNativeLibs", RES_ID_EXTRACT_NATIVE_LIBS,
          o.extractNativeLibs);
      byte[] manBytes = man.write();
      // 8. write zip
      int lastDex = 1;
      Enumeration<? extends ZipEntry> de = base.zip.entries();
      while (de.hasMoreElements()) {
        String dn = de.nextElement().getName();
        if (dn.matches("classes\\d*\\.dex")) {
          String num = dn.substring(7, dn.length() - 4);
          int k = num.length() == 0 ? 1 : Integer.parseInt(num);
          if (k > lastDex)
            lastDex = k;
        }
      }
      p("[BASE] %s\n", base.name);
      p("[*] last base dex: -> %s\n", dexName(lastDex));
      ApkZipWriter w = new ApkZipWriter(out, o.sign);
      try {
        w.addBytes("AndroidManifest.xml", manBytes, false, 0, true);
        if (table != null) {
          w.addBytes("resources.arsc", ArscMerger.write(table), true, 4, true);
        }
        List<Part> order = new ArrayList<>();
        order.add(base);
        order.addAll(use);
        int dexNext = 2;
        for (Part pt : order) {
          Enumeration<? extends ZipEntry> en = pt.zip.entries();
          while (en.hasMoreElements()) {
            ZipEntry e = en.nextElement();
            String n = e.getName();
            if (e.isDirectory() || isSignatureFile(n))
              continue;
            if (n.equals("AndroidManifest.xml") || n.equals("resources.arsc"))
              continue;
            if (pt != base && pt.kind.equals("feature") && n.matches("classes\\d*\\.dex")) {
              while (w.has(dexName(dexNext)))
                dexNext++;
              n = dexName(dexNext++);
            }
            boolean lib = n.startsWith("lib/") && n.endsWith(".so");
            if (lib && !o.extractNativeLibs) {
              w.addStored(n, e.getSize(), e.getCrc(), pt.zip.getInputStream(e), 4096);
            } else if (lib) {
              w.addDeflated(n, pt.zip.getInputStream(e));
            } else if (e.getMethod() == ZipEntry.STORED) {
              w.addStored(n, e.getSize(), e.getCrc(), pt.zip.getInputStream(e), 4);
            } else {
              w.addDeflated(n, pt.zip.getInputStream(e));
            }
          }
          p("[+] Copied files from %s\n", pt.name);
          if (pt == base)
            p("[*] Edit base manifest\n");
        }
        if (table != null)
          p("[*] Merged arsc %s\n", "resources.arsc");
        if (o.sign) {
          p("[*] Signing the APK:\n    ->  %s\n", out.getAbsolutePath());
          byte[][] s = PseudoApkSigner.sign(w.digests, o.signTemplate, o.signKey);
          w.addBytes("META-INF/MANIFEST.MF", s[0], false, 0, false);
          w.addBytes("META-INF/CERT.SF", s[1], false, 0, false);
          w.addBytes("META-INF/CERT.RSA", s[2], false, 0, false);
        } else {
          p("[*] Saving the APK:\n    ->  %s\n", out.getAbsolutePath());
        }
      } finally {
        w.close();
      }
      p("\n################ Output ###################\n\n");
      p("\nCompleted successfully in %s.\n", fmtTime(System.currentTimeMillis() - t0));
      return out;
    } catch (Throwable t) {
      java.io.StringWriter sw = new java.io.StringWriter();
      t.printStackTrace(new java.io.PrintWriter(sw));
      p("\nError! %s\n%s\n", String.valueOf(t), sw.toString());
      return null;
    } finally {
      for (Part pt : parts) {
        try {
          if (pt.zip != null)
            pt.zip.close();
        } catch (IOException ignored) {
        }
      }
      for (File f : temps)
        f.delete();
    }
  }

  private static String dexName(int i) {
    return i <= 1 ? "classes.dex" : "classes" + i + ".dex";
  }
}
