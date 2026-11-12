package com.tilks.apkmirror;

import java.util.Locale;
import java.util.concurrent.TimeUnit;

/** Size / duration formatting used in the decrypt log. */
final class Fmt {
  private Fmt() {
  }

  static String size(long b) {
    long a = Math.abs(b);
    if (a < 1024L)
      return b + " B";
    double d = b;
    if (a < 1024L * 1024L)
      return String.format(Locale.US, "%.1f KiB", d / 1024.0);
    if (a < 1024L * 1024L * 1024L)
      return String.format(Locale.US, "%.1f MiB", d / 1048576.0);
    if (a < 1024L * 1024L * 1024L * 1024L)
      return String.format(Locale.US, "%.1f GiB", d / 1073741824.0);
    if (a < 1024L * 1024L * 1024L * 1024L * 1024L)
      return String.format(Locale.US, "%.1f TiB", d / 1099511627776.0);
    if (a < 1024L * 1024L * 1024L * 1024L * 1024L * 1024L)
      return String.format(Locale.US, "%.1f PiB", d / 1125899906842624.0);
    return String.format(Locale.US, "%.1f EiB", d / 1152921504606846976.0);
  }

  static String time(long ms) {
    long d = TimeUnit.MILLISECONDS.toDays(ms);
    long h = TimeUnit.MILLISECONDS.toHours(ms) % 24;
    long m = TimeUnit.MILLISECONDS.toMinutes(ms) % 60;
    long s = TimeUnit.MILLISECONDS.toSeconds(ms) % 60;
    if (d > 0)
      return String.format(Locale.US, "%dd %02dh:%02dm:%02ds.%04dms", d, h, m, s, ms % 1000);
    return String.format(Locale.US, "%02dh:%02dm:%02ds.%04dms", h, m, s, ms % 1000);
  }

  /** Little-endian unsigned read of up to 8 bytes (same as the original byte helper). */
  static long le(byte[] b) {
    long r = 0;
    for (int i = 0; i < b.length && i < 8; i++)
      r |= (b[i] & 0xFFL) << (8 * i);
    return r;
  }
}
