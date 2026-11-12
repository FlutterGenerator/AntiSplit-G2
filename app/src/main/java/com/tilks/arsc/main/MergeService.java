package com.tilks.arsc.main;

import android.app.IntentService;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import com.tilks.arsc.merge.Merger;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;

public class MergeService extends IntentService {
  public static final int CODE_LOG = 100;
  public static final int CODE_DONE = 101;

  public MergeService() {
    super("MergeService");
  }

  private static byte[] readAsset(android.content.res.AssetManager am, String name)
      throws Exception {
    InputStream in = am.open(name);
    ByteArrayOutputStream o = new ByteArrayOutputStream();
    byte[] b = new byte[8192];
    int n;
    while ((n = in.read(b)) > 0)
      o.write(b, 0, n);
    in.close();
    return o.toByteArray();
  }

  private void send(PendingIntent pi, int code, String text) {
    if (pi == null)
      return;
    try {
      Intent i = new Intent();
      i.putExtra("result", text);
      pi.send(this, code, i);
    } catch (Exception ignored) {
      // the activity is gone, the merge simply continues without a live log
    }
  }

  @Override
  protected void onHandleIntent(Intent intent) {
    if (intent == null)
      return;
    final PendingIntent pi = intent.getParcelableExtra("pendingIntent");
    String path = intent.getStringExtra("path");
    try {
      SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
      Merger.Options o = new Merger.Options();
      o.sign = sp.getBoolean("signEnable", true);
      o.module = sp.getBoolean("moduleEnable", false);
      o.extractNativeLibs = sp.getBoolean("extractNativeLibsEnable", false);
      o.mismatching = sp.getBoolean("mismatchingPackagesEnable", false);
      o.languageOnly = sp.getBoolean("languageEnable", false);
      o.languageCode = sp.getString("languageCode", "ru");
      o.cacheDir = getCacheDir();
      if (o.sign) {
        o.signTemplate = readAsset(getAssets(), "testkey.past");
        o.signKey = readAsset(getAssets(), "testkey.pk8");
      }
      new Merger(new Merger.Logger() {
        @Override
        public void log(String s) {
          send(pi, CODE_LOG, s);
        }
      }).run(new File(path), o);
    } catch (Throwable t) {
      send(pi, CODE_LOG, "\nError! " + t + "\n");
    } finally {
      send(pi, CODE_DONE, "");
    }
  }
}
