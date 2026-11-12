package com.tilks.arsc.main;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.net.Uri;
import android.os.Environment;
import android.provider.Settings;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.*;
import com.tilks.arscmerge.R;
import java.io.File;

public class MainActivity extends Activity {
  private static final int REQ_PERMISSION = 1;
  private static final int REQ_MERGE = 2;
  private static final String[] PERMS = { Manifest.permission.READ_EXTERNAL_STORAGE,
      Manifest.permission.WRITE_EXTERNAL_STORAGE };

  private EditText pathEdit;
  private Button mergeBtn;
  private ProgressBar progress;
  private TextView logView;
  private Runnable afterPermission;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);
    pathEdit = (EditText) findViewById(R.id.editText1);
    ImageButton select = (ImageButton) findViewById(R.id.select);
    mergeBtn = (Button) findViewById(R.id.button);
    progress = (ProgressBar) findViewById(R.id.progressBar);
    logView = (TextView) findViewById(R.id.textView1);
    progress.setVisibility(View.GONE);
    if (savedInstanceState != null) {
      CharSequence t = savedInstanceState.getCharSequence("log");
      if (t != null)
        logView.setText(t);
    }

    select.setOnClickListener(new View.OnClickListener() {
      @Override
      public void onClick(View v) {
        withPermission(new Runnable() {
          @Override
          public void run() {
            openPicker();
          }
        });
      }
    });
    mergeBtn.setOnClickListener(new View.OnClickListener() {
      @Override
      public void onClick(View v) {
        withPermission(new Runnable() {
          @Override
          public void run() {
            startMerge();
          }
        });
      }
    });
  }

  private static final int REQ_ALL_FILES = 3;

  private boolean hasPermissions() {
    if (Build.VERSION.SDK_INT >= 30)
      return Environment.isExternalStorageManager();
    if (Build.VERSION.SDK_INT < 23)
      return true;
    for (String p : PERMS) {
      if (checkSelfPermission(p) != PackageManager.PERMISSION_GRANTED)
        return false;
    }
    return true;
  }

  private void withPermission(Runnable r) {
    if (hasPermissions()) {
      r.run();
    } else if (Build.VERSION.SDK_INT >= 30) {
      // Android 11+: "All files access" (MANAGE_EXTERNAL_STORAGE) is granted in system settings.
      afterPermission = r;
      try {
        Intent i = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
            Uri.parse("package:" + getPackageName()));
        startActivityForResult(i, REQ_ALL_FILES);
      } catch (Exception e) {
        try {
          startActivityForResult(new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION),
              REQ_ALL_FILES);
        } catch (Exception e2) {
          afterPermission = null;
          Toast.makeText(this, "Permission Denied, You cannot use local drive.",
              Toast.LENGTH_SHORT).show();
        }
      }
    } else {
      afterPermission = r;
      requestPermissions(PERMS, REQ_PERMISSION);
    }
  }

  private boolean handleAllFilesResult(int req) {
    if (req != REQ_ALL_FILES)
      return false;
    Runnable r = afterPermission;
    afterPermission = null;
    if (Build.VERSION.SDK_INT >= 30 && Environment.isExternalStorageManager()) {
      Toast.makeText(this, "Permission Granted, Now you can use local drive.", Toast.LENGTH_SHORT)
          .show();
      if (r != null)
        r.run();
    } else {
      Toast.makeText(this, "Permission Denied, You cannot use local drive.", Toast.LENGTH_SHORT)
          .show();
    }
    return true;
  }

  @Override
  public void onRequestPermissionsResult(int requestCode, String[] permissions,
      int[] grantResults) {
    super.onRequestPermissionsResult(requestCode, permissions, grantResults);
    if (requestCode != REQ_PERMISSION)
      return;
    boolean ok = grantResults.length > 0;
    for (int g : grantResults)
      if (g != PackageManager.PERMISSION_GRANTED)
        ok = false;
    if (ok) {
      Toast.makeText(this, "Permission Granted, Now you can use local drive.", Toast.LENGTH_SHORT)
          .show();
      if (afterPermission != null)
        afterPermission.run();
    } else {
      Toast.makeText(this, "Permission Denied, You cannot use local drive.", Toast.LENGTH_SHORT)
          .show();
    }
    afterPermission = null;
  }

  private void openPicker() {
    File start = Environment.getExternalStorageDirectory();
    String cur = pathEdit.getText().toString().trim();
    if (cur.length() > 0) {
      File f = new File(cur);
      if (f.getParentFile() != null && f.getParentFile().isDirectory())
        start = f.getParentFile();
    }
    new FilePicker(this, start, new FilePicker.Listener() {
      @Override
      public void onFilePicked(File f) {
        pathEdit.setText(f.getAbsolutePath());
      }
    }).show();
  }

  private void startMerge() {
    String path = pathEdit.getText().toString().trim();
    Toast.makeText(this, "AntiSplit", Toast.LENGTH_SHORT).show();
    logView.setText("");
    progress.setVisibility(View.VISIBLE);
    mergeBtn.setEnabled(false);
    PendingIntent pi = createPendingResult(REQ_MERGE, new Intent(), 0);
    Intent i = new Intent(this, MergeService.class);
    i.putExtra("path", path);
    i.putExtra("pendingIntent", pi);
    startService(i);
  }

  @Override
  protected void onActivityResult(int requestCode, int resultCode, Intent data) {
    super.onActivityResult(requestCode, resultCode, data);
    if (handleAllFilesResult(requestCode))
      return;
    if (requestCode != REQ_MERGE)
      return;
    if (resultCode == MergeService.CODE_LOG && data != null) {
      logView.append(data.getStringExtra("result"));
    } else if (resultCode == MergeService.CODE_DONE) {
      progress.setVisibility(View.GONE);
      mergeBtn.setEnabled(true);
    }
  }

  @Override
  protected void onSaveInstanceState(Bundle outState) {
    super.onSaveInstanceState(outState);
    outState.putCharSequence("log", logView.getText());
  }

  @Override
  public boolean onCreateOptionsMenu(Menu menu) {
    getMenuInflater().inflate(R.menu.mymenu, menu);
    return true;
  }

  @Override
  public boolean onOptionsItemSelected(MenuItem item) {
    int id = item.getItemId();
    if (id == R.id.settings) {
      startActivity(new Intent(this, SettingsActivity.class));
    } else if (id == R.id.decrypt) {
      if (SettingsActivity.moduleInstalled()) {
        Intent i = new Intent();
        i.setClassName(getPackageName(), "com.tilks.apkmirror.MainActivity");
        startActivity(i);
      } else {
        Toast.makeText(this, R.string.module_not_installed, Toast.LENGTH_SHORT).show();
      }
    } else if (id == R.id.about) {
      new AlertDialog.Builder(this).setTitle(R.string.about)
          .setMessage(getString(R.string.app_name)
              + " 1.3\nAntiSplit - merges .apks / .zip / .xapk split bundles into a single APK.")
          .setPositiveButton(android.R.string.ok, null).show();
    } else if (id == R.id.help) {
      new AlertDialog.Builder(this).setTitle(R.string.help).setMessage(
          "1. Select an .apks / .zip / .xapk file.\n2. Press Merge.\n3. The merged APK is written next to the source file.\n\nSigning, native library compression, language mode and the optional module are in Settings.")
          .setPositiveButton(android.R.string.ok, null).show();
    } else {
      return super.onOptionsItemSelected(item);
    }
    return true;
  }
}
