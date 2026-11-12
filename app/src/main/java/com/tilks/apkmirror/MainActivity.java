package com.tilks.apkmirror;

import android.Manifest;
import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.net.Uri;
import android.os.Environment;
import android.provider.Settings;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.*;
import com.tilks.arsc.main.FilePicker;
import com.tilks.arscmerge.R;
import java.io.File;

/** "Decrypt ApkMirror": picks an .apkm file and decrypts it to .apks. */
public class MainActivity extends Activity implements View.OnClickListener {
  private static final int REQ_PERMISSION = 1;
  private static final int REQ_DECRYPT = 2;
  private static final String[] PERMS = { Manifest.permission.READ_EXTERNAL_STORAGE,
      Manifest.permission.WRITE_EXTERNAL_STORAGE };

  private EditText pathEdit;
  private ProgressBar progress;
  private TextView logView;
  private Button button;
  private String path = Environment.getExternalStorageDirectory().getPath();
  private boolean running;
  private Runnable afterPermission;

  @Override
  protected void onCreate(Bundle state) {
    super.onCreate(state);
    setContentView(R.layout.activity_main);
    progress = (ProgressBar) findViewById(R.id.progressBar);
    progress.setVisibility(View.GONE);
    logView = (TextView) findViewById(R.id.textView1);
    pathEdit = (EditText) findViewById(R.id.editText1);
    pathEdit.setHint(R.string.file_apkm);
    pathEdit.addTextChangedListener(new TextWatcher() {
      @Override
      public void beforeTextChanged(CharSequence s, int a, int b, int c) {
      }

      @Override
      public void onTextChanged(CharSequence s, int a, int b, int c) {
        path = pathEdit.getText().toString();
      }

      @Override
      public void afterTextChanged(Editable s) {
      }
    });
    button = (Button) findViewById(R.id.button);
    button.setText(R.string.decrypt);
    button.setOnClickListener(this);
    ((ImageButton) findViewById(R.id.select)).setOnClickListener(this);
    if (state != null) {
      CharSequence z = state.getCharSequence("zip1");
      if (z != null)
        pathEdit.setText(z);
      CharSequence r = state.getCharSequence("result");
      if (r != null)
        logView.setText(r);
      running = state.getBoolean("isRunning");
    }
    progress.setVisibility(running ? View.VISIBLE : View.GONE);
    button.setEnabled(!running);
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
  public void onRequestPermissionsResult(int code, String[] perms, int[] res) {
    super.onRequestPermissionsResult(code, perms, res);
    if (code != REQ_PERMISSION)
      return;
    boolean ok = res.length > 0;
    for (int g : res)
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

  private void pick() {
    File cur = new File(path.trim());
    File start = cur.isDirectory() ? cur : cur.getParentFile();
    if (start == null || !start.isDirectory() || start.listFiles() == null) {
      start = Environment.getExternalStorageDirectory();
    }
    new FilePicker(this, start, new FilePicker.Listener() {
      @Override
      public void onFilePicked(File f) {
        Toast.makeText(MainActivity.this, "FILE: " + f.getAbsolutePath(), Toast.LENGTH_SHORT)
            .show();
        path = f.getAbsolutePath();
        pathEdit.setText(path);
      }
    }, ".apkm").show();
  }

  @Override
  public void onClick(final View v) {
    if (v.getId() == R.id.select) {
      withPermission(new Runnable() {
        @Override
        public void run() {
          pick();
        }
      });
      return;
    }
    withPermission(new Runnable() {
      @Override
      public void run() {
        if (!new File(path).isFile()) {
          Toast.makeText(MainActivity.this, R.string.choose_file, Toast.LENGTH_SHORT).show();
          return;
        }
        logView.setText("");
        PendingIntent pi = createPendingResult(REQ_DECRYPT, new Intent(), 0);
        Intent i = new Intent(MainActivity.this, MergeService.class);
        i.putExtra("zip", path);
        i.putExtra("pendingIntent", pi);
        running = true;
        progress.setVisibility(View.VISIBLE);
        button.setEnabled(false);
        startService(i);
      }
    });
  }

  @Override
  protected void onActivityResult(int req, int res, Intent data) {
    super.onActivityResult(req, res, data);
    if (handleAllFilesResult(req))
      return;
    if (req != REQ_DECRYPT)
      return;
    if (res == Decryptor.CODE_LOG && data != null) {
      String t = data.getStringExtra("result");
      if (t != null)
        logView.append(t);
    } else if (res == Decryptor.CODE_DONE) {
      running = false;
      progress.setVisibility(View.GONE);
      button.setEnabled(true);
    }
  }

  @Override
  protected void onSaveInstanceState(Bundle out) {
    out.putCharSequence("zip1", pathEdit.getText());
    out.putCharSequence("result", logView.getText());
    out.putBoolean("isRunning", running);
    super.onSaveInstanceState(out);
  }
}
