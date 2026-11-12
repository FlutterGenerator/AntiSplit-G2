package com.tilks.apkmirror;

import android.app.IntentService;
import android.app.PendingIntent;
import android.content.Intent;

public class MergeService extends IntentService {
  public MergeService() {
    super("MergeService");
  }

  @Override
  protected void onHandleIntent(Intent intent) {
    if (intent == null)
      return;
    String zip = intent.getStringExtra("zip");
    PendingIntent pi = intent.getParcelableExtra("pendingIntent");
    try {
      new Decryptor(this, zip, pi).run();
    } catch (Throwable t) {
      t.printStackTrace();
    }
  }
}
