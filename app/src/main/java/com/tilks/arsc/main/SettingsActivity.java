package com.tilks.arsc.main;

import android.os.Bundle;
import android.preference.Preference;
import android.preference.PreferenceActivity;
import android.preference.PreferenceManager;
import android.widget.Toast;
import com.tilks.arscmerge.R;

public class SettingsActivity extends PreferenceActivity {
  static boolean moduleInstalled() {
    try {
      Class.forName("com.tilks.apkmirror.MainActivity");
      return true;
    } catch (Throwable t) {
      return false;
    }
  }

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setTitle(R.string.settings);
    addPreferencesFromResource(R.xml.preferences);

    final Preference lang = findPreference("languageCode");
    String cur = PreferenceManager.getDefaultSharedPreferences(this).getString("languageCode",
        "ru");
    lang.setSummary(getString(R.string.pref_language_key_summary) + ": " + cur);
    lang.setOnPreferenceChangeListener(new Preference.OnPreferenceChangeListener() {
      @Override
      public boolean onPreferenceChange(Preference preference, Object newValue) {
        String v = String.valueOf(newValue).trim();
        if (v.length() < 2)
          return false;
        preference.setSummary(getString(R.string.pref_language_key_summary) + ": " + v);
        return true;
      }
    });

    Preference module = findPreference("moduleEnable");
    module.setOnPreferenceChangeListener(new Preference.OnPreferenceChangeListener() {
      @Override
      public boolean onPreferenceChange(Preference preference, Object newValue) {
        Toast.makeText(SettingsActivity.this,
            moduleInstalled() ? R.string.module_is_installed : R.string.module_not_installed,
            Toast.LENGTH_SHORT).show();
        return true;
      }
    });
  }
}
