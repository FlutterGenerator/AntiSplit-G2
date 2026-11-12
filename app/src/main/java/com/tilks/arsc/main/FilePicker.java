package com.tilks.arsc.main;

import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.*;
import com.tilks.arscmerge.R;
import java.io.File;
import java.text.SimpleDateFormat;
import java.util.*;

/** Simple dialog file browser that lists folders and *.apks / *.zip / *.xapk files. */
public class FilePicker {
  public interface Listener {
    void onFilePicked(File f);
  }

  private final Context ctx;
  private final Listener listener;
  private final String[] exts;
  private File dir;
  private ListView list;
  private AlertDialog dialog;
  private Adapter adapter;
  private final SimpleDateFormat fmt = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss", Locale.US);

  public FilePicker(Context ctx, File start, Listener l) {
    this(ctx, start, l, ".apks", ".zip", ".xapk");
  }

  public FilePicker(Context ctx, File start, Listener l, String... exts) {
    this.ctx = ctx;
    this.listener = l;
    this.exts = exts;
    this.dir = start != null && start.isDirectory() ? start
        : android.os.Environment.getExternalStorageDirectory();
  }

  private boolean accepted(File f) {
    String n = f.getName().toLowerCase(Locale.US);
    for (String e : exts)
      if (n.endsWith(e))
        return true;
    return false;
  }

  /** Picks the list icon by file type: folder, .apks, .xapk, .apkm or a generic file. */
  private static int iconFor(File f) {
    if (f.isDirectory())
      return R.drawable.ic_folder;
    String n = f.getName().toLowerCase(Locale.US);
    if (n.endsWith(".apks"))
      return R.drawable.ic_apks;
    if (n.endsWith(".xapk"))
      return R.drawable.ic_xapk;
    if (n.endsWith(".apkm"))
      return R.drawable.ic_apkm;
    return R.drawable.ic_file;
  }

  private List<File> entries() {
    List<File> r = new ArrayList<>();
    File[] fs = dir.listFiles();
    if (fs != null) {
      for (File f : fs) {
        if (f.isHidden() || !f.canRead())
          continue;
        if (f.isDirectory() || accepted(f))
          r.add(f);
      }
    }
    Collections.sort(r, new Comparator<File>() {
      @Override
      public int compare(File a, File b) {
        if (a.isDirectory() != b.isDirectory())
          return a.isDirectory() ? -1 : 1;
        return a.getName().compareToIgnoreCase(b.getName());
      }
    });
    if (dir.getParentFile() != null)
      r.add(0, dir.getParentFile());
    return r;
  }

  private static String size(long b) {
    if (b < 1024)
      return b + " bytes";
    if (b < 1024 * 1024)
      return String.format(Locale.US, "%.1f KB", b / 1024.0);
    return String.format(Locale.US, "%.1f MB", b / 1048576.0);
  }

  private class Adapter extends ArrayAdapter<File> {
    Adapter(List<File> l) {
      super(ctx, R.layout.li_row_textview, R.id.text1, l);
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
      View v = convertView != null ? convertView
          : LayoutInflater.from(ctx).inflate(R.layout.li_row_textview, parent, false);
      File f = getItem(position);
      boolean isParent = f.equals(dir.getParentFile());
      ((TextView) v.findViewById(R.id.text1)).setText(isParent ? ".." : f.getName());
      ImageView icon = (ImageView) v.findViewById(R.id.icon);
      icon.setVisibility(View.VISIBLE);
      icon.setImageResource(iconFor(f));
      ((TextView) v.findViewById(R.id.txt_size)).setText(f.isDirectory() ? "" : size(f.length()));
      ((TextView) v.findViewById(R.id.txt_date))
          .setText(isParent ? "" : fmt.format(new Date(f.lastModified())));
      return v;
    }
  }

  private void refresh() {
    adapter.clear();
    adapter.addAll(entries());
    adapter.notifyDataSetChanged();
    dialog.setTitle(dir.getAbsolutePath());
    list.setSelection(0);
  }

  public void show() {
    list = new ListView(ctx);
    adapter = new Adapter(entries());
    list.setAdapter(adapter);
    list.setOnItemClickListener(new AdapterView.OnItemClickListener() {
      @Override
      public void onItemClick(AdapterView<?> p, View v, int pos, long id) {
        File f = adapter.getItem(pos);
        if (f.isDirectory()) {
          dir = f;
          refresh();
        } else {
          dialog.dismiss();
          listener.onFilePicked(f);
        }
      }
    });
    dialog = new AlertDialog.Builder(ctx).setTitle(R.string.choose_file).setView(list)
        .setNegativeButton(R.string.dialog_cancel, new DialogInterface.OnClickListener() {
          @Override
          public void onClick(DialogInterface d, int w) {
            d.dismiss();
          }
        }).create();
    dialog.show();
    dialog.setTitle(dir.getAbsolutePath());
  }
}
