// This file is part of Hash Suite password cracker,
// Copyright (c) 2014-2015 by Alain Espinosa. See LICENSE.

package com.hashsuite.droid;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.LineNumberReader;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;

import android.app.ActionBar;
import android.app.Activity;
import android.app.AlarmManager;
import android.app.AlertDialog;
import android.app.Dialog;
import android.app.DownloadManager;
import android.app.DownloadManager.Request;
import android.app.Fragment;
import android.app.FragmentTransaction;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnCancelListener;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager.NameNotFoundException;
import android.database.Cursor;
import android.graphics.Color;
import android.net.Uri;
import android.os.BatteryManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.PowerManager;
import android.preference.PreferenceManager;
import android.text.Html;
import android.text.method.LinkMovementMethod;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TableLayout;
import android.widget.TableRow;
import android.widget.TextView;
import android.widget.Toast;
import ar.com.daidalos.afiledialog.FileChooserDialog;

public class MainActivity extends Activity implements ActionBar.TabListener, OnItemSelectedListener
{
	// Formats constants
	static final int LM_INDEX = 0;
	//private static final int NTLM_INDEX = 1;
	//private static final int DCC_INDEX = 2;

	// Key-providers constants
	static final int CHARSET_INDEX = 0;
	static final int WORDLIST_INDEX = 1;
	static final int KEYBOARD_INDEX = 2;
	static final int PHRASES_INDEX = 3;
	static final int DB_INFO_INDEX = 4;
	static final int LM2NTLM_INDEX = 5;
	//private static final int FAST_LM_INDEX = 6;
	//private static final int RULES_INDEX = 7;

	// Native methods
	private static native void initAll(String files_path);
	// In_Out
	private static native void ImportHashes(String file_path);
	private static native int GetImportResultInt(int index);
	private static native void ImportHashesStop();
	private static native void ImportDB(String file_path);
	private static native void Export(String dir_path, int index);
	
	// Hashes stats
	private static native String ShowHashesStats(int format_index, int width);
	private static native int GetNumHash2Crack(int format_index);
	static native int GetNumMatches();
	private static native void clearAllAccounts();

	// Attacks
	private static native void StartAttack(int format_index, int provider_index, int num_threads, int min_size, int max_size, String param, int use_rules, int rules_on, int gpus_used);
	private static native void ResumeAttack(long db_id, int num_threads, int gpus_used);
	private static native void StopAttack();
	private static native long GetAttackID();
	private static native void SaveAttackState();
	private static native String GetAttackDescription();
	private static native void Benchmark();
	private static native void BenchmarkStop();
	private static native int GetBenchmarkDuration();
	private static native int[] GetBenchmarkValues(int format_index);
	private static native int GetRulesGPUStatus();

	// Wordlist
	public static native long SaveWordlist(String path, String name, long file_lenght);
	public static native long SavePhrases(String path, String name, long file_lenght);
	public static native void setPhrasesMaxWords(int max_num_words);

	// Settings
	private static native int GetSetting(int id, int default_value);
	private static native void SaveSetting(int id, int value_to_save);
	private static native void SaveSettingsToDB();

	private static final String DEFAULT_WORDLIST = "common_wordlist.txt";
	private static final String DEFAULT_PHRASES_FILE = "more_used_words.txt";
	private static final String DOWNLOADING_STATE = "wl_downloading.txt";
	// Constants to save settings in the same manner of the desktop version
	private static final int ID_FORMAT_BASE = 32991;
	private static final int ID_KEY_PROV_BASE = 33101;
	private static final int ID_WIZARD = 37667;

	private static final int REQUEST_LOAD = 0;
	static int format_index = 0;
	static int key_provider_index = 0;
	private boolean is_cracking;

	private static boolean is_initialize_native = false;
	public static int num_hashes_show = 1;
	public static int current_page_hash = 0;

	public static MainActivity my_activity;
	private static ArrayList<WordlistDownloadingData> downloading_data;
	
	// Tabs
	private Fragment[] my_tabs;
	HashesFragment tab_main;
	StatusFragment tab_status;
	private MenuItem action_menu;
	static int screen_width_dp;
	private static float display_density;
	private static int display_width;
	
	// Attack info
	private static AttackStatusData status = new AttackStatusData();
	private static Timer attack_timer;
	private static TimerTask timer_update_gui;
	
	// Saved State
	private static final String TAB_SELECTED = "tab_selected";
	private static final String IMPORT_FILENAME = "IMPORT_FILENAME";
	private static final String ATTACK_ID = "ATTACK_ID";
	// APP States
	private static final String APP_STATE = "app_state";
	private static final int APP_STATE_NORMAL = 0;
	private static final int APP_STATE_IMPORT_HASHES = 1;
	private static final int APP_STATE_CRACKING = 2;
	private static PowerManager.WakeLock wl;
	BroadcastReceiver download_receiver;

	static
	{
		System.loadLibrary("HashSuiteNative");
		downloading_data = new ArrayList<WordlistDownloadingData>();
	}

	public static int calculateDialogWidth(int dp)
	{
		return Math.min(display_width, (int)(dp*display_density));
	}
	public static boolean isTabletUI()
	{
		return screen_width_dp >= 640;
	}
	public static int getScreenTitleWitdh()
	{
		if(screen_width_dp >= 900)
			return 1;
		
		return 0;
			
	}
	private void copyFile(String filename, boolean is_wordlist)
	{
		File woutput = new File(getFilesDir().getAbsolutePath() + "/" + filename);
		if (!woutput.exists())
		{
			long lenght = 0;
			try
			{
				InputStream is = getAssets().open(filename);
				FileOutputStream os = new FileOutputStream(woutput);

				byte[] buffer = new byte[4096];
				int bytesRead;
				while ((bytesRead = is.read(buffer)) != -1)
				{
					lenght += bytesRead;
					os.write(buffer, 0, bytesRead);
				}

				is.close();
				os.close();
			}
			catch (IOException e)
			{
			}
			// Save to db
			if (is_wordlist)
				SaveWordlist(woutput.getAbsolutePath(), filename, lenght);
			else
				SavePhrases(woutput.getAbsolutePath(), filename, lenght);
		}
	}
	@Override
	protected void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		
		display_density = this.getResources().getDisplayMetrics().density;
		display_width = this.getResources().getDisplayMetrics().widthPixels;
		screen_width_dp = (int) (display_width / display_density);

		my_activity = this;
		is_cracking = false;
		
		if (!is_initialize_native)
		{
			initAll(getFilesDir().getAbsolutePath());
			is_initialize_native = true;

			format_index = GetSetting(ID_FORMAT_BASE, ID_FORMAT_BASE) - ID_FORMAT_BASE;
			key_provider_index = GetSetting(ID_KEY_PROV_BASE, ID_KEY_PROV_BASE) - ID_KEY_PROV_BASE;
			SaveSetting(ID_WIZARD, 1);

			// Put the default wordlist
			copyFile(DEFAULT_WORDLIST, true);

			// Put the default Phrases
			copyFile(DEFAULT_PHRASES_FILE, false);
		}
		
		// Set up the action bar.
		ActionBar actionBar = getActionBar();
		if(isTabletUI())
		{
			this.setContentView(R.layout.tablet_ui);
			actionBar.setNavigationMode(ActionBar.NAVIGATION_MODE_STANDARD);
		}
		else
		{
			actionBar.setNavigationMode(ActionBar.NAVIGATION_MODE_TABS);

			my_tabs = new Fragment[3];
			my_tabs[0] = new HashesFragment();
			my_tabs[1] = new StatusFragment();
			my_tabs[2] = new ParamsFragment();
			
			actionBar.addTab(actionBar.newTab().setText(getString(R.string.title_main)).setTabListener(this));
			actionBar.addTab(actionBar.newTab().setText(getString(R.string.title_status)).setTabListener(this));
			actionBar.addTab(actionBar.newTab().setText(getString(R.string.title_params)).setTabListener(this));
		}
		
		// Wordlist Downloader
		try
		{
			FileReader file = new FileReader(getFilesDir() + "/" + DOWNLOADING_STATE);
			LineNumberReader reader = new LineNumberReader(file);
			
			String id_str = reader.readLine();
			while(id_str != null)
			{
				downloading_data.add(new WordlistDownloadingData(Long.parseLong(id_str), Long.parseLong(reader.readLine())));
				id_str = reader.readLine();
			}
			
			reader.close();
			file.close();
		}
		catch (Exception e)
		{}
		
		download_receiver = new BroadcastReceiver()
		{
			@Override
			public void onReceive(Context context, Intent intent)
			{
				if (DownloadManager.ACTION_DOWNLOAD_COMPLETE.equals(intent.getAction()))
				{
					long downloadId = intent.getLongExtra(DownloadManager.EXTRA_DOWNLOAD_ID, 0);
					int d_index = -1;
					// Check if is one of our wordlist
					for (int i = 0; i < downloading_data.size(); i++)
						if(downloadId == downloading_data.get(i).enqueue_id)
						{
							d_index = i;
							break;
						}
					
					if(d_index >= 0)
					{
						DownloadManager dm = (DownloadManager) context.getSystemService(Context.DOWNLOAD_SERVICE);
						DownloadManager.Query query = new DownloadManager.Query();
						query.setFilterById(downloadId);
						Cursor c = dm.query(query);
						if (c.moveToFirst())
						{
							int columnIndex = c.getColumnIndex(DownloadManager.COLUMN_STATUS);
							if (DownloadManager.STATUS_SUCCESSFUL == c.getInt(columnIndex))
							{
								String path = c.getString(c.getColumnIndex(DownloadManager.COLUMN_LOCAL_FILENAME));
								WordlistData.finishWordlistDownload(downloading_data.get(d_index).db_id, path, new File(path).length());
								downloading_data.remove(d_index);
							}
							// TODO: check failed downloads
						}
					}
				}
			}
		};
        registerReceiver(download_receiver, new IntentFilter(DownloadManager.ACTION_DOWNLOAD_COMPLETE));

		setTitle(ShowHashesStats(format_index, getScreenTitleWitdh()));
		ParamsFragment.params = PreferenceManager.getDefaultSharedPreferences(MainActivity.my_activity);
		// Saved data
		if(savedInstanceState != null)
		{
			int app_state = savedInstanceState.getInt(APP_STATE);
			switch(app_state)
			{
			case APP_STATE_IMPORT_HASHES:
				onImportHashesDialog(savedInstanceState.getString(IMPORT_FILENAME));
				break;
			case APP_STATE_CRACKING:
				ResumeAttack(savedInstanceState.getLong(ATTACK_ID), ParamsFragment.getNumThreads(), ParamsFragment.getGPUsUsed());
				break;
			default:
				if(!isTabletUI())
					actionBar.setSelectedNavigationItem(savedInstanceState.getInt(TAB_SELECTED));
				break;
			}
		}
		refreshHashes();
	}
	
	@Override
	protected void onStop()
	{
		BenchmarkStop();
		OnCompleteBenchmark();
		ImportHashesStop();
		
		SaveSettingsToDB();
		 
		super.onStop();
	}
	
	@Override
	protected void onDestroy()
	{
		if(is_cracking)
			 StopAttack();
		// Save the downloading data
		try
		{
			FileOutputStream file = new FileOutputStream(getFilesDir() + "/" + DOWNLOADING_STATE);
			OutputStreamWriter writer = new OutputStreamWriter(file);
			
			for (int i = 0; i < downloading_data.size(); i++)
			{
				writer.write(""+downloading_data.get(i).db_id);
				writer.write('\n');
				writer.write(""+downloading_data.get(i).enqueue_id);
				writer.write('\n');
			}
	
			writer.close();
			file.close();
		}
		catch (Exception e)
		{}
				
		this.unregisterReceiver(download_receiver);
		super.onDestroy();
	}
	 
	 @Override
	protected void onSaveInstanceState(Bundle outState)
	{
		 if(is_importing)
		 {
			 outState.putInt(APP_STATE, APP_STATE_IMPORT_HASHES);
			 outState.putString(IMPORT_FILENAME, import_file_path);
		 }
		 else if(is_cracking)
		 {
			 outState.putInt(APP_STATE, APP_STATE_CRACKING);
			 outState.putLong(ATTACK_ID, GetAttackID());
		 }
		 else
		 {
			 outState.putInt(APP_STATE, APP_STATE_NORMAL);
			 if(!isTabletUI())
				 outState.putInt(TAB_SELECTED, getActionBar().getSelectedNavigationIndex());
		 }
		//super.onSaveInstanceState(outState);
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu)
	{
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		action_menu = menu.findItem(R.id.start_attack);
		if(is_cracking)
		{
			action_menu.setIcon(R.drawable.ic_action_stop);
			action_menu.setTitle("Stop");
		}
		return true;
	}

	// Import hashes
	private boolean is_importing = false;
	private String import_file_path;
	private void onImportHashesDialog(String file_path)
	{
		import_file_path = file_path;
		is_importing = true;
		
		ImportHashes(file_path);
		LayoutInflater inflater = MainActivity.my_activity.getLayoutInflater();
		// Instantiate an AlertDialog.Builder with its constructor
		AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.my_activity)
			.setPositiveButton("OK", new DialogInterface.OnClickListener()
			{
				public void onClick(DialogInterface dialog, int id)
				{
					dialog.dismiss();
					setTitle(ShowHashesStats(format_index, getScreenTitleWitdh()));
					my_activity.tab_main.LoadHashes();
					refreshHashes();
				}
			})
			.setCancelable(false)
			.setTitle("Importing hashes...")
			.setView(inflater.inflate(R.layout.import_stats, null));

		// Get the AlertDialog from create()
		final AlertDialog stats_dialog = builder.create();
		// -------------------------------------------------------------------------

		final Timer import_timer = new Timer();
		stats_dialog.show();
		stats_dialog.getWindow().setLayout(calculateDialogWidth(420), WindowManager.LayoutParams.WRAP_CONTENT);
		stats_dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(false);
		final TableLayout formats_table = (TableLayout)stats_dialog.findViewById(R.id.import_table);
		final String[] format_names = HashesFragment.GetFormats();
		final int[] format_remaped = new int[format_names.length];
		for (int i = 0; i < format_remaped.length; i++)
			format_remaped[i] = -1;
		
		import_timer.schedule(new TimerTask()
		{
			private static final int IMPORT_IS_ENDED = 0;
			private static final int IMPORT_USERS_ADDED = 1;
			private static final int IMPORT_LINES_SKIPED = 2;
			private static final int IMPORT_COMPLETITION = 3;
			private static final int IMPORT_FORMATS_DATA = 4;
			@Override
			public void run()
			{
				final int isEnded = GetImportResultInt(IMPORT_IS_ENDED);
				if (isEnded != 0)
					import_timer.cancel();
				// Update the UI
				MainActivity.my_activity.runOnUiThread(new Runnable()
				{
					private TextView CreateTextView(TextView first_child)
					{
						TextView name = new TextView(my_activity);
						name.setGravity(Gravity.CENTER_HORIZONTAL);
						name.setPadding(10, 0, 0, 0);
						name.setTextSize(first_child.getTextSize()/display_density);
						name.setTextColor(first_child.getTextColors());
						
						return name;
					}
					@Override
					public void run()
					{
						((TextView) stats_dialog.findViewById(R.id.user_added)).setText("Users Added: " + GetImportResultInt(IMPORT_USERS_ADDED));
						((TextView) stats_dialog.findViewById(R.id.lines_skipped)).setText("Lines Skipped: " + GetImportResultInt(IMPORT_LINES_SKIPED));
						((ProgressBar) stats_dialog.findViewById(R.id.status_completition)).setProgress(GetImportResultInt(IMPORT_COMPLETITION));

						for (int i = 0; i < format_names.length; i++)
						{
							int num_users_added 	= GetImportResultInt(3*i+IMPORT_FORMATS_DATA+0);
							int num_users_disabled 	= GetImportResultInt(3*i+IMPORT_FORMATS_DATA+1);
							int num_users_exist 	= GetImportResultInt(3*i+IMPORT_FORMATS_DATA+2);
							
							if(num_users_added > 0 || num_users_disabled > 0 || num_users_exist > 0)
							{
								// Not showed yet
								if(format_remaped[i] < 0)
								{
									TextView first_child = (TextView)((TableRow)formats_table.getChildAt(0)).getChildAt(0);
									
									TableRow row = new TableRow(my_activity);
									TextView name = CreateTextView(first_child);
									name.setText(format_names[i]);
									name.setGravity(Gravity.LEFT);
									row.addView(name);
									
									row.addView(CreateTextView(first_child));
									row.addView(CreateTextView(first_child));
									row.addView(CreateTextView(first_child));
									
									format_remaped[i] = formats_table.getChildCount();
									
									formats_table.addView(row);
								}

								// Update value
								TableRow row = (TableRow) formats_table.getChildAt(format_remaped[i]);
								((TextView)row.getChildAt(1)).setText(""+num_users_added);
								((TextView)row.getChildAt(2)).setText(""+num_users_disabled);
								((TextView)row.getChildAt(3)).setText(""+num_users_exist);
							}
						}

						if (isEnded != 0)
						{
							stats_dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(true);
							stats_dialog.setTitle("Import complete");
							is_importing = false;
						}
					}
				});
			}
		}, 500, 500);
	}
	private void onImportFile()
	{
		// Create the dialog.
		FileChooserDialog dialog = new FileChooserDialog(this, "Select file to import (pwdump | cachedump | .db | .pcap | ...)", getLayoutInflater());

		// Define the filter
		dialog.setFilter(".*txt|.*db|.*pcap|.*cap");

		// Assign listener for the select event.
		dialog.addListener(new FileChooserDialog.OnFileSelectedListener()
		{
			private void BeginImport(Dialog source, String file_path)
			{
				source.dismiss();
				if(file_path.endsWith(".db"))
				{
					ImportDB(file_path);
					// Delete wordlist files to import again
					new File(getFilesDir().getAbsolutePath() + "/" + DEFAULT_WORDLIST).delete();
					new File(getFilesDir().getAbsolutePath() + "/" + DEFAULT_PHRASES_FILE).delete();
					
					// Restart app
					Intent mStartActivity = new Intent(my_activity, MainActivity.class);
					int mPendingIntentId = 123456;
					PendingIntent mPendingIntent = PendingIntent.getActivity(my_activity, mPendingIntentId,    mStartActivity, PendingIntent.FLAG_CANCEL_CURRENT);
					AlarmManager mgr = (AlarmManager)my_activity.getSystemService(Context.ALARM_SERVICE);
					mgr.set(AlarmManager.RTC, System.currentTimeMillis() + 300, mPendingIntent);
					System.exit(0);
				}
				else
					onImportHashesDialog(file_path);
			}

			public void onFileSelected(Dialog source, File file)
			{
				BeginImport(source, file.getAbsolutePath());
			}

			public void onFileSelected(Dialog source, File folder, String name)
			{
				BeginImport(source, folder.getAbsolutePath() + name);
			}
		});

		// Show the dialog.
		dialog.show();
	}
	private static int conflict_format_result;
	private static RadioGroup rb_formats;
	public static int SelectConflictingFormat(final String line, final int[] valid_formats)
	{
		conflict_format_result = -2;
		my_activity.runOnUiThread(new Runnable()
		{
			@Override
			public void run()
			{
				LayoutInflater inflater = MainActivity.my_activity.getLayoutInflater();
				// Instantiate an AlertDialog.Builder with its constructor
				
				AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.my_activity).setPositiveButton("OK", new DialogInterface.OnClickListener()
				{
					public void onClick(DialogInterface dialog, int id)
					{
						// Found the selected format
						int selected_format_id = rb_formats.getCheckedRadioButtonId();
						for (int i = 0; i < rb_formats.getChildCount(); i++)
							if(rb_formats.getChildAt(i).getId() == selected_format_id)
							{
								int num_formats_added = 0;
								for (int j = 0; j < valid_formats.length; j++)
									if(valid_formats[j] != 0)
									{
										if(num_formats_added == i)
										{
											conflict_format_result = j;
											break;
										}
										num_formats_added++;
									}
								break;
							}
						
						if(conflict_format_result < 0)
							conflict_format_result = -1;
						dialog.dismiss();
					}
				}).setCancelable(false).setTitle("Conflicting formats over line of text").setView(inflater.inflate(R.layout.select_format, null));
				
				AlertDialog formats_dialog = builder.create();
				formats_dialog.show();
				//formats_dialog.getWindow().setLayout(calculateDialogWidth(420), WindowManager.LayoutParams.WRAP_CONTENT);
				
				TextView conflict_line = (TextView)formats_dialog.findViewById(R.id.conflict_line);
				conflict_line.setText(line);
				
				rb_formats = (RadioGroup)formats_dialog.findViewById(R.id.conflicting_formats_rb);
				rb_formats.clearCheck();
				int num_formats_added = 0;
				String[] format_names = HashesFragment.GetFormats();
				
				// Add the formats to select
				for (int i = 0; i < valid_formats.length; i++)
					if(valid_formats[i] != 0)
					{
						RadioButton rb = new RadioButton(my_activity);
						rb.setText(format_names[i]);
						rb_formats.addView(rb, num_formats_added);
						if(num_formats_added==0)
							rb_formats.check(rb.getId());
						num_formats_added++;
					}
			}
		});	
		
		while(conflict_format_result < -1)
		{
			try
			{
				Thread.sleep(300);
			}
			catch (InterruptedException e)
			{}
		}
		return conflict_format_result;
	}

	// Attacks
	private int attack_counter;
	private static AlertDialog rules_dialog = null;
	private boolean checkBattery(String fail_message)
	{
		IntentFilter ifilter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
		Intent batteryStatus = my_activity.registerReceiver(null, ifilter);
		int battery_status_val = batteryStatus.getIntExtra(BatteryManager.EXTRA_STATUS, -1);
		int level = batteryStatus.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
		int scale = batteryStatus.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
		
		boolean isDischarging = battery_status_val == BatteryManager.BATTERY_STATUS_DISCHARGING;
		int batteryPct = 100*level /scale;
		
		if(isDischarging && batteryPct < ParamsFragment.getBatteryLimit())
		{
			StopAttack();
			Toast.makeText(my_activity, fail_message, Toast.LENGTH_LONG).show();
			return false;
		}
		// Protect battery
		int health = batteryStatus.getIntExtra(BatteryManager.EXTRA_HEALTH, -1);
		if(health==BatteryManager.BATTERY_HEALTH_OVER_VOLTAGE)
		{
			StopAttack();
			Toast.makeText(my_activity, "Battery over-voltage.", Toast.LENGTH_LONG).show();
			return false;
		}
		if(health==BatteryManager.BATTERY_HEALTH_OVERHEAT)
		{
			StopAttack();
			Toast.makeText(my_activity, "Battery overheat.", Toast.LENGTH_LONG).show();
			return false;
		}
		if(health==BatteryManager.BATTERY_HEALTH_UNSPECIFIED_FAILURE)
		{
			StopAttack();
			Toast.makeText(my_activity, "Battery had an unknow problem.", Toast.LENGTH_LONG).show();
			return false;
		}
		
		return true;
	}
	private void onStartAttackCommon()
	{
		attack_counter = 0;
		is_cracking = true;
		if(action_menu != null)
		{
			action_menu.setIcon(R.drawable.ic_action_stop);
			action_menu.setTitle("Stop");
		}
		
		timer_update_gui = new TimerTask()
		{
			@Override
			public void run()
			{
				status.UpdateStatus();
				if((attack_counter % 256) == 255)
					SaveAttackState();

				// Update the UI
				my_activity.runOnUiThread(new Runnable()
				{
					@Override
					public void run()
					{
						// Check battery status
						if((attack_counter % 8) == 7)
							checkBattery("Battery limit reached, stopping attack.");
						
						tab_status.UpdateStatus(status);
						my_activity.setTitle(ShowHashesStats(format_index, getScreenTitleWitdh()));

						if (!my_activity.is_cracking && my_activity.action_menu != null)
						{
							my_activity.action_menu.setIcon(R.drawable.ic_action_play);
							my_activity.action_menu.setTitle("Start");
							my_activity.tab_main.LoadHashes();
						}
						
						attack_counter++;
					}
				});
			}
		};
		attack_timer = new Timer();
		attack_timer.schedule(timer_update_gui, 3000, 3000);
		if(!isTabletUI())
			this.getActionBar().setSelectedNavigationItem(1);

		tab_status.UpdateCurrentAttack(GetAttackDescription());
		tab_status.setStartText();
		
		PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
		wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "HashSuiteWakeLock");
		wl.acquire();
	}
	private static void FinishBatchCallBack()
	{
		if(attack_timer != null)
		{
			attack_timer.cancel();
			attack_timer = null;
		}
		my_activity.is_cracking = false;
		if(timer_update_gui != null)
		{
			timer_update_gui.run();
			timer_update_gui = null;
		}
		if(wl != null)
		{
			wl.release();
			wl = null;
		}
	}
	private static void ChangeCurrentAttackCallBack()
	{
		final String attack_info = MainActivity.GetAttackDescription();
		my_activity.runOnUiThread(new Runnable()
		{
			@Override
			public void run()
			{
				my_activity.tab_status.UpdateCurrentAttack(attack_info);
			}
		});
	}
	private static void AttackBeginCallBack()
	{
		my_activity.runOnUiThread(new Runnable()
		{
			@Override
			public void run()
			{
				if(rules_dialog != null)
				{
					rules_dialog.dismiss();
					rules_dialog = null;
					
					if(attack_timer != null)
					{
						attack_timer.cancel();
						attack_timer = null;
					}
					if(timer_update_gui != null)
						timer_update_gui = null;
				}
				my_activity.onStartAttackCommon();
			}
		});
	}
	
	private static void alignTopRight(AlertDialog dialog)
	{
		WindowManager.LayoutParams wmlp = new WindowManager.LayoutParams();
		wmlp.copyFrom(dialog.getWindow().getAttributes());
		
    	wmlp.gravity = Gravity.TOP | Gravity.RIGHT;
    	wmlp.x = 0;
    	wmlp.y = (int)(my_activity.getActionBar().getHeight());
    	wmlp.windowAnimations = R.style.DialogAnimation;
    	wmlp.horizontalMargin = 0f;
    	wmlp.verticalMargin = 0f;
    	
    	dialog.getWindow().setAttributes(wmlp);
    	dialog.getWindow().clearFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND);
	}

	// TODO: Test Suite code---------------------------------------------------------------
//	private static native void TestSuite();
//	public static void TestSuiteAttack(final int pformat_index, final int pkey_index)
//	{
//		my_activity.runOnUiThread(new Runnable()
//		{
//			@Override
//			public void run()
//			{
//				//if(!isTabletUI())
//				//	my_activity.getActionBar().setSelectedNavigationItem(0);
//				
//				my_activity.tab_main.SetProviderSelection(pkey_index);
//				//if(MainActivity.format_index == pformat_index)
//				//	my_activity.tab_main.SetFormatSelection(pformat_index + (pformat_index==0 ? 1 : -1));
//				my_activity.tab_main.SetFormatSelection(pformat_index);
//				my_activity.tab_main.LoadHashes();
//				
//				my_activity.onOptionsItemSelected(my_activity.action_menu);
//			}
//		});
//	}
	//-----------------------------------------------------------------------------------
	@Override
	public boolean onOptionsItemSelected(MenuItem item)
	{
		AlertDialog.Builder builder;
		// Handle item selection
		switch (item.getItemId())
		{
		case R.id.start_attack:
			if (!is_cracking)
			{
				if (GetNumHash2Crack(format_index) > 0)
				{
					if(checkBattery("Battery low, can not start the attack."))
					{
						int num_threads = ParamsFragment.getNumThreads();
						int gpus_used = ParamsFragment.getGPUsUsed();
						if(num_threads > 0 || gpus_used > 0)
						{
							int use_rules = ParamsFragment.getUseRules(format_index, key_provider_index);
							int rules_mask_on = ParamsFragment.getRulesOn();
							
							if(use_rules!=0 && rules_mask_on==0)
								Toast.makeText(this, "No rule selected", Toast.LENGTH_SHORT).show();
							else
							{
								StartAttack(format_index, key_provider_index, num_threads, ParamsFragment.getMin(format_index, key_provider_index), ParamsFragment.getMax(format_index, key_provider_index),
									ParamsFragment.getParam(key_provider_index), use_rules, rules_mask_on, gpus_used);
								//onStartAttackCommon();
								if(gpus_used!=0 && use_rules!=0)
								{
									LayoutInflater inflater = my_activity.getLayoutInflater();
									builder = new AlertDialog.Builder(my_activity)
										.setTitle("Compiling rules to device...")
										.setView(inflater.inflate(R.layout.rules_compilation, null))
										//.setIcon(R.drawable.ic_action_alarms)
										.setCancelable(false);
						
									// Get the AlertDialog from create()
									rules_dialog = builder.create();
									rules_dialog.show();
									//rules_dialog.getWindow().setLayout(calculateDialogWidth(560), WindowManager.LayoutParams.WRAP_CONTENT);
									
									timer_update_gui = new TimerTask()
									{
										@Override
										public void run()
										{
											// Update the UI
											my_activity.runOnUiThread(new Runnable()
											{
												@Override
												public void run()
												{
													TextView kernel_memory = (TextView) rules_dialog.findViewById(R.id.rules_compilation_memory);
													ProgressBar rules_compilation_status = (ProgressBar) rules_dialog.findViewById(R.id.rules_compilation_status);
													
													int status = GetRulesGPUStatus();
													
													kernel_memory.setText("Using "+(status&0xffffff)+" KB for kernels");
													rules_compilation_status.setProgress(status>>24);
												}
											});
										}
									};
									attack_timer = new Timer();
									attack_timer.schedule(timer_update_gui, 1000, 1000);
								}
							}
						}
						else
						{
							if(!isTabletUI())
								my_activity.getActionBar().setSelectedNavigationItem(2);
							Toast.makeText(this, "No hardware selected", Toast.LENGTH_SHORT).show();
						}
					}
				}
				else
					Toast.makeText(this, "No hashes loaded", Toast.LENGTH_SHORT).show();
			}
			else
			{
				StopAttack();
			}
			return true;
		case R.id.import_file:
			onImportFile();
			return true;
		case R.id.export:
			CharSequence[] exporters = new CharSequence[] { "Found passwords", "Found passwords as wordlist", "LM/NTLM in pwdump format", "DCC in cachedump format", "Hash Suite Database"};
			builder = new AlertDialog.Builder(my_activity);
			if(!isTabletUI())
				builder.setTitle("Export");
		    builder.setItems(exporters, new DialogInterface.OnClickListener()
		    {
               public void onClick(DialogInterface dialog, final int which)
               {
            	   dialog.dismiss();
            	   // The 'which' argument contains the index position of the selected item
            	   if(which >= 0 && which < 5)
            	   {
            		   	// Create the dialog.
            			FileChooserDialog select_directory = new FileChooserDialog(my_activity, "Select directory to export", my_activity.getLayoutInflater());
            			select_directory.setFolderMode(true);
            			select_directory.setShowOnlySelectable(true);

            			// Assign listener for the select event.
            			select_directory.addListener(new FileChooserDialog.OnFileSelectedListener()
            			{
            				private void Export(Dialog source, String file_path)
            				{
            					source.dismiss();
            					MainActivity.Export(file_path, which);
            					Toast.makeText(my_activity, "Exported file successfully", Toast.LENGTH_SHORT).show();
            				}

            				public void onFileSelected(Dialog source, File file)
            				{
            					Export(source, file.getAbsolutePath());
            				}
            				public void onFileSelected(Dialog source, File folder, String name)
            				{
            					Export(source, folder.getAbsolutePath());
            				}
            			});

            			// Show the dialog.
            			select_directory.show();
            		}
               }
		    });
		    AlertDialog dialog = builder.create();
		    
		    if(isTabletUI())
		    	alignTopRight(dialog);
		    dialog.show();
		    
		    dialog.getWindow().setLayout(calculateDialogWidth(320), WindowManager.LayoutParams.WRAP_CONTENT);
		    
			return true;
		case R.id.resume_attack:
			if(checkBattery("Battery low, can not resume an attack."))
			{
				if (!is_cracking)
				{
					ResumeAttackData[] resume_attacks = ResumeAttackData.GetAttacks2Resume();
					if(resume_attacks.length > 0)
					{
						builder = new AlertDialog.Builder(MainActivity.my_activity);
						if(!isTabletUI())
							builder.setTitle("Choose attack to resume");
		
						LayoutInflater inflater = MainActivity.my_activity.getLayoutInflater();
						builder.setView(inflater.inflate(R.layout.wordlist_preference, null));
		
						// Get the AlertDialog from create()
						final AlertDialog resume_dialog = builder.create();
						if(isTabletUI())
					    	alignTopRight(resume_dialog);
						resume_dialog.show();
						resume_dialog.getWindow().setLayout(calculateDialogWidth(360), WindowManager.LayoutParams.WRAP_CONTENT);
						
						ListView resumes = (ListView)resume_dialog.findViewById(R.id.list_wordlist);
						resumes.setAdapter(new ArrayAdapter<ResumeAttackData>(MainActivity.my_activity, android.R.layout.simple_list_item_1, resume_attacks));
						resumes.setChoiceMode(ListView.CHOICE_MODE_SINGLE);
						resumes.setOnItemClickListener(new OnItemClickListener()
						{
							@Override
							public void onItemClick(AdapterView<?> parent, View view, int position, long id)
							{
								resume_dialog.dismiss();
								int num_threads = ParamsFragment.getNumThreads();
								int gpus_used = ParamsFragment.getGPUsUsed();
								if(num_threads > 0 || gpus_used > 0)
								{
									ResumeAttack(((ResumeAttackData)parent.getItemAtPosition(position)).id, num_threads, gpus_used);
									//onStartAttackCommon();
								}
								else
								{
									if(!isTabletUI())
										my_activity.getActionBar().setSelectedNavigationItem(2);
									Toast.makeText(my_activity, "No hardware selected", Toast.LENGTH_SHORT).show();
								}
							}
						});
					}
					else
						Toast.makeText(this, "No attack to resume", Toast.LENGTH_SHORT).show();
				}
				else
					Toast.makeText(this, "An attack is already executing", Toast.LENGTH_SHORT).show();
			}
			return true;
			
		case R.id.clear_all:
			if (!is_cracking)
			{
				new AlertDialog.Builder(MainActivity.my_activity)
				.setTitle("Operation irreversible.")
				.setMessage("Are you sure you want to delete all accounts?")
				.setPositiveButton("OK", new DialogInterface.OnClickListener()
				{
					@Override
					public void onClick(DialogInterface dialog, int which)
					{
						dialog.dismiss();
						clearAllAccounts();
						tab_main.LoadHashes();
						setTitle(ShowHashesStats(format_index, getScreenTitleWitdh()));
					}
				})
				.setNegativeButton("Cancel", new DialogInterface.OnClickListener()
				{
					@Override
					public void onClick(DialogInterface dialog, int which)
					{
						dialog.dismiss();
					}
				})
				.create()
				.show();
			}
			else
				Toast.makeText(this, "An attack is already executing", Toast.LENGTH_SHORT).show();
			return true;
			
		case R.id.downloader:
			final WordlistData[] wordlists2download = WordlistData.getWordlists2Download();
			final ArrayList<Integer> mSelectedItems = new ArrayList<Integer>();
			String[] wordlists_show = new String[wordlists2download.length];
			for (int i = 0; i < wordlists_show.length; i++)
				wordlists_show[i] = wordlists2download[i].name+" ("+wordlists2download[i].size+")";

			builder = new AlertDialog.Builder(my_activity);
		    builder.setTitle("Select wordlist to download").setMultiChoiceItems(wordlists_show, null, new DialogInterface.OnMultiChoiceClickListener()
		    {
		    	public void onClick(DialogInterface dialog, int which, boolean isChecked)
		    	{
            	   if (isChecked)// If the user checked the item, add it to the selected items
                       mSelectedItems.add(which);
                   else if (mSelectedItems.contains(which))// Else, if the item is already in the array, remove it 
                       mSelectedItems.remove(Integer.valueOf(which));
               }
		    })
		    .setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener()
		    {
               @Override
               public void onClick(DialogInterface dialog, int id)
               {
            	   dialog.dismiss();

            	   DownloadManager dm = (DownloadManager) my_activity.getSystemService(DOWNLOAD_SERVICE);
            	   for (int i = 0; i < mSelectedItems.size(); i++)
            	   {
            		   int which = mSelectedItems.get(i);
            		   
            	       Request request = new Request(Uri.parse(wordlists2download[which].url));
            	       request.setTitle(wordlists2download[which].name);
            	       request.setDescription("Downloading wordlist for Hash Suite");
            	       request.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, wordlists2download[which].name);
            	       long enqueue = dm.enqueue(request);
            	       
            	       downloading_data.add(new WordlistDownloadingData(wordlists2download[which].id, enqueue));
            	       WordlistData.setWordlistStateDownloading(wordlists2download[which].id);
            	   }
            	   
            	   Intent show_downloader = new Intent();
            	   show_downloader.setAction(DownloadManager.ACTION_VIEW_DOWNLOADS);
        	       startActivity(show_downloader);
               }
           });
		    AlertDialog downloader = builder.create();
		    downloader.show();
		    downloader.getWindow().setLayout(calculateDialogWidth(520), WindowManager.LayoutParams.WRAP_CONTENT);

			return true;
		case R.id.benchmark:
			if(checkBattery("Battery low, can not benchmark."))
			{
				if (!is_cracking)
				{
					benchmark_secs = GetBenchmarkDuration();
					String title = (benchmark_secs>60) ? "Benchmark end in " + Math.round(benchmark_secs/60.) + " min" : "Benchmark end in " + benchmark_secs + " sec";
					LayoutInflater inflater = my_activity.getLayoutInflater();
					builder = new AlertDialog.Builder(my_activity)
						.setTitle(title)
						.setView(inflater.inflate(R.layout.benchmark, null))
						//.setIcon(R.drawable.ic_action_alarms)
						.setOnCancelListener(new OnCancelListener()
						{
							@Override
							public void onCancel(DialogInterface dialog)
							{
								BenchmarkStop();
								OnCompleteBenchmark();
							}
						});
		
					// Get the AlertDialog from create()
					benchmark_dialog = builder.create();
					benchmark_dialog.show();
					benchmark_dialog.getWindow().setLayout(calculateDialogWidth(560), WindowManager.LayoutParams.WRAP_CONTENT);
					
					bench_table = (TableLayout)benchmark_dialog.findViewById(R.id.benchmark_table);
					// Hardware
					TableLayout hardware_table = (TableLayout)benchmark_dialog.findViewById(R.id.benchmark_hardware);
					TextView first_child = (TextView)((TableRow)hardware_table.getChildAt(0)).getChildAt(0);
					
					TableRow row_cpu = new TableRow(my_activity);
					TextView cpu_name = new TextView(my_activity);
					cpu_name.setTextSize(first_child.getTextSize()/display_density);
					cpu_name.setTextColor(first_child.getTextColors());
					cpu_name.setText("CPU");
					cpu_name.setGravity(Gravity.LEFT);
					row_cpu.addView(cpu_name);
					
					cpu_name = new TextView(my_activity);
					cpu_name.setTextSize(first_child.getTextSize()/display_density);
					cpu_name.setTextColor(first_child.getTextColors());
					cpu_name.setText(""+Runtime.getRuntime().availableProcessors());
					cpu_name.setGravity(Gravity.CENTER_HORIZONTAL);
					row_cpu.addView(cpu_name);
					
					cpu_name = new TextView(my_activity);
					cpu_name.setTextSize(first_child.getTextSize()/display_density);
					cpu_name.setTextColor(first_child.getTextColors());
					long cpu_clock = get_cpu_clock();
					if(cpu_clock >= 1000)
						cpu_name.setText(String.format("%.2fGHz", (cpu_clock/1000.0)));
					else
						cpu_name.setText(""+cpu_clock+"MHz");
					cpu_name.setGravity(Gravity.CENTER_HORIZONTAL);
					row_cpu.addView(cpu_name);
					
					cpu_name = new TextView(my_activity);
					cpu_name.setTextSize(first_child.getTextSize()/display_density);
					cpu_name.setTextColor(first_child.getTextColors());
					cpu_name.setPadding(10, 0, 0, 0);
					cpu_name.setText("Android " + Build.VERSION.RELEASE);
					cpu_name.setGravity(Gravity.CENTER_HORIZONTAL);
					row_cpu.addView(cpu_name);
					
					hardware_table.addView(row_cpu);
					//GPU
					GPUInfo[] gpus_info = GPUInfo.GetGpusInfo();
					for (int i = 0; i < gpus_info.length; i++)
					{
						TableRow row_gpu = new TableRow(my_activity);
						TextView gpu_name = new TextView(my_activity);
						gpu_name.setTextSize(first_child.getTextSize()/display_density);
						gpu_name.setTextColor(Color.rgb(0, 150, 0));
						//gpu_name.setBackgroundColor(Color.rgb(240, 255, 240));
						gpu_name.setText(gpus_info[i].name);
						gpu_name.setGravity(Gravity.LEFT);
						row_gpu.addView(gpu_name);
						
						gpu_name = new TextView(my_activity);
						gpu_name.setTextSize(first_child.getTextSize()/display_density);
						gpu_name.setTextColor(Color.rgb(0, 150, 0));
						//gpu_name.setBackgroundColor(Color.rgb(240, 255, 240));
						gpu_name.setText(""+gpus_info[i].cores);
						gpu_name.setGravity(Gravity.CENTER_HORIZONTAL);
						row_gpu.addView(gpu_name);
						
						gpu_name = new TextView(my_activity);
						gpu_name.setTextSize(first_child.getTextSize()/display_density);
						gpu_name.setTextColor(Color.rgb(0, 150, 0));
						//gpu_name.setBackgroundColor(Color.rgb(240, 255, 240));
						if(gpus_info[i].frequency >= 1000)
							gpu_name.setText(String.format("%.2fGHz", (gpus_info[i].frequency/1000.0)));
						else
							gpu_name.setText(""+gpus_info[i].frequency+"MHz");
						gpu_name.setGravity(Gravity.CENTER_HORIZONTAL);
						row_gpu.addView(gpu_name);
						
						gpu_name = new TextView(my_activity);
						gpu_name.setTextSize(first_child.getTextSize()/display_density);
						gpu_name.setTextColor(Color.rgb(0, 150, 0));
						//gpu_name.setBackgroundColor(Color.rgb(240, 255, 240));
						gpu_name.setPadding(10, 0, 0, 0);
						gpu_name.setText(gpus_info[i].driver_version);
						gpu_name.setGravity(Gravity.CENTER_HORIZONTAL);
						row_gpu.addView(gpu_name);
						
						hardware_table.addView(row_gpu);
					}
					
					// Bench table
					String[] format_names = HashesFragment.GetFormats();
					TableRow first_row = ((TableRow)bench_table.getChildAt(0));
					first_child = (TextView)first_row.getChildAt(0);
					int[] last_bench_values = GetBenchmarkValues(0);
					int num_gpus = gpus_info.length;
					
					for (int j = 0; j < last_bench_values.length; j++)
					{
						TextView data = new TextView(my_activity);
						if(last_bench_values[j] <= 1000)
						{
							data.setText(""+last_bench_values[j]);
						}
						else
						{
							if(last_bench_values[j]==65536)
								data.setText("2^16");
							else
								data.setText("10^"+((int)Math.log10(last_bench_values[j])));
						}
						data.setPadding(10, 0, 0, 0);	
						data.setTextSize(first_child.getTextSize()/display_density);
						data.setTextColor(first_child.getTextColors());
						data.setGravity(Gravity.CENTER_HORIZONTAL);
						first_row.addView(data);
					}
					
					for (int j = 0; j < format_names.length; j++)
					{
						TableRow row = new TableRow(my_activity);
						row.setLayoutParams(new ViewGroup.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
						
						int[] current_bench_value = GetBenchmarkValues(j);
						if(current_bench_value.length != last_bench_values.length)
						{
							row.addView(new TextView(my_activity));
							
							for (int i = 0; i < current_bench_value.length; i++)
							{
								TextView data = new TextView(my_activity);
								data.setText(""+current_bench_value[i]);
								data.setPadding(10, 0, 0, 0);		
								data.setTextSize(first_child.getTextSize()/display_density);
								data.setTextColor(first_child.getTextColors());
								data.setGravity(Gravity.CENTER_HORIZONTAL);
								row.addView(data);
							}
							
							for (int i = current_bench_value.length; i < Math.max(current_bench_value.length, last_bench_values.length); i++)
								row.addView(new TextView(my_activity));
								
							bench_table.addView(row);
							
							row = new TableRow(my_activity);
							row.setLayoutParams(new ViewGroup.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
						}
						last_bench_values = current_bench_value;
						// Format name
						TextView name = new TextView(my_activity);
						name.setTextSize(first_child.getTextSize()/display_density);
						name.setTextColor(first_child.getTextColors());
						name.setText(format_names[j]);
						name.setGravity(Gravity.LEFT);
						row.addView(name);
						bench_table.addView(row);
						
						for (int i = 0; i < num_gpus; i++)
						{
							row = new TableRow(my_activity);
							row.setLayoutParams(new ViewGroup.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
							
							name = new TextView(my_activity);
							name.setTextSize(first_child.getTextSize()/display_density);
							name.setTextColor(Color.rgb(0, 150, 0));
							//name.setBackgroundColor(Color.rgb(230, 255, 230));
							//name.setText("GPU"+i);
							//name.setGravity(Gravity.CENTER_HORIZONTAL);
							row.addView(name);
							bench_table.addView(row);
						}
					}
					
					is_complete_benchmark = false;
					new Thread(new Runnable()
					{
				        public void run()
				        {
				            Benchmark();
				        }
				    }).start();
				}
				else
					Toast.makeText(this, "An attack is already executing", Toast.LENGTH_SHORT).show();
			}
			return true;
		case R.id.about:
			//TestSuite();
			builder = new AlertDialog.Builder(MainActivity.my_activity)
				.setTitle("About")
				//.setIcon(R.drawable.ic_action_about)
				.setView(this.getLayoutInflater().inflate(R.layout.about, null))
				.setPositiveButton("OK", new DialogInterface.OnClickListener()
				{
					@Override
					public void onClick(DialogInterface dialog, int which)
					{
						dialog.dismiss();
					}
				});
			AlertDialog about = builder.create();
			about.show();
			about.getWindow().setLayout(calculateDialogWidth(340), WindowManager.LayoutParams.WRAP_CONTENT);
			
			// Set the url
			TextView url_hs = (TextView)about.findViewById(R.id.visit_website);
			url_hs.setText(Html.fromHtml("<a href=\"http://hashsuite.openwall.net\">Hash Suite Website</a>"));
			url_hs.setMovementMethod(LinkMovementMethod.getInstance());
			
			try
			{
				String app_version = my_activity.getPackageManager().getPackageInfo(my_activity.getPackageName(), 0).versionName;
				TextView about_version = (TextView)about.findViewById(R.id.about_version);
				about_version.setText(about_version.getText()+app_version);
			}
			catch (NameNotFoundException e)
			{}
				
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}
	private static long get_cpu_clock()
	{
		// Find CPU clock speed
		long cpu_clock = 0;
		File cpu_clock_file = new File("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq");
		if (cpu_clock_file.exists())
		{
			 try
			 {
				 BufferedReader br = new BufferedReader(new FileReader(cpu_clock_file));
				 cpu_clock = Long.parseLong(br.readLine());
				 br.close();
			 }
			 catch (IOException e)
			 {}
		}
		cpu_clock = Math.round(cpu_clock/1000.);
		
		return cpu_clock;
	}

	// Benchmark
	static AlertDialog benchmark_dialog = null;
	static TableLayout bench_table = null;
	static int benchmark_secs;
	private static int[] bench_dcc_values = new int[]{1,4,16,64}; 
	private static boolean is_complete_benchmark;
	static void SetBenchData(final String bench_data, final int row_index, int time_spend)
	{
		benchmark_secs -= time_spend;
		my_activity.runOnUiThread(new Runnable()
		{
			@Override
			public void run()
			{
				if(bench_table != null)
				{
					TableRow row = (TableRow)bench_table.getChildAt(2+row_index);
					TextView first_child = ((TextView)row.getChildAt(0));
					
					TextView data = new TextView(my_activity);
					data.setText(bench_data);
					data.setPadding(10, 0, 0, 0);		
					data.setTextSize(first_child.getTextSize()/display_density);
					data.setTextColor(first_child.getTextColors());
					data.setGravity(Gravity.CENTER_HORIZONTAL);
					row.addView(data);
					
					if(benchmark_secs > 60)
						benchmark_dialog.setTitle("Benchmark end in " + Math.round(benchmark_secs/60.) + " min");
					else
						benchmark_dialog.setTitle("Benchmark end in " + benchmark_secs + " sec");
				}
			}
		});
	}
	private static void SaveDataTable(TableLayout table, OutputStreamWriter writer) throws IOException
	{
		writer.write('\n');
		// Save benchmark table data
		for (int i = 0; i < table.getChildCount(); i++)
		{
			View child = table.getChildAt(i);
			if(child != null && child instanceof TableRow)
			{
				TableRow row = (TableRow)child;
				for (int j = 0; j < row.getChildCount(); j++)
				{
					View text_view = row.getChildAt(j);
					if(text_view instanceof TextView)
					{
						writer.write(((TextView)row.getChildAt(j)).getText().toString().replace(',', ' '));
						writer.write(',');
					}
				}
				writer.write('\n');
			}
		}
	}
	static void OnCompleteBenchmark()
	{
		if(is_complete_benchmark) return;
		
		is_complete_benchmark = true;
		my_activity.runOnUiThread(new Runnable()
		{
			@Override
			public void run()
			{
				if(benchmark_dialog != null)
					benchmark_dialog.setTitle("Benchmark Complete");
				
				// Try to save the benchmark as a csv file
				if(bench_table != null)
				{
					try
					{
						File bench_file = new File(my_activity.getExternalFilesDir(null), "benchmark.csv");
						FileOutputStream file = new FileOutputStream(bench_file.getAbsolutePath(), true);
						OutputStreamWriter writer = new OutputStreamWriter(file);
						
						String app_version = my_activity.getPackageManager().getPackageInfo(my_activity.getPackageName(), 0).versionName;
						
						// Save benchmark header
						writer.write("/////////////////////////////////////////////////////////////////////////////////\n");
						writer.write("Hash Suite Droid "+app_version);
						writer.write(","+Build.MANUFACTURER);
						writer.write(" "+Build.PRODUCT);
						writer.write(" "+Build.MODEL);
						writer.write(","+new Date().toString()+"\n");
						
						// Save benchmark table data
						SaveDataTable((TableLayout)benchmark_dialog.findViewById(R.id.benchmark_hardware), writer);
						SaveDataTable(bench_table, writer);
				
						writer.close();
						file.close();
					}
					catch (Exception e)
					{}
				}
				benchmark_dialog = null;
				bench_table = null;
			}
		});
	}

	// Spinners
	public void onItemSelected(AdapterView<?> parent, View view, int pos, long id)
	{
		int spinner_id = parent.getId();
		if (spinner_id == R.id.format_selector && format_index != pos)
		{
			format_index = pos;
			setTitle(ShowHashesStats(format_index, getScreenTitleWitdh()));
			current_page_hash = 0;
			tab_main.LoadHashes();
			SaveSetting(ID_FORMAT_BASE, format_index+ID_FORMAT_BASE);
			// Check supported LM Provider
			if (format_index == LM_INDEX && (key_provider_index == PHRASES_INDEX || key_provider_index == LM2NTLM_INDEX))
			{
				Toast.makeText(this, "Unsupported key-provider, changing to Charset", Toast.LENGTH_SHORT).show();
				tab_main.SetProviderSelection(0);
			}
		}
		if (spinner_id == R.id.key_provider_selector && key_provider_index != pos)
		{
			// Check supported LM Provider
			if (format_index == LM_INDEX && (pos == PHRASES_INDEX || pos == LM2NTLM_INDEX))
			{
				Toast.makeText(this, "Unsupported key-provider for LM format", Toast.LENGTH_SHORT).show();
				tab_main.SetProviderSelection(key_provider_index);
			}
			else
			{
				key_provider_index = pos;
				SaveSetting(ID_KEY_PROV_BASE, key_provider_index+ID_KEY_PROV_BASE);
			}
		}
	}

	public void onNothingSelected(AdapterView<?> parent)
	{
	}

	private void refreshHashes()
	{
		Timer refresh_hashes = new Timer();
		refresh_hashes.schedule(new TimerTask()
		{
			@Override
			public void run()
			{
				my_activity.runOnUiThread(new Runnable()
				{
					@Override
					public void run()
					{
						my_activity.tab_main.LoadHashes();
					}
				});
			}
		}, 300);
	}
	// Tabs navigation
	@Override
	public void onTabSelected(ActionBar.Tab tab, FragmentTransaction ft)
	{
		int position = tab.getPosition();
		
		ft.replace(android.R.id.content, my_tabs[position]);
		
		if(position == 0)
			refreshHashes();
	}
	@Override
	public void onTabUnselected(ActionBar.Tab tab, FragmentTransaction ft)
	{
		int position = tab.getPosition();
		ft.remove(my_tabs[position]);
	}
	@Override
	public void onTabReselected(ActionBar.Tab tab, FragmentTransaction ft)
	{}
}

class WordlistDownloadingData
{
	public long db_id;
	public long enqueue_id;
	
	public WordlistDownloadingData(long db_id, long enqueue_id)
	{
		this.db_id = db_id;
		this.enqueue_id = enqueue_id;
	}
}

class ResumeAttackData
{
	public String name;
	public long id;

	public static native ResumeAttackData[] GetAttacks2Resume(); 
	
	@Override
	public String toString()
	{
		return name;
	}
}

class Account
{
	public String username;
	//public String hash;
	public String cleartext;
	public int flag;
	
	public static native Account[] GetHashes(int format_index, int num_hashes_show, int offset);
}

class AttackStatusData
{
	public String num_passwords_loaded;
	public String key_served;
	public String key_space_batch;

	public String password_per_sec;
	public String time_begin;
	public String time_total;
	public String work_done;
	public String finish_time;

	public int progress;
	public native void UpdateStatus();
}

class GPUInfo
{
	public String name;
	public int cores;
	public int frequency;
	public String driver_version;
	public int vendor_icon;
	
	public static native GPUInfo[] GetGpusInfo();
}

