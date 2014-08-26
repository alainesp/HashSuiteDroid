// This file is part of Hash Suite password cracker,
// Copyright (c) 2014 by Alain Espinosa. See LICENSE.

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
import android.view.WindowManager;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.TableLayout;
import android.widget.TableRow;
import android.widget.TextView;
import android.widget.Toast;
import ar.com.daidalos.afiledialog.FileChooserDialog;

public class MainActivity extends Activity implements ActionBar.TabListener, OnItemSelectedListener
{
	// Formats constants
	static final int LM_INDEX = 0;
	private static final int NTLM_INDEX = 1;
	private static final int DCC_INDEX = 2;

	// Key-providers constants
	static final int CHARSET_INDEX = 0;
	static final int WORDLIST_INDEX = 1;
	static final int KEYBOARD_INDEX = 2;
	static final int PHRASES_INDEX = 3;
	static final int DB_INFO_INDEX = 4;
	static final int LM2NTLM_INDEX = 5;
	private static final int FAST_LM_INDEX = 6;
	private static final int RULES_INDEX = 7;

	// Native methods
	private static native void initAll(String files_path);
	// In_Out
	private static native void ImportHashes(String file_path);
	private static native ImportResult GetImportResult();
	private static native void ImportHashesStop();
	private static native void ImportDB(String file_path);
	private static native void Export(String dir_path, int index);
	
	// Hashes stats
	private static native String ShowHashesStats(int format_index, int width);
	private static native int GetNumHash2Crack(int format_index);
	static native int GetNumMatches();
	private static native void clearAllAccounts();

	// Attacks
	private static native void StartAttack(int format_index, int provider_index, int num_threads, int min_size, int max_size, String param, int use_rules, int rules_on);
	private static native void ResumeAttack(long db_id, int num_threads);
	private static native void StopAttack();
	private static native long GetAttackID();
	private static native void SaveAttackState();
	private static native String GetAttackDescription();
	private static native void Benchmark();
	private static native void BenchmarkStop();

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
	private static int screen_width_dp;
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
				ResumeAttack(savedInstanceState.getLong(ATTACK_ID), ParamsFragment.getNumThreads());
				onStartAttackCommon();
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
		
		import_timer.schedule(new TimerTask()
		{
			@Override
			public void run()
			{
				final ImportResult importer_stats = GetImportResult();
				if (importer_stats.isEnded != 0)
					import_timer.cancel();
				// Update the UI
				MainActivity.my_activity.runOnUiThread(new Runnable()
				{
					@Override
					public void run()
					{
						((TextView) stats_dialog.findViewById(R.id.user_added)).setText("Users Added: " + importer_stats.num_users_added);
						((TextView) stats_dialog.findViewById(R.id.lines_skipped)).setText("Lines Skipped: " + importer_stats.lines_skiped);

						((TextView) stats_dialog.findViewById(R.id.lm_added)).setText("" + importer_stats.num_hash_added_lm);
						((TextView) stats_dialog.findViewById(R.id.lm_disable)).setText("" + importer_stats.num_hash_disable_lm);
						((TextView) stats_dialog.findViewById(R.id.lm_exist)).setText("" + importer_stats.num_hash_exist_lm);

						((TextView) stats_dialog.findViewById(R.id.ntlm_added)).setText("" + importer_stats.num_hash_added_ntlm);
						((TextView) stats_dialog.findViewById(R.id.ntlm_disable)).setText("" + importer_stats.num_hash_disable_ntlm);
						((TextView) stats_dialog.findViewById(R.id.ntlm_exist)).setText("" + importer_stats.num_hash_exist_ntlm);

						((TextView) stats_dialog.findViewById(R.id.dcc_added)).setText("" + importer_stats.num_hash_added_dcc);
						((TextView) stats_dialog.findViewById(R.id.dcc_disable)).setText("" + importer_stats.num_hash_disable_dcc);
						((TextView) stats_dialog.findViewById(R.id.dcc_exist)).setText("" + importer_stats.num_hash_exist_dcc);

						((ProgressBar) stats_dialog.findViewById(R.id.status_completition)).setProgress(importer_stats.completition);

						if (importer_stats.isEnded != 0)
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
		FileChooserDialog dialog = new FileChooserDialog(this, "Select file to import (pwdump | cachedump | .db)", getLayoutInflater());

		// Define the filter
		dialog.setFilter(".*txt|.*db");

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

	// Attacks
	private int attack_counter;
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
						if((attack_counter % 16) == 15)
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
						StartAttack(format_index, key_provider_index, ParamsFragment.getNumThreads(), ParamsFragment.getMin(format_index, key_provider_index), ParamsFragment.getMax(format_index, key_provider_index),
								ParamsFragment.getParam(key_provider_index), ParamsFragment.getUseRules(format_index, key_provider_index), ParamsFragment.getRulesOn());
						onStartAttackCommon();
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
								ResumeAttack(((ResumeAttackData)parent.getItemAtPosition(position)).id, ParamsFragment.getNumThreads());
								onStartAttackCommon();
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
					benchmark_secs = 5 * (8*2+4);
					LayoutInflater inflater = MainActivity.my_activity.getLayoutInflater();
					builder = new AlertDialog.Builder(MainActivity.my_activity)
						.setTitle("Benchmark end in " + benchmark_secs + " sec")
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
					benchmark_dialog.getWindow().setLayout(calculateDialogWidth(330), WindowManager.LayoutParams.WRAP_CONTENT);
					
					bench_table = (TableLayout)benchmark_dialog.findViewById(R.id.benchmark_table);
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
	
	// Benchmark
	static AlertDialog benchmark_dialog = null;
	static TableLayout bench_table = null;
	static int benchmark_secs;
	private static int[] bench_dcc_values = new int[]{1,4,16,64}; 
	private static boolean is_complete_benchmark;
	static void SetBenchData(final String bench_data, final int row_index)
	{
		my_activity.runOnUiThread(new Runnable()
		{
			@Override
			public void run()
			{
				if(bench_table != null)
				{
					TextView data = new TextView(my_activity);
					data.setText(bench_data);
					data.setPadding(10, 0, 0, 0);
	
					TableRow row = (TableRow)bench_table.getChildAt(2+row_index);
					TextView first_child = ((TextView)row.getChildAt(0));
					
					// Add DCC numbers
					if(row.getChildCount() == 3)
					{
						TextView num = new TextView(my_activity);
						num.setText(""+bench_dcc_values[row_index]);
						num.setPadding(10, 0, 0, 0);
						num.setTextSize(first_child.getTextSize()/display_density);
						num.setTextColor(first_child.getTextColors());
						row.addView(num);
					}
					
					data.setTextSize(first_child.getTextSize()/display_density);
					data.setTextColor(first_child.getTextColors());
					row.addView(data);
					benchmark_secs -= 5;
					benchmark_dialog.setTitle("Benchmark end in " + benchmark_secs + " sec");
				}
			}
		});
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
						String app_version = my_activity.getPackageManager().getPackageInfo(my_activity.getPackageName(), 0).versionName;
						
						// Save benchmark header
						writer.write("/////////////////////////////////////////////////////////////////////////////////\n");
						writer.write("Hash Suite Droid "+app_version);
						if(Runtime.getRuntime().availableProcessors() == 1)
							writer.write(",1 core at "+cpu_clock+"MHz");
						else
							writer.write(","+Runtime.getRuntime().availableProcessors() +" cores at "+cpu_clock+"MHz");
						writer.write(","+Build.MANUFACTURER);
						writer.write(" "+Build.PRODUCT);
						writer.write(" "+Build.MODEL);
						writer.write(",Android OS "+Build.VERSION.RELEASE);
						writer.write(","+new Date().toString()+"\n");
						
						// Save benchmark table data
						for (int i = 0; i < bench_table.getChildCount(); i++)
						{
							View child = bench_table.getChildAt(i);
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

class ImportResult
{
	public int isEnded;

	public int completition;
	public int num_users_added;
	public int lines_skiped;

	public int num_hash_added_lm;
	public int num_hash_disable_lm;
	public int num_hash_exist_lm;

	public int num_hash_added_ntlm;
	public int num_hash_disable_ntlm;
	public int num_hash_exist_ntlm;

	public int num_hash_added_dcc;
	public int num_hash_disable_dcc;
	public int num_hash_exist_dcc;
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

