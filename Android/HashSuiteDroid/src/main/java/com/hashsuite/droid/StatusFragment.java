// This file is part of Hash Suite password cracker,
// Copyright (c) 2014 by Alain Espinosa. See LICENSE.

package com.hashsuite.droid;

import android.app.Fragment;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.BatteryManager;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ProgressBar;
import android.widget.TextView;

public class StatusFragment extends Fragment
{
	private TextView rate;
	private TextView load;
	private TextView done;

	private TextView time;
	private TextView end_in;
	private TextView all_time;

	private TextView keys_tested;
	private TextView key_space;

	private ProgressBar pb_attack;
	
	private TextView current_attack;
	private String current_attack_value;
	
	private TextView battery_temperature;
	private int max_temperature = 0;

	public StatusFragment()
	{
		MainActivity.my_activity.tab_status = this;
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState)
	{
		View rootView = inflater.inflate(R.layout.status_tab, container, false);

		rate = (TextView) rootView.findViewById(R.id.status_rate);
		load = (TextView) rootView.findViewById(R.id.status_load);
		done = (TextView) rootView.findViewById(R.id.status_done);

		time = (TextView) rootView.findViewById(R.id.status_time);
		end_in = (TextView) rootView.findViewById(R.id.status_end_in);
		all_time = (TextView) rootView.findViewById(R.id.status_all_time);

		keys_tested = (TextView) rootView.findViewById(R.id.status_keys_tested);
		key_space = (TextView) rootView.findViewById(R.id.status_key_space);
		
		current_attack = (TextView) rootView.findViewById(R.id.current_attack);
		if (current_attack_value != null)
			current_attack.setText(current_attack_value);

		pb_attack = ((ProgressBar) rootView.findViewById(R.id.pb_attack));
		battery_temperature = (TextView) rootView.findViewById(R.id.battery_temp);

		return rootView;
	}

	public void setStartText()
	{
		if(rate != null) rate.setText("---");
		if(load != null) load.setText("---");
		if(done != null) done.setText("---");

		if(time != null)	 time.setText("---");
		if(end_in != null)	 end_in.setText("---");
		if(all_time != null) all_time.setText("---");

		if(keys_tested != null) keys_tested.setText("---");
		if(key_space != null)  key_space.setText("---");
		if(pb_attack != null) {pb_attack.setIndeterminate(false); pb_attack.setProgress(1);}
		if(battery_temperature != null) battery_temperature.setText("");
		max_temperature = 0;
	}
	public void UpdateCurrentAttack(String attack_info)
	{
		if(current_attack != null)
			current_attack.setText(attack_info);

		current_attack_value = attack_info;
	}

	public void UpdateStatus(AttackStatusData data)
	{
		if(rate != null) rate.setText(data.password_per_sec);
		if(load != null) load.setText(data.num_passwords_loaded);
		if(done != null) done.setText(data.work_done);

		if(time != null)	 time.setText(data.time_begin);
		if(end_in != null)	 end_in.setText(data.finish_time);
		if(all_time != null) all_time.setText(data.time_total);

		if(keys_tested != null) keys_tested.setText(data.key_served);
		if(key_space != null)  key_space.setText(data.key_space_batch);

		if(pb_attack != null)
		{
			if (data.progress > 0)
			{
				pb_attack.setIndeterminate(false);
				pb_attack.setProgress(data.progress);
			}
			else
				pb_attack.setIndeterminate(true);
		}
		
		if(battery_temperature != null)
		{
			IntentFilter ifilter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
			Intent batteryStatus = MainActivity.my_activity.registerReceiver(null, ifilter);
			int battery_temp = batteryStatus.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1);
			if(battery_temp > max_temperature)
				max_temperature = battery_temp;
			battery_temperature.setText(""+(battery_temp/10.)+"℃");
		}
	}
}
