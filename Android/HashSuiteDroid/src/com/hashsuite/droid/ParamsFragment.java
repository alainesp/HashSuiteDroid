// This file is part of Hash Suite password cracker,
// Copyright (c) 2014 by Alain Espinosa. See LICENSE.

package com.hashsuite.droid;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.preference.CheckBoxPreference;
import android.preference.Preference;
import android.preference.PreferenceCategory;
import android.preference.PreferenceFragment;

public class ParamsFragment extends PreferenceFragment
{
	private static final String pref_key_threads = "pref_key_threads";
	private static final String pref_key_charset_range = "pref_key_charset_range";
	private static final String pref_key_charset_string = "pref_key_charset_string";
	private static final String pref_key_wordlist = "pref_key_wordlist";
	private static final String pref_key_keyboard_range = "pref_key_keyboard_range";
	private static final String pref_key_keyboard_layout = "pref_key_keyboard_layout";
	private static final String pref_key_phrases_range = "pref_key_phrases_range";
	private static final String pref_key_phrases_words = "pref_key_phrases_words";
	private static final String pref_key_battery_limit = "pref_key_battery_limit";
	private static final String pref_key_charset_use_rules = "pref_key_charset_use_rules";
	private static final String pref_key_wordlist_use_rules = "pref_key_wordlist_use_rules";
	private static final String pref_key_keyboard_use_rules = "pref_key_keyboard_use_rules";
	private static final String pref_key_phrases_use_rules = "pref_key_phrases_use_rules";
	private static final String pref_key_rules = "pref_key_rules";
	
	private static final int ICON_SNAPDRAGON = 20;
	static SharedPreferences params;

	public ParamsFragment()
	{}

	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);

		// Load the preferences from an XML resource
		addPreferencesFromResource(R.xml.params);
		
		PreferenceCategory hardware_category = (PreferenceCategory)this.findPreference("pref_key_hardware");
		GPUInfo[] gpus_info = GPUInfo.GetGpusInfo();
		for (int i = 0; i < gpus_info.length; i++)
		{
			Preference preference = new CheckBoxPreference(MainActivity.my_activity);
			preference.setTitle("Use " + gpus_info[i].name);
			preference.setKey("pref_key_gpu" + i);
			preference.setDefaultValue(true);
			preference.setPersistent(true);
			if(MainActivity.screen_width_dp < 640 || MainActivity.screen_width_dp >= 960)
				preference.setIcon((gpus_info[i].vendor_icon==ICON_SNAPDRAGON) ? R.drawable.ic_snapdragon : R.drawable.ic_opencl);
			hardware_category.addPreference(preference);
		}
	}
	
	public static int getGPUsUsed()
	{
		int mask = 0;
		GPUInfo[] gpus_info = GPUInfo.GetGpusInfo();
		for (int i = 0; i < gpus_info.length; i++)
			if(params.getBoolean("pref_key_gpu" + i, true))
				mask |= 1 << i;
		
		return mask;
	}

	public static int getNumThreads()
	{
		return params.getInt(pref_key_threads, ThreadsPreference.getDefaultValue());
	}
	
	public static int getBatteryLimit()
	{
		return params.getInt(pref_key_battery_limit, 20) & 0xff;
	}
	public static int getBatteryMaxTemperature()
	{
		return params.getInt(pref_key_battery_limit, 50) >> 8;
	}
	public static int getUseRules(int format_index, int key_provider_index)
	{
		if(format_index == MainActivity.LM_INDEX)
			return 0;
		
		boolean use_rules = false;
		
		switch (key_provider_index)
		{
		case MainActivity.CHARSET_INDEX:
			use_rules = params.getBoolean(pref_key_charset_use_rules, false);
			break;

		case MainActivity.WORDLIST_INDEX:
			use_rules = params.getBoolean(pref_key_wordlist_use_rules, true);
			break;

		case MainActivity.KEYBOARD_INDEX:
			use_rules = params.getBoolean(pref_key_keyboard_use_rules, false);
			break;

		case MainActivity.PHRASES_INDEX:
			use_rules = params.getBoolean(pref_key_phrases_use_rules, false);
			break;
			
		case MainActivity.DB_INFO_INDEX:
			use_rules = true;
			break;
		}
		
		if(use_rules)
			return 1;
		
		return 0;
	}
	
	public static int getRulesOn()
	{
		return params.getInt(pref_key_rules, RulesPreference.DEFAULT_VALUE);
	}

	public static int getMin(int format_index, int key_provider_index)
	{
		int range;
		switch (key_provider_index)
		{
		case MainActivity.CHARSET_INDEX:
			range = params.getInt(pref_key_charset_range, RangeNumberPreference.DEFAULT_VALUE);
			return RangeNumberPreference.getBeginValue(range);

		case MainActivity.WORDLIST_INDEX:
		case MainActivity.DB_INFO_INDEX:
			return 1;

		case MainActivity.KEYBOARD_INDEX:
			range = params.getInt(pref_key_keyboard_range, RangeNumberPreference.DEFAULT_VALUE);
			return RangeNumberPreference.getBeginValue(range);

		case MainActivity.PHRASES_INDEX:
			range = params.getInt(pref_key_phrases_range, RangeNumberPreference.DEFAULT_VALUE);
			return RangeNumberPreference.getBeginValue(range);
		}

		return 0;
	}

	public static int getMax(int format_index, int key_provider_index)
	{
		int range;
		switch (key_provider_index)
		{
		case MainActivity.CHARSET_INDEX:
			range = params.getInt(pref_key_charset_range, RangeNumberPreference.DEFAULT_VALUE);
			return RangeNumberPreference.getEndValue(range);

		case MainActivity.WORDLIST_INDEX:
		case MainActivity.DB_INFO_INDEX:
		case MainActivity.LM2NTLM_INDEX:
			if (format_index == MainActivity.LM_INDEX)
				return 7;
			return 27;

		case MainActivity.KEYBOARD_INDEX:
			range = params.getInt(pref_key_keyboard_range, RangeNumberPreference.DEFAULT_VALUE);
			return RangeNumberPreference.getEndValue(range);

		case MainActivity.PHRASES_INDEX:
			range = params.getInt(pref_key_phrases_range, RangeNumberPreference.DEFAULT_VALUE);
			return RangeNumberPreference.getEndValue(range);
		}

		return 0;
	}

	public static String getParam(int key_provider_index)
	{
		int selection;
		switch (key_provider_index)
		{
		case MainActivity.CHARSET_INDEX:
			selection = params.getInt(pref_key_charset_string, CharsetStringPreference.DEFAULT_VALUE);
			CharsetStringPreference.setCharset(selection);
			return "";

		case MainActivity.WORDLIST_INDEX:
			selection = params.getInt(pref_key_wordlist, 0);
			return WordlistPreference.getWordlistId(selection);

		case MainActivity.KEYBOARD_INDEX:
			selection = params.getInt(pref_key_keyboard_layout, 0);
			KeyboardLayoutPreference.setKeyboard(selection);
			return "";

		case MainActivity.PHRASES_INDEX:
			MainActivity.setPhrasesMaxWords(params.getInt(pref_key_phrases_words, NumberPreference.DEFAULT_VALUE));
			return "1";
		}

		return "";
	}
}
