// This file is part of Hash Suite password cracker,
// Copyright (c) 2014 by Alain Espinosa
//
// Code licensed under GPL version 2

package com.hashsuite.droid;

import android.app.Fragment;
import android.content.Context;
import android.graphics.Color;
import android.os.Bundle;
import android.view.GestureDetector;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.View.OnTouchListener;
import android.view.animation.TranslateAnimation;
import android.widget.ArrayAdapter;
import android.widget.LinearLayout;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;
import android.widget.ViewFlipper;

public class HashesFragment extends Fragment implements OnTouchListener
{
	private GestureDetector mDetector;
	private TextView pager_text = null;
	private Spinner _key_providers = null;
	private LinearLayout hashes0;
	private LinearLayout hashes1;
	private ViewFlipper hashes_flipper;

	public HashesFragment()
	{
		MainActivity.my_activity.tab_main = this;
	}
	
	// Loading hashes
	static class AccountViewData
	{
		public TextView username;
		public TextView cleartext;
		//public TextView hash;
	}
	// private static final int UNKNOW_CLEARTEXT = 0;
	// private static final int NO_BG_COLOR = 0;
	private static final int PARTIAL_CLEARTEXT = 1;
	private static final int FOUND_CLEARTEXT = 2;
	private static final int FOUND_DISABLE = 3;
	private static final int FOUND_EXPIRE = 4;
	// private static final int HEADER_COLOR = 5;
	private static final int BG_COLOR_GPU = 6;
	// private static final int BG_COLOR_CPU = 7;
	private static final int ITEM_DATA_MASK = 0xFF;
	private boolean use_hashes0 = true;

	private static int GetCellTextColor(int flag)
	{
		switch (flag & ITEM_DATA_MASK)
		{
		case PARTIAL_CLEARTEXT:
		case FOUND_CLEARTEXT:
			return Color.rgb(180, 10, 40);
		case FOUND_DISABLE:
			return Color.rgb(100, 100, 100);
		case FOUND_EXPIRE:
			return Color.rgb(90, 50, 74);
		case BG_COLOR_GPU:
			return Color.rgb(0, 100, 0);
		}

		return Color.BLACK;
	}
	private static int GetCellBkColor(int flag)
	{
		switch (flag & ITEM_DATA_MASK)
		{
		case PARTIAL_CLEARTEXT:
			return Color.rgb(255, 246, 246);
		case FOUND_CLEARTEXT:
			return Color.rgb(250, 220, 220);
		case FOUND_DISABLE:
			return Color.rgb(226, 226, 226);
		case FOUND_EXPIRE:
			return Color.rgb(240, 210, 226);
			// case HEADER_COLOR:
			// return header_color;
		case BG_COLOR_GPU:
			return Color.rgb(230, 255, 230);
		}

		// return Color.rgb(234, 234, 234);
		return Color.rgb(255, 255, 255);
	}
	private void addHash(LinearLayout hashes, int index, LayoutInflater inflater, Account[] accounts)
	{
		View vi = hashes.getChildAt(index);
		boolean view_exists = true;
		AccountViewData data;
		if (vi == null)
		{
			vi = inflater.inflate(R.layout.one_account, null);

			// Use Cache
			data = new AccountViewData();
			data.username = (TextView) vi.findViewById(R.id.account_username);
			data.cleartext = (TextView) vi.findViewById(R.id.account_cleartext);
			//data.hash = (TextView) vi.findViewById(R.id.account_hex);
			vi.setTag(data);
			view_exists = false;
		}
		else
			data = (AccountViewData) vi.getTag();

		// Set information about account
		Account item = accounts[index];
		data.username.setText(item.username);
		data.cleartext.setText(item.cleartext);
		//if(data.hash != null)
		//	data.hash.setText(item.hash);

		// Set fancy colors
		vi.setBackgroundColor(GetCellBkColor(item.flag));
		int text_color = GetCellTextColor(item.flag);
		data.username.setTextColor(text_color);
		data.cleartext.setTextColor(text_color);
		//if(data.hash != null)
		//	data.hash.setTextColor(text_color);

		if(!view_exists)
			hashes.addView(vi);
	}
	public void LoadHashes()
	{
		if(hashes0 == null || hashes1 == null)
			return;
		
		// Calculate number of hashes in screen
		int hashes_height = ((View) hashes0.getParent()).getHeight() - hashes0.getTop();
		hashes_height -= hashes0.getPaddingTop() + hashes0.getPaddingBottom();
		View first_item = hashes0.getChildAt(0);
		if(first_item != null)
		{
			int item_height = first_item.getMeasuredHeight();

			if (hashes_height > 0 && item_height > 0)
			{
				int hashes_count = hashes_height / item_height;
				if (MainActivity.num_hashes_show != hashes_count)
				{
					MainActivity.num_hashes_show = hashes_count;
					MainActivity.current_page_hash = 0;
				}
			}
		}
		
		LayoutInflater inflater = (LayoutInflater) MainActivity.my_activity.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
		Account[] _accounts = Account.GetHashes(MainActivity.format_index, MainActivity.num_hashes_show, MainActivity.current_page_hash * MainActivity.num_hashes_show);
		SetPageinfo(MainActivity.current_page_hash, MainActivity.num_hashes_show, MainActivity.GetNumMatches());

		LinearLayout hashes = use_hashes0 ? hashes0 : hashes1;
		for (int i = 0; i < _accounts.length; i++)
			addHash(hashes, i, inflater, _accounts);
		// Remove hashes not needed
		int count_view_to_remove = hashes.getChildCount() - _accounts.length;
		if (count_view_to_remove > 0)
			hashes.removeViews(_accounts.length, count_view_to_remove);
	}

	void HashesAnimate(boolean move_in_x, boolean is_next)
	{
		int duration = 300;
		TranslateAnimation in, out;
		int sign = is_next ? -1 : 1;

		if (move_in_x)
		{
			int size = hashes_flipper.getWidth();
			out = new TranslateAnimation(0, sign*size, 0, 0);
			in = new TranslateAnimation((-sign)*size, 0, 0, 0);
		}
		else
		{
			int size = hashes_flipper.getHeight();
			out = new TranslateAnimation(0, 0, 0, sign*size);
			in = new TranslateAnimation(0, 0, (-sign)*size, 0);
		}

		out.setDuration(duration);
		in.setDuration(duration);

		hashes_flipper.setOutAnimation(out);
		hashes_flipper.setInAnimation(in);
		
		use_hashes0 = !use_hashes0;
		LoadHashes();
		if(!use_hashes0)
			hashes_flipper.showNext();
		else
			hashes_flipper.showPrevious();
	}
	
	// Hashes paging
	private static int NumPages(int total_elem, int num_elem_show)
	{
		// Return at least 1 page
		if (num_elem_show > 0)
			return Math.max(1, (total_elem + num_elem_show - 1) / num_elem_show);

		return 1;
	}
	public void goNextPage(boolean move_in_x)
	{
		if ((MainActivity.current_page_hash+1) < NumPages(MainActivity.GetNumMatches(), MainActivity.num_hashes_show))
		{
			MainActivity.current_page_hash++;
			HashesAnimate(move_in_x, true);
		}
		else
			Toast.makeText(MainActivity.my_activity, "No more pages", Toast.LENGTH_SHORT).show();
	}
	public void goPrevPage(boolean move_in_x)
	{
		if (MainActivity.current_page_hash > 0)
		{
			MainActivity.current_page_hash--;
			HashesAnimate(move_in_x, false);
		}
		else
			Toast.makeText(MainActivity.my_activity, "First page", Toast.LENGTH_SHORT).show();
	}

	public void SetPageinfo(int m_current_page_hash, int m_num_hashes_show, int m_num_matches)
	{
		if (pager_text == null)
			return;
		// Show the current page number and total
		int num_pages = NumPages(m_num_matches, m_num_hashes_show);
		pager_text.setText("" + (m_current_page_hash + 1) + " / " + num_pages);
	}

	public void SetProviderSelection(int pos)
	{
		_key_providers.setSelection(pos);
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState)
	{
		View rootView = inflater.inflate(R.layout.main_tab, container, false);
		Spinner _formats = (Spinner) rootView.findViewById(R.id.format_selector);
		_key_providers = (Spinner) rootView.findViewById(R.id.key_provider_selector);
		// Create an ArrayAdapter using the string array and a default spinner layout
		ArrayAdapter<CharSequence> _formats_adapter = new ArrayAdapter<CharSequence>(MainActivity.my_activity, android.R.layout.simple_spinner_item,
				new CharSequence[] { "LM", "NTLM", "DCC" });
		ArrayAdapter<CharSequence> _key_provider_adapter = new ArrayAdapter<CharSequence>(MainActivity.my_activity, android.R.layout.simple_spinner_item,
				new CharSequence[] { "Charset", "Wordlist", "Keyboard", "Phrases", "DB Info", "LM2NT" });
		// Specify the layout to use when the list of choices appears
		_formats_adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		_formats.setOnItemSelectedListener(MainActivity.my_activity);
		_key_provider_adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		_key_providers.setOnItemSelectedListener(MainActivity.my_activity);
		// Apply the adapter to the spinner
		_formats.setAdapter(_formats_adapter);
		_key_providers.setAdapter(_key_provider_adapter);

		_formats.setSelection(MainActivity.format_index);
		_key_providers.setSelection(MainActivity.key_provider_index);

		hashes_flipper = (ViewFlipper) rootView.findViewById(R.id.hashes_flipper);
		hashes0 = (LinearLayout) rootView.findViewById(R.id.list_hashes);
		hashes0.setOnTouchListener(this);
		hashes1 = (LinearLayout) rootView.findViewById(R.id.list_hashes_next);
		hashes1.setOnTouchListener(this);
		mDetector = new GestureDetector(MainActivity.my_activity, new MyGestureListener());

		pager_text = (TextView) rootView.findViewById(R.id.pager_text);

		LoadHashes();

		return rootView;
	}

	@Override
	public boolean onTouch(View v, MotionEvent event)
	{
		this.mDetector.onTouchEvent(event);
		v.onTouchEvent(event);
		return true;
	}

	class MyGestureListener extends GestureDetector.SimpleOnGestureListener
	{
		// private static final String DEBUG_TAG = "Gestures";
		private int SWIPE_MIN_DISTANCE;
		private int SWIPE_VELOCITY_THRESHOLD;
		private int SWIPE_MAX_VELOCITY_THRESHOLD;
		private int SWIPE_MAX_OFF_PATH;

		public MyGestureListener()
		{
			final ViewConfiguration vc = ViewConfiguration.get(MainActivity.my_activity);
			SWIPE_MIN_DISTANCE = vc.getScaledPagingTouchSlop();
			SWIPE_VELOCITY_THRESHOLD = vc.getScaledMinimumFlingVelocity();
			SWIPE_MAX_VELOCITY_THRESHOLD = vc.getScaledMaximumFlingVelocity();
			SWIPE_MAX_OFF_PATH = vc.getScaledTouchSlop();
		}

		@Override
		public boolean onDown(MotionEvent event)
		{
			return true;
		}

		@Override
		public boolean onFling(MotionEvent e1, MotionEvent e2, float velocityX, float velocityY)
		{
			boolean result = false;

			float diffY = e2.getY() - e1.getY();
			float diffX = e2.getX() - e1.getX();
			if (Math.abs(diffX) > Math.abs(diffY))
			{
				if (Math.abs(diffY) > SWIPE_MAX_OFF_PATH)
					return false;

				if (Math.abs(diffX) > SWIPE_MIN_DISTANCE && Math.abs(velocityX) > SWIPE_VELOCITY_THRESHOLD
						&& Math.abs(velocityX) < SWIPE_MAX_VELOCITY_THRESHOLD)
				{
					if (diffX > 0)
					{
						// Log.d(DEBUG_TAG, "Fling Right");
						goPrevPage(true);
					}
					else
					{
						// Log.d(DEBUG_TAG, "Fling Left");
						goNextPage(true);
					}
				}
			}
			else
			{
				if (Math.abs(diffX) > SWIPE_MAX_OFF_PATH)
					return false;

				if (Math.abs(diffY) > SWIPE_MIN_DISTANCE && Math.abs(velocityY) > SWIPE_VELOCITY_THRESHOLD
						&& Math.abs(velocityY) < SWIPE_MAX_VELOCITY_THRESHOLD)
				{
					if (diffY > 0)
					{
						// Log.d(DEBUG_TAG, "Fling Bottom");
						goPrevPage(false);
					}
					else
					{
						// Log.d(DEBUG_TAG, "Fling Top");
						goNextPage(false);
					}
				}
			}

			return result;
		}
	}

}