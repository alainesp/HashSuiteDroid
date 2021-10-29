// This file is part of Hash Suite password cracker,
// Copyright (c) 2014 by Alain Espinosa. See LICENSE.

package com.hashsuite.droid;

import java.util.ArrayList;

import android.content.Context;
import android.content.Intent;
import android.content.res.TypedArray;
import android.os.Parcel;
import android.os.Parcelable;
import android.preference.DialogPreference;
import android.util.AttributeSet;
import android.view.View;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ArrayAdapter;
import android.widget.ListView;

class WordlistData
{
	public String name;
	public String size;
	public String url;
	public long id;
	
	public WordlistData(int _id)
	{
		id = _id;
	}
	
	public static native WordlistData[] GetWordlists();
	public static native WordlistData[] getWordlists2Download();
	public static native void setWordlistStateDownloading(long id);
	public static native void finishWordlistDownload(long db_id, String path, long file_lenght);
	public static String filelength2string(long length)
	{
		if(length >= 107374182400L)
			return String.format("%.0f GB", length/1073741824.);
		else if(length >= 1073741824)
			return String.format("%.1f GB", length/1073741824.);
		else if(length >= 104857600)
			return String.format("%.0f MB", length/1048576.);
		else if(length >= 1048576)
			return String.format("%.1f MB", length/1048576.);
		else if(length >= 102400)
			return String.format("%.0f KB", length/1024.);
		else if(length >= 1024)
			return String.format("%.1f KB", length/1024.);

		return "" + length + " B";
	}
	
	@Override
	public String toString()
	{
		if(id >= 0 )
			return name + " (" + size + ")";
		
		return "<Add...>";
	}
}

public class WordlistPreference extends DialogPreference implements OnItemClickListener
{
    private int mValue;
    private ArrayList<WordlistData> wordlist;
    ListView wordlist_list;
    
    public static String getWordlistId(int index)
    {
    	WordlistData[] _wordlists = WordlistData.GetWordlists();
    	if(index >= 0 && index < _wordlists.length)
    	{
    		return "" + _wordlists[index].id;
    	}
    	
    	return "";
    }
 
    public WordlistPreference(Context context)
    {
        this(context, null);
    }
 
    public WordlistPreference(Context context, AttributeSet attrs)
    {
        super(context, attrs);
 
        // set layout
        setDialogLayoutResource(R.layout.wordlist_preference);
        setDialogIcon(R.drawable.ic_action_copy);
        setPositiveButtonText("Set");
        
        wordlist = new ArrayList<WordlistData>();
        
        WordlistData[] _wordlists = WordlistData.GetWordlists();
        for (int i = 0; i < _wordlists.length; i++)
        	wordlist.add(_wordlists[i]);
        
        wordlist.add(new WordlistData(-1));
    }
    
    private void setValue(int value)
    {
    	if(value >= 0 && value < wordlist.size())
    	{
    		mValue = value;
    		this.setSummary(wordlist.get(value).toString());
    		persistInt(value);
            notifyChanged();
    	}
    }
 
    @Override
    protected void onSetInitialValue(boolean restore, Object defaultValue)
    {
        setValue(restore ? getPersistedInt(0) : (Integer) defaultValue);
    }
 
    @Override
    protected Object onGetDefaultValue(TypedArray a, int index)
    {
        return a.getInt(index, 0);
    }
 
    @Override
    protected void onBindDialogView(View view)
    {
        super.onBindDialogView(view);
 
        wordlist_list = (ListView)view.findViewById(R.id.list_wordlist);
        wordlist_list.setAdapter(new ArrayAdapter<WordlistData>(MainActivity.my_activity, android.R.layout.simple_list_item_1, wordlist));
        wordlist_list.setChoiceMode(ListView.CHOICE_MODE_SINGLE);
        wordlist_list.setItemChecked(mValue, true);
        wordlist_list.setOnItemClickListener((OnItemClickListener) this);
    }

    @Override
    protected Parcelable onSaveInstanceState()
    {
        // save the instance state so that it will survive screen orientation changes and other events that may temporarily destroy it
        final Parcelable superState = super.onSaveInstanceState();
 
        // set the state's value with the class member that holds current setting value
        final SavedState myState = new SavedState(superState);
        myState.value = mValue;
 
        return myState;
    }
 
    @Override
    protected void onRestoreInstanceState(Parcelable state)
    {
        // check whether we saved the state in onSaveInstanceState()
        if (state == null || !state.getClass().equals(SavedState.class))
        {
            // didn't save the state, so call superclass
            super.onRestoreInstanceState(state);
            return;
        }
 
        // restore the state
        SavedState myState = (SavedState) state;
        setValue(myState.value);
 
        super.onRestoreInstanceState(myState.getSuperState());
    }
 
    private static class SavedState extends BaseSavedState
    {
        int value;
 
        public SavedState(Parcelable superState)
        {
            super(superState);
        }
 
        public SavedState(Parcel source)
        {
            super(source);
            value = source.readInt();
        }
 
        @Override
        public void writeToParcel(Parcel dest, int flags)
        {
            super.writeToParcel(dest, flags);
            dest.writeInt(value);
        }
 
        @SuppressWarnings("unused")
        public static final Parcelable.Creator<SavedState> CREATOR = new Parcelable.Creator<SavedState>()
        {
            @Override
            public SavedState createFromParcel(Parcel in)
            {
                return new SavedState(in);
            }
 
            @Override
            public SavedState[] newArray(int size)
            {
                return new SavedState[size];
            }
        };
    }
    public void addWordlist(WordlistData data){
        int i = 0;
        for (;i < wordlist.size() - 1; i++)
            if (wordlist.get(i).id > data.id)
                break;
        wordlist.add(i, data);

        if (callChangeListener(i)) {
            setValue(i);
        }
    }

	@Override
	public void onItemClick(AdapterView<?> parent, View view, int position, long id)
	{
		this.getDialog().dismiss();
		
		if(position == wordlist.size() - 1) {
            MainActivity.my_activity.wp = this;

            Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            // Define the filter
            intent.setType("*/*");
            String[] mimeTypes = {"text/plain", "application/zip", "application/gzip", "application/x-gtar-compressed", "application/x-bzip2-compressed"};
            intent.putExtra(Intent.EXTRA_MIME_TYPES, mimeTypes);
            intent.putExtra(Intent.EXTRA_TITLE, "Select wordlist (txt, zip, gz, tgz, bz2)");
            MainActivity.my_activity.startActivityForResult(intent, MainActivity.IMPORT_WORDLIST);
        }
		else if (callChangeListener(position))
        {
            setValue(position);
        }
	}
}