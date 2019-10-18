// This file is part of Hash Suite password cracker,
// Copyright (c) 2014 by Alain Espinosa. See LICENSE.

package com.hashsuite.droid;

import java.util.ArrayList;
import android.content.Context;
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


public class KeyboardLayoutPreference extends DialogPreference implements OnItemClickListener
{
    private int mValue;
    private ArrayList<NameIDData> keyboards;
    ListView keyboards_list;
    static NameIDData[] kb_nameid;
    
    public static void setKeyboard(int index)
    {
    	if(index >= 0 && index < kb_nameid.length)
    		NameIDData.setKeyboardLayout(kb_nameid[index].id);
    }
 
    public KeyboardLayoutPreference(Context context)
    {
        this(context, null);
    }
 
    public KeyboardLayoutPreference(Context context, AttributeSet attrs)
    {
        super(context, attrs);
 
        // set layout
        setDialogLayoutResource(R.layout.wordlist_preference);
        setDialogIcon(R.drawable.ic_action_keyboard);
        setPositiveButtonText("");
        
        keyboards = new ArrayList<NameIDData>();
        
        kb_nameid = NameIDData.getKeyboards();
        for (int i = 0; i < kb_nameid.length; i++)
        	keyboards.add(kb_nameid[i]);
    }
    
    private void setValue(int value)
    {
    	if(value >=0 && value < keyboards.size())
    	{
    		mValue = value;
    		this.setSummary(keyboards.get(value).name);
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
 
        keyboards_list = (ListView)view.findViewById(R.id.list_wordlist);
        keyboards_list.setAdapter(new ArrayAdapter<NameIDData>(MainActivity.my_activity, android.R.layout.simple_list_item_1, keyboards));
        keyboards_list.setChoiceMode(ListView.CHOICE_MODE_SINGLE);
        keyboards_list.setItemChecked(mValue, true);
        keyboards_list.setOnItemClickListener((OnItemClickListener) this);
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

	@Override
	public void onItemClick(AdapterView<?> parent, View view, int position, long id)
	{
		this.getDialog().dismiss();
		
		if (callChangeListener(position))
        {
            setValue(position);
        }
	}
}
