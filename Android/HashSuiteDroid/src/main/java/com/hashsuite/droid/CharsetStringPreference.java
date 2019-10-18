// This file is part of Hash Suite password cracker,
// Copyright (c) 2014 by Alain Espinosa. See LICENSE.

package com.hashsuite.droid;

import android.content.Context;
import android.content.res.TypedArray;
import android.os.Parcel;
import android.os.Parcelable;
import android.preference.DialogPreference;
import android.util.AttributeSet;
import android.view.View;
import android.widget.CheckBox;
import android.widget.LinearLayout;

public class CharsetStringPreference extends DialogPreference
{
    private int mValue;
    public static final int DEFAULT_VALUE = 1 | (1<<1) | (1<<2) | (1<<3);
    
    static NameIDData[] charsets;
    CheckBox[] checkbos;
    
    static{
    	charsets = NameIDData.getCharsets();
    }
 
    public CharsetStringPreference(Context context)
    {
        this(context, null);
    }
    
    static void setCharset(int selection)
    {
    	NameIDData.clearCharset();

		for (int i = 0; i < charsets.length; i++)
			if(getCheckedState(selection, i))
				NameIDData.addCharset(charsets[i].id);
    }
 
    public CharsetStringPreference(Context context, AttributeSet attrs)
    {
        super(context, attrs);

        // set layout
        setDialogLayoutResource(R.layout.charset_string);
        setPositiveButtonText("Set");
        setDialogIcon(null);
    }
 
    @Override
    protected void onSetInitialValue(boolean restore, Object defaultValue)
    {
        setValue(restore ? getPersistedInt(DEFAULT_VALUE) : (Integer) defaultValue);
    }
 
    @Override
    protected Object onGetDefaultValue(TypedArray a, int index)
    {
        return a.getInt(index, DEFAULT_VALUE);
    }
 
    @Override
    protected void onBindDialogView(View view)
    {
        super.onBindDialogView(view);
        
        if(checkbos == null)
            checkbos = new CheckBox[charsets.length];
 
        LinearLayout col0 = (LinearLayout) view.findViewById(R.id.charset_col0);
        LinearLayout col1 = (LinearLayout) view.findViewById(R.id.charset_col1);
        
        for (int i = 0; i < charsets.length; i++)
		{
        	checkbos[i] = new CheckBox(getContext());
        	checkbos[i].setText(charsets[i].name);
        	checkbos[i].setChecked(getCheckedState(mValue, i));
        	if(i%2 == 0)
        		col0.addView(checkbos[i]);
        	else
        		col1.addView(checkbos[i]);
		}
    }
    
 
    private static boolean getCheckedState(int value, int set)
    {
    	return ((value >> set) & 1) != 0;
    }
 
    public int getValue()
    {
        return mValue;
    }
 
    public void setValue(int value)
    {
        if (value != mValue && value != 0)
        {
            mValue = value;
            persistInt(value);
            notifyChanged();
            
            boolean need_plus = false;
            StringBuilder summary = new StringBuilder();
            for (int i = 0; i < charsets.length; i++)
            	if(getCheckedState(mValue, i))
            	{
            		if(need_plus) summary.append("+");
    				summary.append(charsets[i].name);
    				need_plus = true;
            	}
            
            	
            this.setSummary(summary);
        }
    }
 
    @Override
    protected void onDialogClosed(boolean positiveResult)
    {
        super.onDialogClosed(positiveResult);
 
        // When the user selects "OK", persist the new value
        if (positiveResult)
        {
        	int value = 0;
        	for (int i = 0; i < charsets.length; i++)
        		if(checkbos[i].isChecked())
        			value |= 1 << i;
        	
            if (value != 0 && callChangeListener(value))
                setValue(value);
        }
    }
 
    @Override
    protected Parcelable onSaveInstanceState()
    {
        // save the instance state so that it will survive screen orientation changes and other events that may temporarily destroy it
        final Parcelable superState = super.onSaveInstanceState();
 
        // set the state's value with the class member that holds current setting value
        final SavedState myState = new SavedState(superState);
        myState.value = getValue();
 
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
}
class NameIDData
{
	public String name;
	public long id;
	
	// Charset
	public static native NameIDData[] getCharsets();
	public static native void clearCharset();
	public static native void addCharset(long db_id);
	
	// Keyboard
	public static native NameIDData[] getKeyboards();
	public static native void setKeyboardLayout(long db_id);
	
	@Override
	public String toString()
	{
		return name;
	}
}
