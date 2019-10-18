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
import android.widget.NumberPicker;
import android.widget.TextView;

public class ThreadsPreference extends DialogPreference
{
    private static int MIN_VALUE = 1;
    private static int MAX_VALUE = 1;
    private static int num_gpus = 0;
    private int mValue;
    private NumberPicker mNumberPicker;
 
    static{
    	num_gpus = GPUInfo.GetGpusInfo().length;
    	MIN_VALUE = num_gpus > 0 ? 0 : 1;
    	MAX_VALUE = Runtime.getRuntime().availableProcessors();
    }
    public static int getDefaultValue()
    {
    	return Math.max(MAX_VALUE, 0);
    }
    
    public ThreadsPreference(Context context)
    {
        this(context, null);
    }
 
    public ThreadsPreference(Context context, AttributeSet attrs)
    {
        super(context, attrs);
 
        // get attributes specified in XML
 
        // set layout
        setDialogLayoutResource(R.layout.number_picker_dialog_text);
        setDialogIcon(R.drawable.ic_action_computer);
        setPositiveButtonText("Set");
        
        setValue(getDefaultValue());
    }
 
    @Override
    protected void onSetInitialValue(boolean restore, Object defaultValue)
    {
        setValue(restore ? getPersistedInt(getDefaultValue()) : getDefaultValue());
    }
 
    @Override
    protected Object onGetDefaultValue(TypedArray a, int index)
    {
    	int value = getDefaultValue();
    	
    	//setValue(value);
    	
    	return value;
    }
 
    @Override
    protected void onBindDialogView(View view)
    {
        super.onBindDialogView(view);
 
        TextView dialogMessageText = (TextView) view.findViewById(R.id.text_dialog_message);
        dialogMessageText.setText(getDialogMessage());
 
        mNumberPicker = (NumberPicker) view.findViewById(R.id.number_picker);
        mNumberPicker.setMinValue(MIN_VALUE);
        mNumberPicker.setMaxValue(MAX_VALUE);
        mNumberPicker.setValue(mValue);
        mNumberPicker.setFormatter(new NumberPicker.Formatter()
		{
			@Override
			public String format(int value)
			{
				if(value == 1)
					return "1 thread";
				else
					return ""+value+" threads";
			}
		});
    }
 
    public int getValue()
    {
        return mValue;
    }
 
    public void setValue(int value)
    {
        value = Math.max(Math.min(value, MAX_VALUE), MIN_VALUE);
 
        if (value != mValue)
        {
            mValue = value;
            persistInt(value);
            notifyChanged();
            if(mValue == 1)
            	this.setSummary("Using " + mValue + " thread of " + MAX_VALUE);
            else
            	this.setSummary("Using " + mValue + " threads of " + MAX_VALUE);
        }
    }
 
    @Override
    protected void onDialogClosed(boolean positiveResult)
    {
        super.onDialogClosed(positiveResult);
 
        // when the user selects "OK", persist the new value
        if (positiveResult)
        {
            int numberPickerValue = mNumberPicker.getValue();
            if (callChangeListener(numberPickerValue))
            {
                setValue(numberPickerValue);
            }
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
