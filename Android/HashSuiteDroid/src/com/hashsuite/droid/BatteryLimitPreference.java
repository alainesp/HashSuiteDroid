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

public class BatteryLimitPreference extends DialogPreference
{
    private static final int MIN_VALUE_PERCENT = 5;
    private static final int MAX_VALUE_PERCENT = 90;
    private static final int MIN_VALUE_TEMPERAURE = 25;
    private static final int MAX_VALUE_TEMPERAURE = 70;
    private static final int DEFAULT_VALUE_AGREGATE = 12820;// 50 | 20
 
    private int compact_value;
    private NumberPicker np_percent;
    private NumberPicker np_temperature;
 
    public BatteryLimitPreference(Context context)
    {
        this(context, null);
    }
 
    public BatteryLimitPreference(Context context, AttributeSet attrs)
    {
        super(context, attrs);
 
        // set layout
        setDialogLayoutResource(R.layout.battery_limits);
        setDialogIcon(R.drawable.ic_action_battery);
        setPositiveButtonText("Set");
    }
 
    @Override
    protected void onSetInitialValue(boolean restore, Object defaultValue)
    {
        setValue(restore ? getPersistedInt(DEFAULT_VALUE_AGREGATE) : (Integer) defaultValue);
    }
 
    @Override
    protected Object onGetDefaultValue(TypedArray a, int index)
    {
        return a.getInt(index, DEFAULT_VALUE_AGREGATE);
    }
 
    @Override
    protected void onBindDialogView(View view)
    {
        super.onBindDialogView(view);
 
        np_percent = (NumberPicker) view.findViewById(R.id.np_battery_percent);
        np_percent.setMinValue(MIN_VALUE_PERCENT);
        np_percent.setMaxValue(MAX_VALUE_PERCENT);
        np_percent.setFormatter(new NumberPicker.Formatter()
		{
			@Override
			public String format(int value)
			{
				return ""+value+"%";
			}
		});
        np_percent.setValue(compact_value & 0xff);
        
        np_temperature = (NumberPicker) view.findViewById(R.id.np_battery_temperature);
        np_temperature.setMinValue(MIN_VALUE_TEMPERAURE);
        np_temperature.setMaxValue(MAX_VALUE_TEMPERAURE);
        np_temperature.setFormatter(new NumberPicker.Formatter()
		{
			@Override
			public String format(int value)
			{
				return ""+value+"°C";
			}
		});
        np_temperature.setValue(compact_value >> 8);
    }
 
    public void setValue(int value)
    {
    	// Test each value separetely
    	int value_percent = value & 0xff;
    	int value_temperature = value >> 8;
    	value_percent = Math.min(Math.max(value_percent, MIN_VALUE_PERCENT), MAX_VALUE_PERCENT);
    	value_temperature = Math.min(Math.max(value_temperature, MIN_VALUE_TEMPERAURE), MAX_VALUE_TEMPERAURE);
    	value = value_percent + (value_temperature<<8);
 
        if (value != compact_value)
        {
        	compact_value = value;
            persistInt(value);
            notifyChanged();
            this.setSummary("Stop if Level < " + (compact_value & 0xff) + "% or T > " + (compact_value >> 8) + "°C");
        }
    }
 
    @Override
    protected void onDialogClosed(boolean positiveResult)
    {
        super.onDialogClosed(positiveResult);
 
        // when the user selects "OK", persist the new value
        if (positiveResult)
        {
            int numberPickerValue = np_percent.getValue() + (np_temperature.getValue()<<8);
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
        myState.value = compact_value;
 
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

