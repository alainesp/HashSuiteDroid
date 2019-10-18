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
import android.widget.NumberPicker.OnValueChangeListener;
import android.widget.TextView;

public class RangeNumberPreference extends DialogPreference implements OnValueChangeListener
{
    public static final int DEFAULT_VALUE = 0 | (5 << 16);
    private static final int MIN_VALUE = 0;
    private static final int MAX_VALUE = 27;
 
    private int mMinValue;
    private int mMaxValue;
    private int mValue;
    private NumberPicker np_min;
    private NumberPicker np_max;
    private TextView dialogMessageText;
 
    public RangeNumberPreference(Context context)
    {
        this(context, null);
    }
 
    public RangeNumberPreference(Context context, AttributeSet attrs)
    {
        super(context, attrs);
 
        // get attributes specified in XML
        setMinValue(MIN_VALUE);
        setMaxValue(MAX_VALUE);
 
        // set layout
        setDialogLayoutResource(R.layout.range_number_preference);
        setDialogIcon(null);
        setPositiveButtonText("Set");
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
 
        dialogMessageText = (TextView) view.findViewById(R.id.text_dialog_message);
 
        np_min = (NumberPicker) view.findViewById(R.id.pref_min_number);
        np_min.setMinValue(mMinValue);
        np_min.setMaxValue(mMaxValue);
        np_min.setValue(getBeginValue(mValue));
        
        np_max = (NumberPicker) view.findViewById(R.id.pref_max_number);
        np_max.setMinValue(mMinValue);
        np_max.setMaxValue(mMaxValue);
        np_max.setValue(getEndValue(mValue));
        
        np_min.setOnValueChangedListener(this);
        np_max.setOnValueChangedListener(this);
        
        dialogMessageText.setText("Range spans ["+np_min.getValue()+"-"+np_max.getValue()+"]");
    }
    
    @Override
	public void onValueChange(NumberPicker picker, int oldVal, int newVal)
	{
		if(picker == np_min)
		{
			if(newVal > np_max.getValue())
				np_max.setValue(newVal);
		}
		else if(picker == np_max)
		{
			if(newVal < np_min.getValue())
				np_min.setValue(newVal);
		}
		dialogMessageText.setText("Range spans ["+np_min.getValue()+"-"+np_max.getValue()+"]");
	}
 
	public void setMaxValue(int value)
	{
		mMaxValue = value;
		setValue(mValue);
	}
    public void setMinValue(int value)
    {
    	mMinValue = value;
        setValue(mValue);
    }
 
    public static int getBeginValue(int val)
    {
        return val & 0xffff;
    }
    public static int getEndValue(int val)
    {
        return val >> 16;
    }
    
    private static int mergeInts(int begin, int end)
    {
    	return begin | (end << 16);
    }
 
    public void setValue(int value)
    {
    	int begin = value & 0xffff;
		int end = value >> 16;
		
    	begin = Math.max(Math.min(begin, mMaxValue), mMinValue);
    	end = Math.max(Math.min(end, mMaxValue), mMinValue);
    	
    	value = mergeInts(begin, end);
 
        if (value != mValue)
        {
            mValue = value;
            persistInt(value);
            notifyChanged();
            this.setSummary("Keys length in the range [" + begin + "-" + end + "]");
        }
    }
 
    @Override
    protected void onDialogClosed(boolean positiveResult)
    {
        super.onDialogClosed(positiveResult);
 
        // when the user selects "OK", persist the new value
        if (positiveResult)
        {
            int begin = np_min.getValue();
            int end = np_max.getValue();
            if (callChangeListener(mergeInts(begin, end)))
            {
                setValue(mergeInts(begin, end));
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
        myState.min_value = mMinValue;
        myState.max_value = mMaxValue;
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
        setMaxValue(myState.max_value);
        setMinValue(myState.min_value);
        setValue(myState.value);
 
        super.onRestoreInstanceState(myState.getSuperState());
    }
 
    private static class SavedState extends BaseSavedState
    {
        int value;
        int min_value;
        int max_value;
 
        public SavedState(Parcelable superState)
        {
            super(superState);
        }
 
        public SavedState(Parcel source)
        {
            super(source);
            value = source.readInt();
            min_value = source.readInt();
            max_value = source.readInt();
        }
 
        @Override
        public void writeToParcel(Parcel dest, int flags)
        {
            super.writeToParcel(dest, flags);
            dest.writeInt(value);
            dest.writeInt(min_value);
            dest.writeInt(max_value);
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