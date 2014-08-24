// This file is part of Hash Suite password cracker,
// Copyright (c) 2014 by Alain Espinosa
//
// Code licensed under GPL version 2

package com.hashsuite.droid;

import android.content.Context;
import android.content.res.TypedArray;
import android.os.Parcel;
import android.os.Parcelable;
import android.preference.DialogPreference;
import android.util.AttributeSet;
import android.view.View;
import android.widget.NumberPicker;

public class NumberPreference extends DialogPreference
{
    private static final int MIN_VALUE = 2;
    public static final int DEFAULT_VALUE = 210;
 
    private int mValue;
    private NumberPicker mNumberPicker;
 
    public NumberPreference(Context context)
    {
        this(context, null);
    }
 
    public NumberPreference(Context context, AttributeSet attrs)
    {
        super(context, attrs);
 
        // set layout
        setDialogLayoutResource(R.layout.number_picker_dialog);
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
 
        mNumberPicker = (NumberPicker) view.findViewById(R.id.number_picker);
        mNumberPicker.setMinValue(MIN_VALUE);
        mNumberPicker.setMaxValue(Integer.MAX_VALUE);
        mNumberPicker.setValue(mValue);
    }
 
    public void setValue(int value)
    {
        value = Math.max(value, MIN_VALUE);
 
        if (value != mValue)
        {
            mValue = value;
            persistInt(value);
            notifyChanged();
            this.setSummary("Using " + mValue + " most used words");
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
}
