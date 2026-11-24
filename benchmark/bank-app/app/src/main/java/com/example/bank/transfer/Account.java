package com.example.bank.transfer;

import android.os.Parcel;
import android.os.Parcelable;

public class Account implements Parcelable {

    private final String number;
    private final String displayName;

    public Account(String number, String displayName) {
        this.number = number;
        this.displayName = displayName;
    }

    public String getNumber() {
        return number;
    }

    public String getDisplayName() {
        return displayName;
    }

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(number);
        dest.writeString(displayName);
    }
}
