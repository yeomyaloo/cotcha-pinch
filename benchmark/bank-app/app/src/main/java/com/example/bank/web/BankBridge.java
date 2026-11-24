package com.example.bank.web;

import android.content.Context;
import android.webkit.JavascriptInterface;

import com.example.bank.auth.TokenStore;

public class BankBridge {

    private final Context context;

    public BankBridge(Context context) {
        this.context = context;
    }

    @JavascriptInterface
    public String getSessionToken() {
        return new TokenStore(context).authToken();
    }

    @JavascriptInterface
    public String appVersion() {
        return "1.4.0";
    }
}
