package com.example.bank.coupon

import android.content.Context
import android.webkit.WebView

class CouponWebView(context: Context) : WebView(context) {

    init {
        settings.javaScriptEnabled = true
        settings.allowFileAccess = true
        settings.allowUniversalAccessFromFileURLs = true
    }
}
