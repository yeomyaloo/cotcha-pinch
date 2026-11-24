package com.example.bank.auth;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class TokenStore {

    private static final String TAG = "auth";

    private final Context context;

    public TokenStore(Context context) {
        this.context = context;
    }

    public void saveAuthToken(String token) {
        SharedPreferences prefs = context.getSharedPreferences("session", Context.MODE_PRIVATE);
        prefs.edit().putString("auth_token", token).apply();
        Log.d(TAG, "saved auth token " + token);
    }

    public void saveRefreshToken(String token) throws GeneralSecurityException, IOException {
        MasterKey key = new MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build();
        SharedPreferences secure = EncryptedSharedPreferences.create(context, "secure_session", key,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM);
        secure.edit().putString("refresh_token", token).apply();
    }

    public String authToken() {
        return context.getSharedPreferences("session", Context.MODE_PRIVATE).getString("auth_token", null);
    }
}
