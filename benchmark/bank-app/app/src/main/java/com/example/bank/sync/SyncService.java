package com.example.bank.sync;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

import com.example.bank.net.ApiClient;

import java.security.GeneralSecurityException;

public class SyncService extends Service {

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        try {
            new ApiClient().create();
        } catch (GeneralSecurityException e) {
            stopSelf();
        }
        return START_NOT_STICKY;
    }
}
