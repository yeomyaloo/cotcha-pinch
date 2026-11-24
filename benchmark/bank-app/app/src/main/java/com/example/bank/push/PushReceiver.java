package com.example.bank.push;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class PushReceiver extends BroadcastReceiver {

    private static final String TAG = "push";

    @Override
    public void onReceive(Context context, Intent intent) {
        String message = intent.getStringExtra("message");
        Log.d(TAG, "token refresh scheduled");
        PendingIntent open = PendingIntent.getActivity(context, 0, new Intent("com.example.bank.OPEN"),
                PendingIntent.FLAG_MUTABLE);
        Notification notification = new Notification.Builder(context, "push")
                .setContentText(message)
                .setContentIntent(open)
                .build();
        context.getSystemService(NotificationManager.class).notify(1, notification);
    }
}
