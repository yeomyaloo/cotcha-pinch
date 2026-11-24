package com.example.bank;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.os.Bundle;
import android.widget.TextView;

import com.example.bank.data.TransactionRepository;

import java.util.List;

public class MainActivity extends Activity {

    private PendingIntent reopen;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        List<String> recent = new TransactionRepository(this).recent("primary");
        TextView list = new TextView(this);
        list.setText(String.join("\n", recent));
        setContentView(list);
        reopen = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
    }
}
