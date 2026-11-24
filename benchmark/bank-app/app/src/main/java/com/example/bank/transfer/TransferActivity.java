package com.example.bank.transfer;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public class TransferActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Account account = getIntent().getParcelableExtra("account");
        TextView title = new TextView(this);
        title.setText(account == null ? "" : account.getDisplayName());
        setContentView(title);
    }
}
