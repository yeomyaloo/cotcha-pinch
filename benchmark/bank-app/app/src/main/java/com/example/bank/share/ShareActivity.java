package com.example.bank.share;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;

public class ShareActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Intent forward = getIntent().getParcelableExtra("forward");
        if (forward != null) {
            startActivity(forward);
        }
        finish();
    }
}
