package com.example.bank.data;

import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

import java.util.ArrayList;
import java.util.List;

public class TransactionRepository {

    private final SQLiteDatabase db;

    public TransactionRepository(Context context) {
        db = SQLiteDatabase.openOrCreateDatabase(context.getDatabasePath("bank.db"), null);
    }

    public List<String> recent(String accountId) {
        List<String> titles = new ArrayList<>();
        try (Cursor cursor = db.rawQuery("SELECT title FROM transactions WHERE account_id = ? ORDER BY id DESC LIMIT 20",
                new String[]{accountId})) {
            while (cursor.moveToNext()) {
                titles.add(cursor.getString(0));
            }
        }
        return titles;
    }
}
