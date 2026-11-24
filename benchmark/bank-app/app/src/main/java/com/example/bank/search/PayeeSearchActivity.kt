package com.example.bank.search

import android.app.Activity
import android.database.sqlite.SQLiteDatabase
import android.os.Bundle
import android.widget.TextView

class PayeeSearchActivity : Activity() {

    private lateinit var db: SQLiteDatabase

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        db = SQLiteDatabase.openOrCreateDatabase(getDatabasePath("bank.db"), null)
        val query = intent.data?.getQueryParameter("q").orEmpty()
        val view = TextView(this)
        view.text = byName(query).joinToString("\n")
        setContentView(view)
    }

    private fun byName(name: String): List<String> {
        val cursor = db.rawQuery("SELECT name FROM payees WHERE name LIKE '%$name%'", null)
        return cursor.use { c -> generateSequence { if (c.moveToNext()) c.getString(0) else null }.toList() }
    }

    fun byId(id: Long): String? {
        val cursor = db.rawQuery("SELECT name FROM payees WHERE id = ?", arrayOf(id.toString()))
        return cursor.use { c -> if (c.moveToFirst()) c.getString(0) else null }
    }
}
