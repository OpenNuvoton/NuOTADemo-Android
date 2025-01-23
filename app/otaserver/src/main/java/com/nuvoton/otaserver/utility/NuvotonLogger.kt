package com.nuvoton.otaserver.utility

import android.content.Context
import android.util.Log

/**
 * Created by cchsu20 on 2018/6/8.
 */
class NuvotonLogger {
    companion object {
        var DEBUG = true
        var context: Context? = null
        fun debugMessage(tag: String, message: String) {
            if (DEBUG) Log.d(tag, message)
        }

        fun infoMessage(tag: String, message: String) {
            if (DEBUG) Log.i(tag, message)
        }

        fun debugMessageInPref(tag: String, message: String) {
            val pref = context?.getSharedPreferences("NuvotonLogger", Context.MODE_PRIVATE)
            pref?.edit()?.putString(tag, message)?.apply()
        }
    }
}