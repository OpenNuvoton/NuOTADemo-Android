package com.nuvoton.otaserver.utility

import android.content.Context
import android.content.SharedPreferences

/**
 * Created by cchsu20 on 2018/5/30.
 */
class LocalSetting {
    private object Holder { val INSTANCE = LocalSetting() }
    companion object {
        val shared: LocalSetting by lazy { LocalSetting.Holder.INSTANCE }
    }
    var context: Context? = null
    var preferences: SharedPreferences? = null

    fun getSetting(name: String): String {
        preferences = context?.getSharedPreferences("ota", Context.MODE_PRIVATE)
        return preferences?.getString(name, "string not found") ?: "context is null"
    }

    fun putSetting(name: String, content: String) {
        preferences = context?.getSharedPreferences("ota", Context.MODE_PRIVATE)
        preferences?.edit()?.putString(name, content)?.apply()
    }
}