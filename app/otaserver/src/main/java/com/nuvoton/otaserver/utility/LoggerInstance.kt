package com.nuvoton.otaserver.utility

import android.util.Log
import com.orhanobut.logger.Logger

/**
 * Created by cchsu20 on 2018/4/27.
 */

class LoggerInstance private constructor() {
    var flag = true
    private object Holder { val INSTANCE = LoggerInstance() }
    companion object {
        val shared: LoggerInstance by lazy { Holder.INSTANCE }
    }

    fun debugMessage(tag: String, string: String) {
        if (flag){
            Log.d(tag, string)
        }
    }

    fun infoMesssage(string: String) {
        Logger.i(string)
    }
}