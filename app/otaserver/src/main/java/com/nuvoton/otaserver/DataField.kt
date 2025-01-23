package com.nuvoton.otaserver

import com.nuvoton.otaserver.utility.LoggerInstance

/**
 * Created by cchsu20 on 2018/5/21.
 */

class DataField(var name: String,
                var startIndex: Int,
                var length: Int) {
    var dataArray = ByteArray(length)
    var isRemoteLittleEndian = true

    fun putInt(value: Int) {
        dataArray[0] = value.and(0xFF).toByte()
    }

    fun putLong(value: Long) {
        // little endian
        for (i in 0 until length) {
            dataArray[length - i - 1] = value.ushr(i * 8).and(0xFF).toByte()
        }
    }

    fun toInt(): Int {
        return dataArray[0].toInt().and(0xFF)
    }

    fun toLong(): Long {
        val value = if (isRemoteLittleEndian) {
            dataArray[0].toLong().and(0xFF).or(dataArray[1].toLong().shl(8).and(0xFF00))
        } else {
            dataArray[1].toLong().and(0xFF).or(dataArray[0].toLong().shl(8).and(0xFF00))
        }
        LoggerInstance.shared.debugMessage(name, "$name.toLong=$value")
        return value
    }

    override fun toString(): String {
        var string = ""
        for (byte in dataArray) {
            string += String.format("%02X", byte)
        }
        return string
    }

    fun byteOrderSwap(swapUnit: Int) {
        var temp: ByteArray
        var result = ByteArray(0)
        val indexLimit = dataArray.size / swapUnit
        for (i in 0 until indexLimit) {
            temp = dataArray.copyOfRange(i * swapUnit, (i + 1) * swapUnit)
            result += temp.reversedArray()
        }
        dataArray = result
    }

    fun setData(byteArray: ByteArray) {
        var localIndex = 0
        for (index in startIndex until startIndex + length) {
            dataArray[localIndex++] = byteArray[index]
        }
    }

    fun setDecryptedData(byteArray: ByteArray) {
        var localIndex = 0
        for (index in startIndex until startIndex + length) {
             dataArray[localIndex++] = byteArray[index-8]
        }
    }

}