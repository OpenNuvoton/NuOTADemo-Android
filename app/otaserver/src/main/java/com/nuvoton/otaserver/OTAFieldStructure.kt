package com.nuvoton.otaserver

import com.nuvoton.otaserver.crccalc.Crc16
import com.nuvoton.otaserver.utility.NuvotonLogger
import com.nuvoton.otaserver.utility.OTACommand
import kotlin.experimental.and

/**
 * Created by cchsu20 on 2018/7/9.
 */

class CountCrc {
    companion object {
        //        private val crcParameter = AlgoParams("CRC16-Custom", 16, 0x8005, 0xFFFF, false, false, 0x0000, 0x0000)
        val crc16 = com.nuvoton.otaserver.crccalc.CrcCalculator(Crc16.Crc16CcittFalse)
        //        private val crcParameter = AlgoParams("CRC16-Custom", 16, 0x8005, 0xFFFF, false, false, 0x0000, 0x0000)
        val crc32 = com.nuvoton.otaserver.crccalc.CrcCalculator(com.nuvoton.otaserver.crccalc.Crc32.Crc32)
    }
}

class OTAField(val otaCommand: OTACommand) {
    val TAG = "OTAField"
    //Byte 0..1, uint16_t
    var crc16: UInt16? = null

    //Byte 2..3, uint16_t
    var cmdId: UInt16? = null

    //Byte 4..5, uint16_t
    var packetId: UInt16? = null

    //Byte 6..7, uint16_t
    var validLength: UInt16? = null

    //Byte 8..55, customize
    var cipherData: ArrayList<UnsignedInt8>? = null

    //Byte 56..59, uint32_t
    var crc32: UInt32? = null

    //Byte 60..63, uint32_t
    var reserved: UInt32? = null

    init {
        crc16 = UInt16(0L)
        cmdId = UInt16(otaCommand.raw)
        packetId = UInt16(0L)
        validLength = UInt16(otaCommand.reqLen.toLong())
        cipherData = ArrayList()
        for (i in 0 until 48) cipherData!!.add(UnsignedInt8(0))
        crc32 = UInt32(0L)
        reserved = UInt32(0L)
    }
    fun countCrc16(isVerify: Boolean = false): Boolean {
        val dataList = ArrayList<UnsignedInt8>()
        dataList.addAll(cmdId!!.getUInt8List())
        dataList.addAll(packetId!!.getUInt8List())
        dataList.addAll(validLength!!.getUInt8List())
        dataList.addAll(cipherData!!)
        var crc16Data = ByteArray(0)
        dataList.forEach { it -> crc16Data += it.byte }
        val crc16Result = CountCrc.crc16.Calc(crc16Data, 0, crc16Data.size)
        NuvotonLogger.debugMessage(TAG, "16=${com.nuvoton.otaserver.EncryptHelper.byteArrayToString(crc16Data)}")
        NuvotonLogger.debugMessage(TAG, "crc16=$crc16Result")
        val result = UInt16(crc16Result)
        if (!isVerify) this.crc16 = result
        return this.crc16!!.number == result.number
    }

    fun countCrc32(isVerify: Boolean = false): Boolean {
        val dataList = ArrayList<UnsignedInt8>()
        dataList.addAll(crc16!!.getUInt8List())
        dataList.addAll(cmdId!!.getUInt8List())
        dataList.addAll(packetId!!.getUInt8List())
        dataList.addAll(validLength!!.getUInt8List())
        dataList.addAll(cipherData!!)
        var crc32Data = ByteArray(0)
        dataList.forEach { it -> crc32Data += it.byte }
        NuvotonLogger.debugMessage(TAG, "32=${com.nuvoton.otaserver.EncryptHelper.byteArrayToString(crc32Data)}")
        val crc32Result = CountCrc.crc32.Calc(crc32Data, 0, crc32Data.size)
        val result = UInt32(crc32Result)
        if (!isVerify) this.crc32 = result
        return this.crc32!!.number == result.number
    }

    fun prepareData(isLittle: Boolean = true): ByteArray {
        val dataList = ArrayList<UnsignedInt8>()
        dataList.addAll(crc16!!.getUInt8List())
        dataList.addAll(cmdId!!.getUInt8List())
        dataList.addAll(packetId!!.getUInt8List())
        dataList.addAll(validLength!!.getUInt8List())
        dataList.addAll(cipherData!!)
        dataList.addAll(crc32!!.getUInt8List())
        dataList.addAll(reserved!!.getUInt8List())
        var commandData = ByteArray(0)
        dataList.forEach { it -> commandData += it.byte }
        return commandData
    }

    fun cipheringData(key: ByteArray, iv: ByteArray, mode: Int) {
        var before = ByteArray(0)
        cipherData!!.forEach { it -> before += it.byte }
        val result = com.nuvoton.otaserver.EncryptHelper.shared.aes256DoingData(before, key, iv, mode)
        result.forEachIndexed { index, byte -> cipherData!![index] = UnsignedInt8(byte) }
    }

    override fun toString(): String {
        return "otaCommand=${otaCommand.name} \n" +
                "crc16=${crc16!!.number}, ${printUnsignedRaw(crc16!!)}\n" +
                "cmdId=${cmdId!!.number}, ${printUnsignedRaw(cmdId!!)}\n" +
                "packetId=${packetId!!.number}, ${printUnsignedRaw(packetId!!)}\n" +
                "validLength=${validLength!!.number}, ${printUnsignedRaw(validLength!!)}\n" +
                "crc32=${crc32!!.number}, ${printUnsignedRaw(crc32!!)}"
    }

    fun printUnsignedRaw(uIntPrototype: UIntPrototype) : String {
        var string = ""
        val temp: Short = 0xFF
        uIntPrototype.getUInt8List().forEach { it ->
            string += it.byte.toShort().and(temp).toString(16)
        }
        return string
    }

    fun putResponse(byteArray: ByteArray) {
        crc16 = UInt16(byteArray.copyOfRange(0, 2))
        cmdId = UInt16(byteArray.copyOfRange(2, 4))
        packetId = UInt16(byteArray.copyOfRange(4, 6))
        validLength = UInt16(byteArray.copyOfRange(6, 8))
        byteArray.copyOfRange(8, 56).forEachIndexed { i, it ->
            cipherData!![i] = UnsignedInt8(it)
        }
        crc32 = UInt32(byteArray.copyOfRange(56, 60))
    }
}