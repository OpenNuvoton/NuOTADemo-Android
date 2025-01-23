package com.nuvoton.otaserver

import com.nuvoton.otaserver.utility.LoggerInstance

/**
 * Created by cchsu20 on 2018/4/25.
 */

enum class ECDHMode(val mode: Int, val reqLen: Int, val rspLen: Int) {
    ECDH_CAL_START(0, 48, 0),
    ECDH_CAL_CONTI(1, 48, 0),
    ECDH_CAL_END(2, 32, 0),
    ECDH_SEND_START(3, 0, 48),
    ECDH_SEND_CONTI(4, 0, 48),
    ECDH_SEND_END(5, 0, 32);

    companion object {
        fun getMode(value: Int) : ECDHMode {
            when(value){
                0 -> return ECDH_CAL_START
                1 -> return ECDH_CAL_CONTI
                2 -> return ECDH_CAL_END
                3 -> return ECDH_SEND_START
                4 -> return ECDH_SEND_CONTI
                else -> return ECDH_SEND_END
            }
        }
    }

    override fun toString(): String {
        return "mode: ${this.name}, reqLen: $reqLen, rspLen: $rspLen"
    }
}

abstract class OTAProtocolField {
    abstract var TAG: String
    val crcStartIndex = 2
    abstract var crcEndIndex: Int
    var checkSum: Long = 0
    val REQ_PAYLOAD_SIZE = 16
    val RSP_PAYLOAD_SIZE = 20
    val SYSTEM_FW_SIZE = 0x8000
    val APP_FW_SIZE = 0x4000
    val PACKET_LENGTH = 64
    var packet: ByteArray = ByteArray(PACKET_LENGTH)

    abstract fun encodeData() : Boolean
    abstract fun decodeData(data: ByteArray)

    fun countCRCValue(bh: Byte, bl: Byte): Long {
        val lh = bh.toLong() and 0xFF
        val ll = bl.toLong() and 0xFF
        return (lh.shl(8) or ll) and 0xFFFF
    }
}

class CMD_ECDH_KEY_REQ_T : OTAProtocolField() {
    override var TAG = "CMD_ECDH_KEY_REQ_T"
    override var crcEndIndex: Int = 55
    val dataSize = 48
    var cmdId: Int = 0xD0
    var ecdhMode: ECDHMode = ECDHMode.ECDH_CAL_START
    set(mode) {
        if (mode == ECDHMode.ECDH_CAL_END) crcEndIndex = 39
    }
    var encryptedData: ByteArray = ByteArray(dataSize)

    override fun encodeData(): Boolean {
        var index = 0
        val start = 0
//        packet[index++] = (checkSum.ushr(8) and 0xFF).toByte()
//        packet[index++] = (checkSum and 0xFF).toByte()
        index+=2
        packet[index++] = (cmdId and 0xFF).toByte()
        packet[index++] = (ecdhMode.ordinal and 0xFF).toByte()
        packet[index++] = 0
        packet[index++] = 0
        packet[index++] = 0
        packet[index++] = (ecdhMode.reqLen and 0xFF).toByte()
        System.arraycopy(encryptedData, start, packet, index, ecdhMode.reqLen)
        index+=ecdhMode.reqLen
        LoggerInstance.shared.debugMessage(TAG, "index == $PACKET_LENGTH")
        return true
    }

    override fun decodeData(data: ByteArray) {
        var index = 0
        val start = 0
        checkSum = countCRCValue(data[index], data[index+1])
        index+=2
        cmdId = data[index++].toInt()
        ecdhMode = ECDHMode.getMode(data[index++].toInt())
        index+=3
        index++ // Data reqLen is already defined with ECDHMode
        System.arraycopy(data, start, encryptedData, index, ecdhMode.reqLen)
    }

    override fun toString(): String {
        val string = "CMD_ECDH_KEY_REQ_T: checkSUum=$checkSum, cmdId=$cmdId, ecdhMode=${ecdhMode.toString()}"
        return string
    }
}

class CMD_ECDH_KEY_RSP_T: OTAProtocolField() {
    override var TAG = "CMD_ECDH_KEY_RSP_T"
    override var crcEndIndex: Int = 7
    val STS_CMD_OK = 0
    val ERR_CMD_KEY_EXCHANGE = 0x72

    var encryptedData = ByteArray(PACKET_LENGTH)
    var dataLength = 0
    var ecdhMode = ECDHMode.ECDH_SEND_START
    var status = STS_CMD_OK

    override fun encodeData(): Boolean {
        var index = 0
        val start = 0
        packet[index++] = (checkSum.ushr(8) and 0xFF).toByte()
        packet[index++] = (checkSum and 0xFF).toByte()
        packet[index++] = (ecdhMode.ordinal and 0xFF).toByte()
        packet[index++] = 0
        packet[index++] = 0
        packet[index++] = 0
        packet[index++] = (ecdhMode.rspLen and 0xFF).toByte()
        System.arraycopy(encryptedData, start, packet, index, ecdhMode.rspLen)
        index+=ecdhMode.rspLen
        if (index == PACKET_LENGTH){
            return true
        }
        return false
    }

    override fun decodeData(data: ByteArray) {
        System.arraycopy(data, 0, packet, 0, PACKET_LENGTH)
        var index = 0
        val start = 0
        checkSum = countCRCValue(data[index], data[index+1])
        index+=2
        dataLength = data[index++].toInt()
        ecdhMode = ECDHMode.getMode(data[index++].toInt())
        status = data[index++].toInt()
        index+=3
        System.arraycopy(data, index, encryptedData, start, dataLength)
        index+=dataLength
        val string = if (status == ERR_CMD_KEY_EXCHANGE) "ERR_CMD_KEY_EXCHANGE=$status" else "STS_CMD_OK"
        LoggerInstance.shared.debugMessage(TAG+":decodeData", "status: $string")
        crcEndIndex = when(ecdhMode) {
            ECDHMode.ECDH_SEND_START -> 55
            ECDHMode.ECDH_SEND_CONTI -> 55
            ECDHMode.ECDH_SEND_END -> 39
            else -> 7
        }
    }

    override fun toString(): String {
        val string = "CMD_ECDH_KEY_RSP_T: checkSum=$checkSum, ecdhMode=${ecdhMode.toString()}"
        return string
    }
}

class Version(){
    var string: String = "1.0.0.1"
    set(value) {
        val split = value.split('.')
        var temp: Long = 0
        var count = 24
        for (s in split){
            temp = temp or s.toLong().shl(count)
            byte[3-(count/8)] = s.toByte()
            count -= 8
        }
    }

    var byte: ByteArray = byteArrayOf("1".toByte(), "0".toByte(), "0".toByte(), "1".toByte())
    set(value) {
        var temp: String = ""
        for (b in value){
            if (temp != ""){
                temp = "$string.${b.toString()}"
            }
            temp = b.toString()
        }
    }

}

class OTA_CONNECT_REQ_T: OTAProtocolField() {
    override var TAG = "OTA_CONNECT_REQ_T"
    override var crcEndIndex: Int = 23
    var cmdId = 0x80
    var packetId = 0
    val payloadSize: Int = REQ_PAYLOAD_SIZE
    var sysFwVer: Version = Version()
    val sysFwSize: Int = SYSTEM_FW_SIZE
    var appFwVer: Version = Version()
    val appFwSize: Int = APP_FW_SIZE

    override fun encodeData(): Boolean {
        var index = 0
        packet[index++] = (checkSum.ushr(8) and 0xFF).toByte()
        packet[index++] = (checkSum and 0xFF).toByte()
        packet[index++] = (packetId and 0xFF).toByte()

        index+=3
        packet[index++] = (payloadSize and 0xFF).toByte()

        for (ver in sysFwVer.byte){
            packet[index++] = ver
        }

        packet[index++] = (sysFwSize.ushr(8) and 0xFF).toByte()
        packet[index++] = (sysFwSize and 0xFF).toByte()

        for (ver in appFwVer.byte){
            packet[index++] = ver
        }

        packet[index++] = (appFwSize.ushr(8) and 0xFF).toByte()
        packet[index++] = (appFwSize and 0xFF).toByte()

        if (index == PACKET_LENGTH - 39 - 2){
            LoggerInstance.shared.debugMessage(TAG, "index == $PACKET_LENGTH - 39")
            return true
        }
        LoggerInstance.shared.debugMessage(TAG, "index == $PACKET_LENGTH - 39, but $index, return false")
        return false
    }

    override fun decodeData(data: ByteArray) {
        var index = 0
        val start = 0
        checkSum = countCRCValue(data[index+1], data[index])

        index+=2
        cmdId = data[index++].toInt()
        packetId = data[index++].toInt()
        index+=3
        var tempSize = data[index++].toInt()
        if (tempSize == payloadSize){
            //log sizes are equal
        }

        System.arraycopy(data, index, sysFwVer.byte, start, sysFwVer.byte.size)

        index+=4

        index+=3
        tempSize = data[index++].toInt()
        if (tempSize == sysFwSize){
            //log sizes are equal
        }

        System.arraycopy(data, index, appFwVer.byte, start, appFwVer.byte.size)
        index+=4

        if (index == PACKET_LENGTH - 39 - 2){
            LoggerInstance.shared.debugMessage(TAG, "index == $PACKET_LENGTH - 39")
        }else {
            LoggerInstance.shared.debugMessage(TAG, "index != $PACKET_LENGTH - 39, but $index")
        }
    }

    override fun toString(): String {
        val string = "CMD_ECDH_KEY_RSP_T: checkSum=$checkSum, cmdId=$cmdId, " +
                "payloadSize=$payloadSize, sysFwVer=${sysFwVer?.string}, appFwVer=${appFwVer?.string}}"
        return string
    }
}

class OTA_CONNECT_RSP_T: OTAProtocolField() {
    override var TAG = "OTA_CONNECT_RSP_T"
    override var crcEndIndex: Int = 27
    /*
    constant
     */
    val STS_OK = 0
    val ERR_CMD_CHECKSUM = 0x7D

    /*
    variables
     */
    val payloadSize: Int = RSP_PAYLOAD_SIZE
    var packetId = 0
    var status = STS_OK
    //bootloader is not used now
    var sysFwVer = Version()
    var appFwVer = Version()
    //boot status is not used now
    var reqSysUpdateResult: Int = 0
    var reqAppUpdateResult: Int = 0

    override fun toString(): String {
        return "CMD_ECDH_KEY_RSP_T: checkSum=$checkSum, " +
                "payloadSize=$payloadSize, " +
                "packetId=$packetId, " +
                "status=$status, " +
                "sysFwVer=${sysFwVer.string}, " +
                "appFwVer=${appFwVer.string}, " +
                "reqSysUpdateResult=$reqSysUpdateResult, " +
                "reqAppUpdateResult=$reqAppUpdateResult"
    }

    override fun encodeData(): Boolean {
        // response packet is sent from client
        return true
    }

    override fun decodeData(data: ByteArray) {
        var index = 0
        val start = 0
        checkSum = countCRCValue(data[index+1], data[index])

        index+=2
        val tempSize = data[index++].toInt()
        if (tempSize == payloadSize){
            //log sizes are equal
        }

        packetId = data[index++].toInt()
        index+=3
        status = data[index++].toInt()

        if (status == STS_OK){
            //log here
        }else {
            //log here
        }

        //bootloader version is not used now
        index+=4

        System.arraycopy(data, index, sysFwVer.byte, start, sysFwVer.byte.size)
        index+=4

        System.arraycopy(data, index, appFwVer, start, appFwVer.byte.size)
        index+=4

        //boot status is not used now
        index+=4

        reqSysUpdateResult = data[index].toInt().shl(8) or data[index+1].toInt()
        index+=2

        reqAppUpdateResult = data[index].toInt().shl(8) or data[index+1].toInt()
        index+=2

        if (index == PACKET_LENGTH - 35 - 2){
            LoggerInstance.shared.debugMessage(TAG, "index == $PACKET_LENGTH - 35")
        }else {
            LoggerInstance.shared.debugMessage(TAG, "index != $PACKET_LENGTH - 35, but $index")
        }

    }
}

class OTA_WRITE_REQ_T: OTAProtocolField() {
    override var TAG = "OTA_WRITE_REQ_T"
    override var crcEndIndex: Int = 51
    val REQ_WRITE_DATA_SIZE = 44
    var cmdId = 0x83
    var packetId = 0
    val payloadSize: Int = 44
    var data: ByteArray = ByteArray(REQ_WRITE_DATA_SIZE+4)

    override fun toString(): String {
        return "checksum=$checkSum, cmdId=$cmdId, packetId=$packetId"
    }

    override fun encodeData(): Boolean {
        var index = 0
        val start = 0
        packet[index++] = (checkSum.ushr(8) and 0xFF).toByte()
        packet[index++] = (checkSum and 0xFF).toByte()
        packet[index++] = (cmdId and 0xFF).toByte()
        packet[index++] = (packetId and 0xFF).toByte()

        index+=3
        packet[index++] = (payloadSize and 0xFF).toByte()

        System.arraycopy(data, start, packet, index, REQ_WRITE_DATA_SIZE)
        index+=REQ_WRITE_DATA_SIZE

        if (index == PACKET_LENGTH - 9 - 2){
            LoggerInstance.shared.debugMessage(TAG, "index == $PACKET_LENGTH - 9")
            return true
        }
        LoggerInstance.shared.debugMessage(TAG, "index == $PACKET_LENGTH - 9")
        return false
    }

    override fun decodeData(data: ByteArray) {
        //No need to decode request packet
    }
}

class OTA_WRITE_RSP_T: OTAProtocolField() {
    override var TAG = "OTA_WRITE_RSP_T"
    override var crcEndIndex: Int = 7
    var payloadSize = 0
    var packetId = 0
    var status = 0

    override fun toString(): String {
        return "OTA_WRITE_RSP_T: checksum=$checkSum, payloadSize=$payloadSize, packetId=$packetId, status=$status"
    }

    override fun encodeData(): Boolean {
        //No need to encode response packet
        return true
    }

    override fun decodeData(data: ByteArray) {
        var index = 0
        checkSum = countCRCValue(data[index+1], data[index])

        index+=2
        payloadSize = data[index++].toInt()
        packetId = data[index++].toInt()
        index+=3
        status = data[index++].toInt()
        if (index == PACKET_LENGTH - 55 - 2) {
            LoggerInstance.shared.debugMessage(TAG, "index == $PACKET_LENGTH - 55")
        }else {
            LoggerInstance.shared.debugMessage(TAG, "index == $PACKET_LENGTH - 55, but $index")
        }
    }
}

class OTA_DISCONNECT_REQ_T: OTAProtocolField() {
    override var TAG = "OTA_DISCONNECT_REQ_T"
    override var crcEndIndex: Int = 11
    val REQ_DISCONNECT_DATA_SIZE = 4
    var cmdId = 0x8E
    var packetId = 0
    val payloadSize: Int = REQ_DISCONNECT_DATA_SIZE
    var isUpdateDoneFlag = 0

    override fun toString(): String {
        return "OTA_DISCONNECT_REQ_T: checksum=$checkSum, cmdId=$cmdId, packetId=$packetId, isUpdateDoneFlag=$isUpdateDoneFlag"
    }

    override fun encodeData(): Boolean {
        var index = 0
        packet[index++] = (checkSum.ushr(8) and 0xFF).toByte()
        packet[index++] = (checkSum and 0xFF).toByte()
        packet[index++] = (cmdId and 0xFF).toByte()
        packet[index++] = (packetId and 0xFF).toByte()

        index+=3
        packet[index++] = (payloadSize and 0xFF).toByte()

        index+=3
        packet[index++] = (isUpdateDoneFlag and 0xFF).toByte()

        if (index == PACKET_LENGTH - 51 - 2){
            return true
        }
        return false
    }

    override fun decodeData(data: ByteArray) {
        //No need to decode request packet
    }
}

class OTA_DISCONNECT_RSP_T: OTAProtocolField() {
    override var TAG = "OTA_DISCONNECT_RSP_T"
    override var crcEndIndex: Int = 7
    var payloadSize = 0
    var packetId = 0
    var status = 0

    override fun toString(): String {
        return "OTA_DISCONNECT_RSP_T: checksum=$checkSum, payloadSize=$payloadSize, packetId=$packetId, status=$status"
    }

    override fun encodeData(): Boolean {
        //No need to encode response packet
        return true
    }

    override fun decodeData(data: ByteArray) {
        var index = 0
        checkSum = countCRCValue(data[index+1], data[index])

        index+=2
        payloadSize = data[index++].toInt()
        packetId = data[index++].toInt()
        index+=3
        status = data[index++].toInt()
        if (index == PACKET_LENGTH - 55 - 2) {
            LoggerInstance.shared.debugMessage(TAG, "index == $PACKET_LENGTH - 55")
        }else {
            LoggerInstance.shared.debugMessage(TAG, "index == $PACKET_LENGTH - 55, but $index")
        }
    }
}

class CMD_AUTH_KEY_REQ_T: OTAProtocolField() {
    override var TAG = "CMD_AUTH_KEY_REQ_T"
    override var crcEndIndex: Int = 39
    val REQ_AUTH_DATA_SIZE = 32
    var cmdId = 0x87
    var packetId = 0
    val payloadSize: Int = REQ_AUTH_DATA_SIZE
    val hash = ByteArray(payloadSize)

    override fun toString(): String {
        return "CMD_AUTH_KEY_REQ_T: checksum=$checkSum, cmdId=$cmdId, packetId=$packetId"
    }

    override fun encodeData(): Boolean {
        var index = 0
        packet[index++] = (checkSum.ushr(8) and 0xFF).toByte()
        packet[index++] = (checkSum and 0xFF).toByte()
        packet[index++] = (cmdId and 0xFF).toByte()
        packet[index++] = (packetId and 0xFF).toByte()

        index+=3
        System.arraycopy(hash, 0, packet, index, payloadSize)
        index+=payloadSize

        if (index == PACKET_LENGTH - 15 - 2){
            return true
        }
        return false
    }

    override fun decodeData(data: ByteArray) {
        //No need to decode request packet
    }
}

class CMD_AUTH_KEY_RSP_T: OTAProtocolField() {
    override var TAG = "CMD_AUTH_KEY_RSP_T"
    override var crcEndIndex: Int = 7
    var payloadSize = 0
    var packetId = 0
    var status = 0

    override fun toString(): String {
        return "CMD_AUTH_KEY_RSP_T: checksum=$checkSum, payloadSize=$payloadSize, packetId=$packetId, status=$status"
    }

    override fun encodeData(): Boolean {
        //No need to encode response packet
        return true
    }

    override fun decodeData(data: ByteArray) {
        var index = 0
        checkSum = countCRCValue(data[index+1], data[index])

        index+=2
        payloadSize = data[index++].toInt()
        packetId = data[index++].toInt()
        index+=3
        status = data[index++].toInt()
        if (index == PACKET_LENGTH - 55 - 2) {
            LoggerInstance.shared.debugMessage(TAG, "index == $PACKET_LENGTH - 55 - 2")
        }else {
            LoggerInstance.shared.debugMessage(TAG, "index == $PACKET_LENGTH - 55 - 2, but $index")
        }
    }
}