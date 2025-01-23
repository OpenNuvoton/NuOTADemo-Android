package com.nuvoton.otaserver

/**
 * Created by cchsu20 on 2018/5/21.
 */

class ECDHKeyResponse(responseArray: ByteArray) {
    var countChecksum: Long = 0
    val checksum = com.nuvoton.otaserver.DataField("checksum", 0, 2)
    val dataLength = com.nuvoton.otaserver.DataField("dataLength", 2, 1)
    val ecdhMode = com.nuvoton.otaserver.DataField("ecdhMode", 3, 1)
    val status = com.nuvoton.otaserver.DataField("status", 4, 4)
    val encryptedData = com.nuvoton.otaserver.DataField("encryptedData", 8, 56)
    init {
        checksum.setData(responseArray)
        dataLength.setData(responseArray)
        ecdhMode.setData(responseArray)
        status.setData(responseArray)
        encryptedData.setData(responseArray)
    }
}

class AuthKeyResponse(responseArray: ByteArray) {
    var countChecksum: Long = 0
    val checksum = com.nuvoton.otaserver.DataField("checksum", 0, 2)
    val dataLength = com.nuvoton.otaserver.DataField("dataLength", 2, 1)
    val packetId = com.nuvoton.otaserver.DataField("packetId", 3, 1)
    val status = com.nuvoton.otaserver.DataField("status", 4, 4)
    init {
        checksum.setData(responseArray)
        dataLength.setData(responseArray)
        packetId.setData(responseArray)
        status.setData(responseArray)
    }
}

class ConnectResponse(responseArray: ByteArray) {
    var countChecksum: Long = 0
    val checksum = com.nuvoton.otaserver.DataField("checksum", 0, 2)
    val payloadSize = com.nuvoton.otaserver.DataField("payloadSize", 2, 1)
    val packetId = com.nuvoton.otaserver.DataField("packetId", 3, 1)
    val status = com.nuvoton.otaserver.DataField("status", 4, 4)
    val bldVersion = com.nuvoton.otaserver.DataField("bldVersion", 8, 4)
    val sysFwVersion = com.nuvoton.otaserver.DataField("sysFwVersion", 12, 4)
    val appFwVersion = com.nuvoton.otaserver.DataField("appFwVersion", 16, 4)
    val bootStatus = com.nuvoton.otaserver.DataField("bootStatus", 20, 4)
    val reqSysUpdate = com.nuvoton.otaserver.DataField("reqSysUpdate", 24, 2)
    val reqAppUpdate = com.nuvoton.otaserver.DataField("reqAppUpdate", 26, 2)
    var encryptedData = responseArray.copyOfRange(8, 28+12)
    init {
        checksum.setData(responseArray)
        payloadSize.setData(responseArray)
        packetId.setData(responseArray)
        status.setData(responseArray)
    }

    fun setDecryptedData(decryptedData: ByteArray) {
        bldVersion.setDecryptedData(decryptedData)
        sysFwVersion.setDecryptedData(decryptedData)
        appFwVersion.setDecryptedData(decryptedData)
        bootStatus.setDecryptedData(decryptedData)
        reqSysUpdate.setDecryptedData(decryptedData)
        reqAppUpdate.setDecryptedData(decryptedData)
    }
}

class WriteResponse(responseArray: ByteArray) {
    var countChecksum: Long = 0
    val checksum = com.nuvoton.otaserver.DataField("checksum", 0, 2)
    val payloadSize = com.nuvoton.otaserver.DataField("payloadSize", 2, 1)
    val packetId = com.nuvoton.otaserver.DataField("packetId", 3, 1)
    val status = com.nuvoton.otaserver.DataField("status", 4, 4)
    init {
        checksum.setData(responseArray)
        payloadSize.setData(responseArray)
        packetId.setData(responseArray)
        status.setData(responseArray)
    }
}

class DisconnectResponse(responseArray: ByteArray) {
    var countChecksum: Long = 0
    val checksum = com.nuvoton.otaserver.DataField("checksum", 0, 2)
    val payloadSize = com.nuvoton.otaserver.DataField("payloadSize", 2, 1)
    val packetId = com.nuvoton.otaserver.DataField("packetId", 3, 1)
    val status = com.nuvoton.otaserver.DataField("status", 4, 4)
    init {
        checksum.setData(responseArray)
        payloadSize.setData(responseArray)
        packetId.setData(responseArray)
        status.setData(responseArray)
    }
}