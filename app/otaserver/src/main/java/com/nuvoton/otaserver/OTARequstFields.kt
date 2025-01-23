package com.nuvoton.otaserver

/**
 * Created by cchsu20 on 2018/5/21.
 */

class ECDHKeyRequest {
    val checksum = com.nuvoton.otaserver.DataField("checksum", 0, 2)
    val commandId = com.nuvoton.otaserver.DataField("commandId", 2, 1)
    val ecdhMode = com.nuvoton.otaserver.DataField("ecdhMode", 3, 1)
    val dataLength = com.nuvoton.otaserver.DataField("dataLength", 4, 4)
    val encryptedData = com.nuvoton.otaserver.DataField("encryptedData", 8, 56)

    fun getRequestArray(): ByteArray {
        return checksum.dataArray + commandId.dataArray + ecdhMode.dataArray + dataLength.dataArray + encryptedData.dataArray
    }
}

class AuthKeyRequest {
    val checksum = com.nuvoton.otaserver.DataField("checksum", 0, 2)
    val commandId = com.nuvoton.otaserver.DataField("commandId", 2, 1)
    val packetId = com.nuvoton.otaserver.DataField("packetId", 3, 1)
    val dataLength = com.nuvoton.otaserver.DataField("dataLength", 4, 4)
    val keyHash = com.nuvoton.otaserver.DataField("keyHash", 8, 32)
    val redundant = ByteArray(24)

    fun getRequestArray(): ByteArray {
        return checksum.dataArray + commandId.dataArray + packetId.dataArray + dataLength.dataArray + keyHash.dataArray + redundant
    }
}

class ConnectRequest {
    val checksum = com.nuvoton.otaserver.DataField("checksum", 0, 2)
    val commandId = com.nuvoton.otaserver.DataField("commandId", 2, 1)
    val packetId = com.nuvoton.otaserver.DataField("packetId", 3, 1)
    val payloadSize = com.nuvoton.otaserver.DataField("payloadSize", 4, 4)
    val sysFwVersion = com.nuvoton.otaserver.DataField("sysFwVersion", 8, 4)
    val sysFwSize = com.nuvoton.otaserver.DataField("sysFwSize", 12, 4)
    val appFwVersion = com.nuvoton.otaserver.DataField("appFwVersion", 16, 4)
    val appFwSize = com.nuvoton.otaserver.DataField("appFwSize", 20, 4)
    val redundant = ByteArray(40)

    fun getRequestArray(): ByteArray {
        return checksum.dataArray + commandId.dataArray + packetId.dataArray + payloadSize.dataArray + sysFwVersion.dataArray +
                sysFwSize.dataArray + appFwVersion.dataArray + appFwSize.dataArray + redundant
    }}

class WriteRequest {
    val checksum = com.nuvoton.otaserver.DataField("checksum", 0, 2)
    val commandId = com.nuvoton.otaserver.DataField("commandId", 2, 1)
    val packetId = com.nuvoton.otaserver.DataField("packetId", 3, 1)
    val payloadSize = com.nuvoton.otaserver.DataField("payloadSize", 4, 4)
    val address = com.nuvoton.otaserver.DataField("address", 8, 4)
    val data = com.nuvoton.otaserver.DataField("data", 12, 44)
    val redundant = ByteArray(8)

    fun getRequestArray(): ByteArray {
        return checksum.dataArray + commandId.dataArray + packetId.dataArray + payloadSize.dataArray + address.dataArray + data.dataArray + redundant
    }
}

class DisconnectRequest {
    val checksum = com.nuvoton.otaserver.DataField("checksum", 0, 2)
    val commandId = com.nuvoton.otaserver.DataField("commandId", 2, 1)
    val packetId = com.nuvoton.otaserver.DataField("packetId", 3, 1)
    val payloadSize = com.nuvoton.otaserver.DataField("payloadSize", 4, 4)
    val updatedFlag = com.nuvoton.otaserver.DataField("updatedFlag", 8, 4)
    val redundant = ByteArray(52)

    fun getRequestArray(): ByteArray {
        return checksum.dataArray + commandId.dataArray + packetId.dataArray + payloadSize.dataArray + updatedFlag.dataArray+ redundant
    }
}