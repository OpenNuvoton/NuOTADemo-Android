package com.nuvoton.otaserver

import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Message
import android.util.Log
import com.nuvoton.otaserver.EncryptHelper.Companion.byteArrayToString
import com.nuvoton.otaserver.utility.LoggerInstance
import com.nuvoton.otaserver.utility.NuvotonLogger
import com.nuvoton.otaserver.utility.OTACommand
import com.nuvoton.otaserver.utility.OTAStatusCode
import com.snatik.storage.Storage
import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey
import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.spongycastle.jce.interfaces.ECKey
import java.io.*
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.PrivateKey
import java.util.*
import javax.crypto.Cipher
import kotlin.collections.ArrayList
import kotlin.concurrent.thread

/**
 * Created by cchsu20 on 2018/5/7.
 * Change by WPHU on 2020/12/25
 */

interface ServerCallBack {
    fun toWrite(byteArray: ByteArray)
    fun getConnectBuffer():ByteArray
    fun getBuffer():ByteArray
}
internal var serverCallBack: ServerCallBack? = null
fun setServerCallBackListener(callback: ServerCallBack) {
    serverCallBack = callback
}

enum class OTAWifiState {
    Idle,
    Connect,
    Req_Ecdh_Pub0,
    Req_Ecdh_Pub1,
    Req_Ecdh_Get_Pub0,
    Req_Ecdh_Get_Pub1,
    Req_Ecdh_Rand_Pub0,
    Req_Ecdh_Rand_Pub1,
    Req_Ecdh_Get_Rand_Pub0,
    Req_Ecdh_Get_Rand_Pub1,
    Req_Auth_Key_Sys,
    Req_Set_Mass_Write_Sys,
    Req_Mass_Write_Sys,
    Req_Auth_Key_App,
    Req_Set_Mass_Write_App,
    Req_Mass_Write_App,

    Disconnect,
    Error
}

class OTAServer private constructor() {
    // singleton
    private object Holder { val INSTANCE = OTAServer() }
    companion object {
        val shared: OTAServer by lazy { Holder.INSTANCE }
    }

//    private var serverSocket: ServerSocket? = null  //關閉Socket服務

    var isUpdating = false
    var sysFw: ByteArray? = null
    var appFw: ByteArray? = null
    var license: String? = null
    var messageHandler: Handler? = null

    fun closeServer() {
//        if (serverSocket?.isClosed == true)
//            serverSocket?.close()
    }

//    //建立連線
//    fun openServer(storage: Storage) {
//        thread {
//            try {
//                if (serverSocket != null && !serverSocket!!.isClosed) {
//                    serverSocket?.close()
//                    serverSocket = null
//                }
//                serverSocket = ServerSocket()
//                serverSocket?.reuseAddress = true
//                serverSocket?.bind(InetSocketAddress(PORT_NUM))
//                thread {
//                    val clientHandler = ClientHandler(serverSocket!!.accept())
//                    clientHandler.socketInterface = object : ClientHandler.SocketInterface {
//                        override fun closeSocket() {
//                            serverSocket?.close()
//                            isUpdating = false
//                        }
//                    }
//                    clientHandler.mStorage = storage
//                    clientHandler.messageHandler = messageHandler
//                    clientHandler.fwPathSys = sysFw
//                    clientHandler.fwPathApp = appFw
//                    clientHandler.ecdhSessionKeyPath = license ?: Environment.getExternalStorageDirectory().path + "/Download/license.txt"
//                    clientHandler.run() //建立連線後就ＲＵＮ
//                }
//            }catch (e: Exception) {
//                e.printStackTrace()
//            }
//        }
//    }

    //建立連線 無Socket版本
    fun openServer(storage: Storage) {
        thread {
            try {

                thread {
                    val clientHandler = ClientHandler()
                    clientHandler.mStorage = storage
                    clientHandler.messageHandler = messageHandler
                    clientHandler.fwPathSys = sysFw
                    clientHandler.fwPathApp = appFw
                    clientHandler.ecdhSessionKeyPath = license /*?: Environment.getExternalStorageDirectory().path + "/Download/license.txt"*/
                    clientHandler.run()

                    Log.i("serverSocket","serverSocket clientHandler is run")
                }
            }catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }

    class ClientHandler(/*client: Socket*/) {
        private val DEBUG = true
        private val TAG = "ClientHandler"
        private val PACKET_LENGTH = 64
//        private val reader = BufferedInputStream(client.getInputStream())
//        private val writer: OutputStream = client.getOutputStream()
        private var isRunning = false
        private var state = OTAWifiState.Idle
        private var keys: HashMap<String, ECKey>? = null
        private var ecdhSessionKey: ByteArray? = null
        private var iv: ByteArray? = null
        private var serverRandomPub0: ByteArray? = null
        private var serverRandomPub1: ByteArray? = null
        private var serverRandomPri: ByteArray? = null
        private var clientRandomPub0: ByteArray? = null
        private var clientRandomPub1: ByteArray? = null
        private var fwByteArraySys: ByteArray? = null
        private var fwByteArrayApp: ByteArray? = null
        private var license0String = ""
        private var license1String = ""
        private val fwAddrOffset = 0x48
        private val fwMetadataSize: Long = 0x150
        private val fwBL3xSize = 64
        private var secretKey: ByteArray? = null
        private var buffer = ByteArray(PACKET_LENGTH)
        var mStorage: Storage? = null
        var fwPathSys: ByteArray? = null
        var fwPathApp: ByteArray? = null
        var ecdhSessionKeyPath: String? = null
//        var socketInterface: SocketInterface? = null //暫時關閉
        var messageHandler: Handler? = null

        interface SocketInterface {
            fun closeSocket()
        }

        private fun updateError(state: OTAWifiState, responseStatus: Long) {
            val message = Message()
            val bundle = Bundle()
            val list = arrayListOf(state.name, "${responseStatus.toInt()}", "0", "0")
            bundle.putStringArrayList("list", list)
            message.data = bundle
            messageHandler?.sendMessage(message)
        }

        private fun updateProgress(state: OTAWifiState, responseStatus: Long, progress: Int, progressLimit: Int) {
            val message = Message()
            val bundle = Bundle()
            val list = arrayListOf(state.name, "${responseStatus.toInt()}", "$progress", "$progressLimit")
            bundle.putStringArrayList("list", list)
            message.data = bundle
            messageHandler?.sendMessage(message)
        }

        private fun debugByteArray(byteArray: ByteArray, type: String) {
            if (DEBUG) {
                val string = com.nuvoton.otaserver.EncryptHelper.byteArrayToString(byteArray)
                LoggerInstance.shared.debugMessage("$TAG, $type", string)
            }
        }

        fun run() {
            isRunning = true
            var connectBuffer = ByteArray(11)
            if(serverCallBack!=null){ //WPHU 新增窗口
                connectBuffer = serverCallBack!!.getConnectBuffer()
            }
//            var readAmount = reader.read(connectBuffer, 0, 11)

//            val sessionKeyFile = mStorage?.getFile(ecdhSessionKeyPath)
            var status = com.nuvoton.otaserver.UInt32(OTAStatusCode.STS_OK.raw)
            try {
                val multilineText = ecdhSessionKeyPath!!.trimIndent()
                val lines: List<String> = multilineText.lines()
                license0String = lines[0]
                val license0 = com.nuvoton.otaserver.EncryptHelper.stringToByteArray(2, license0String)
                license1String = lines[1]
                val license1 = com.nuvoton.otaserver.EncryptHelper.stringToByteArray(2, license1String)
                val serverKeys = com.nuvoton.otaserver.EncryptHelper.shared.cServerKeys
                ecdhSessionKey = com.nuvoton.otaserver.EncryptHelper.shared.generateSecret(license0, license1, serverKeys.privateByteArray)
//                ecdhSessionKey = EncryptHelper.shared.stringToByteArray(2, string!!)
                NuvotonLogger.debugMessage(TAG, "key license0=${byteArrayToString(license0)}")
                NuvotonLogger.debugMessage(TAG, "key license1=${byteArrayToString(license1)}")
                NuvotonLogger.debugMessage(TAG, "key ecdhSessionKey=${byteArrayToString(ecdhSessionKey!!)}")
            }catch (e: Exception) {
                e.printStackTrace()
                updateError(OTAWifiState.Connect, -1)
                return
            }
            if ( String(connectBuffer).contains("CONNECT0")) { //如果狀態正確了
                prepareRandomKeys()
                state = OTAWifiState.Connect
            }
            while (isRunning) {
                try {
                    when (state){
                        OTAWifiState.Idle -> {
                        }
                        OTAWifiState.Connect -> {
                            val requestConnect = com.nuvoton.otaserver.OTAField(OTACommand.CMD_CONNECT) //下第一個ＣＭＤ
                            var crc16Result = requestConnect.countCrc16()
                            var crc32Result = requestConnect.countCrc32()
                            NuvotonLogger.debugMessage(TAG, "$requestConnect")
                            val data = requestConnect.prepareData()

//                            writer.write(data)
//                            readAmount = reader.read(buffer, 0, PACKET_LENGTH)
                            if(serverCallBack!=null){ //WPHU 新增窗口
                                serverCallBack!!.toWrite(data)
                                buffer = serverCallBack!!.getBuffer()
                            }

                            val responseConnect = com.nuvoton.otaserver.OTAField(OTACommand.CMD_CONNECT)
                            responseConnect.putResponse(buffer)

                            val status = com.nuvoton.otaserver.UInt32(buffer.copyOfRange(8, 12))
                            val pdid = com.nuvoton.otaserver.UInt32(buffer.copyOfRange(12, 16))
                            val ivList = ArrayList<com.nuvoton.otaserver.UnsignedInt8>(16)
                            buffer.copyOfRange(16, 32).forEach { byte ->
                                ivList.add(com.nuvoton.otaserver.UnsignedInt8(byte))
                            }
                            iv = ByteArray(0)
                            ivList.forEach { it -> iv = iv!! + it.byte }

                            val temp = arrayListOf<com.nuvoton.otaserver.UnsignedInt8>()
                            temp.addAll(status.getUInt8List())
                            temp.addAll(pdid.getUInt8List())
                            temp.addAll(ivList)

                            temp.forEachIndexed { index, unsignedInt8 -> responseConnect.cipherData!![index] = unsignedInt8 }

                            crc32Result = responseConnect.countCrc32(true)
                            crc16Result = responseConnect.countCrc16(true)

                            NuvotonLogger.debugMessage(TAG, "16result=$crc16Result, , 32Result=$crc32Result, $responseConnect")
                            state = if (crc16Result && crc32Result) {
                                updateProgress(state, status.number, 1, 1)
                                OTAWifiState.Req_Ecdh_Pub0
                            } else {
                                updateError(state, status.number)
                                OTAWifiState.Error
                            }
                        }
                        OTAWifiState.Req_Ecdh_Pub0 -> {
                            val serverpubkey0Bytes = com.nuvoton.otaserver.EncryptHelper.shared.getServerPubKey(0)
                            val serverPubkey0 = ArrayList<com.nuvoton.otaserver.UInt32>()

                            val request = com.nuvoton.otaserver.OTAField(OTACommand.CMD_ECDH_PUB0)

                            for (i in 0 until serverpubkey0Bytes.size step 4) {
                                serverPubkey0.add(com.nuvoton.otaserver.UInt32(serverpubkey0Bytes.copyOfRange(i, i + 4)))
                            }

                            var index = 0
                            serverPubkey0.forEach { u32 ->
                                u32.getUInt8List().forEach { u8 ->
                                    request.cipherData!![index++] = u8
                                }
                            }

                            var crc16Result = request.countCrc16()
                            request.cipheringData(ecdhSessionKey!!, iv!!, Cipher.ENCRYPT_MODE)

                            var crc32Result = request.countCrc32()
                            val data = request.prepareData()

//                            try {
//                                writer.write(data)
//                            } catch (e: Exception) {
//                                e.printStackTrace()
//                                state = OTAWifiState.Error
//                            }
//                            readAmount = reader.read(buffer, 0, PACKET_LENGTH)

                            if(serverCallBack!=null){ //WPHU 新增窗口
                                serverCallBack!!.toWrite(data)
                                buffer = serverCallBack!!.getBuffer()
                            }

                            val response = com.nuvoton.otaserver.OTAField(OTACommand.CMD_ECDH_PUB0)
                            response.putResponse(buffer)
                            crc32Result = response.countCrc32(true)
                            response.cipheringData(ecdhSessionKey!!, iv!!, Cipher.DECRYPT_MODE)
                            crc16Result = response.countCrc16(true)

                            var statusData = ByteArray(0)
                            for (i in 8..11) {
                                statusData += response.cipherData!![i].byte
                            }

                            status = com.nuvoton.otaserver.UInt32(statusData)
                            state = if (status.number == com.nuvoton.otaserver.OTAConstants.STS_OK.toLong() && crc16Result && crc32Result) {
                                updateProgress(state, status.number, 1, 1)
                                OTAWifiState.Req_Ecdh_Pub1
                            } else {
                                updateError(state, status.number)
                                OTAWifiState.Error
                            }
                        }
                        OTAWifiState.Req_Ecdh_Pub1 -> {
                            val serverpubkey1Bytes = com.nuvoton.otaserver.EncryptHelper.shared.getServerPubKey(1)
                            val serverPubkey1 = ArrayList<com.nuvoton.otaserver.UInt32>()


                            val request = com.nuvoton.otaserver.OTAField(OTACommand.CMD_ECDH_PUB0)

                            for (i in 0 until serverpubkey1Bytes.size step 4) {
                                serverPubkey1.add(com.nuvoton.otaserver.UInt32(serverpubkey1Bytes.copyOfRange(i, i + 4)))
                            }

                            var index = 0
                            serverPubkey1.forEach { u32 ->
                                u32.getUInt8List().forEach { u8 ->
                                    request.cipherData!![index++] = u8
                                }
                            }

                            var crc16Result = request.countCrc16()
                            request.cipheringData(ecdhSessionKey!!, iv!!, Cipher.ENCRYPT_MODE)

                            var crc32Result = request.countCrc32()
                            val data = request.prepareData()

//                            writer.write(data)
//                            readAmount = reader.read(buffer, 0, PACKET_LENGTH)
                            if(serverCallBack!=null){ //WPHU 新增窗口
                                serverCallBack!!.toWrite(data)
                                buffer = serverCallBack!!.getBuffer()
                            }

                            val response = com.nuvoton.otaserver.OTAField(OTACommand.CMD_ECDH_PUB0)
                            response.putResponse(buffer)
                            buffer.copyOfRange(8, 55).forEachIndexed { i, it -> response.cipherData!![i] = com.nuvoton.otaserver.UnsignedInt8(it) }
                            crc32Result = response.countCrc32(true)
                            response.cipheringData(ecdhSessionKey!!, iv!!, Cipher.DECRYPT_MODE)
                            crc16Result = response.countCrc16(true)

                            var statusData = ByteArray(0)
                            for (i in 8..11) {
                                statusData += response.cipherData!![i].byte
                            }

                            status = com.nuvoton.otaserver.UInt32(statusData)
                            state = if (status.number == com.nuvoton.otaserver.OTAConstants.STS_OK.toLong() && crc16Result && crc32Result) {
                                updateProgress(state, status.number, 1, 1)
                                OTAWifiState.Req_Ecdh_Get_Pub0
                            } else {
                                updateError(state, status.number)
                                OTAWifiState.Error
                            }
                        }
                        OTAWifiState.Req_Ecdh_Get_Pub0 -> {
                            val req = com.nuvoton.otaserver.OTAField(OTACommand.CMD_ECDH_GET_PUB0)
                            var crc16Result = req.countCrc16()
                            req.cipheringData(ecdhSessionKey!!, iv!!, Cipher.ENCRYPT_MODE)
                            var crc32Result = req.countCrc32()

                            val data = req.prepareData()
//                            writer.write(data)
//                            readAmount = reader.read(buffer, 0, PACKET_LENGTH)
                            if(serverCallBack!=null){ //WPHU 新增窗口
                                serverCallBack!!.toWrite(data)
                                buffer = serverCallBack!!.getBuffer()
                            }

                            val rsp = com.nuvoton.otaserver.OTAField(OTACommand.CMD_ECDH_GET_PUB0)
                            rsp.putResponse(buffer)
                            crc32Result = rsp.countCrc32(true)
                            rsp.cipheringData(ecdhSessionKey!!, iv!!, Cipher.DECRYPT_MODE)
                            crc16Result = rsp.countCrc16(true)
                            var cipherDataBuffer = ByteArray(0)
                            rsp.cipherData!!.forEach { it -> cipherDataBuffer += it.byte }
                            status = com.nuvoton.otaserver.UInt32(cipherDataBuffer.copyOfRange(0, 4))
                            val cBL2List = ArrayList<com.nuvoton.otaserver.UInt32>()
                            for (i in 4 until 36 step 4) {
                                cBL2List.add(com.nuvoton.otaserver.UInt32(cipherDataBuffer.copyOfRange(i, i + 4)))
                            }
                            var cBL2Byte = ByteArray(0)
                            cBL2List.forEach { u32 -> u32.getUInt8List().forEach { u8 -> cBL2Byte += u8.byte } }
                            val cBL2String = com.nuvoton.otaserver.EncryptHelper.byteArrayToString(cBL2Byte)
                            NuvotonLogger.debugMessage(TAG, "cBL2String=$cBL2String")
                            state = if (crc16Result && crc32Result && status.number == OTAStatusCode.STS_OK.raw &&
                                    cBL2String.uppercase() == license0String.uppercase()) {
                                updateProgress(state, status.number, 1, 1)
                                OTAWifiState.Req_Ecdh_Get_Pub1
                            } else {
                                updateError(state, status.number)
                                OTAWifiState.Error
                            }
                        }
                        OTAWifiState.Req_Ecdh_Get_Pub1 -> {
                            val req = com.nuvoton.otaserver.OTAField(OTACommand.CMD_ECDH_GET_PUB1)
                            var crc16Result = req.countCrc16()
                            req.cipheringData(ecdhSessionKey!!, iv!!, Cipher.ENCRYPT_MODE)
                            var crc32Result = req.countCrc32()

                            val data = req.prepareData()
//                            writer.write(data)
//                            readAmount = reader.read(buffer, 0, PACKET_LENGTH)
                            if(serverCallBack!=null){ //WPHU 新增窗口
                                serverCallBack!!.toWrite(data)
                                buffer = serverCallBack!!.getBuffer()
                            }

                            val rsp = com.nuvoton.otaserver.OTAField(OTACommand.CMD_ECDH_GET_PUB0)
                            rsp.putResponse(buffer)
                            crc32Result = rsp.countCrc32(true)
                            rsp.cipheringData(ecdhSessionKey!!, iv!!, Cipher.DECRYPT_MODE)
                            crc16Result = rsp.countCrc16(true)
                            var cipherDataBuffer = ByteArray(0)
                            rsp.cipherData!!.forEach { it -> cipherDataBuffer += it.byte }
                            status = com.nuvoton.otaserver.UInt32(cipherDataBuffer.copyOfRange(0, 4))
                            val cBL2List = ArrayList<com.nuvoton.otaserver.UInt32>()
                            for (i in 4 until 36 step 4) {
                                cBL2List.add(com.nuvoton.otaserver.UInt32(cipherDataBuffer.copyOfRange(i, i + 4)))
                            }
                            var cBL2Byte = ByteArray(0)
                            cBL2List.forEach { u32 -> u32.getUInt8List().forEach { u8 -> cBL2Byte += u8.byte } }
                            val cBL2String = com.nuvoton.otaserver.EncryptHelper.byteArrayToString(cBL2Byte)
                            NuvotonLogger.debugMessage(TAG, "cBL2String=$cBL2String")
                            state = if (crc16Result && crc32Result && status.number == OTAStatusCode.STS_OK.raw &&
                                    cBL2String.uppercase() == license1String.uppercase()) {
                                updateProgress(state, status.number, 1, 1)
                                OTAWifiState.Req_Ecdh_Rand_Pub0
                            } else {
                                updateError(state, status.number)
                                OTAWifiState.Error
                            }
                        }
                        OTAWifiState.Req_Ecdh_Rand_Pub0 -> {
                            val req = com.nuvoton.otaserver.OTAField(OTACommand.CMD_ECDH_RAND_PUB0)
                            var index = 0
                            for (i in 0 until serverRandomPub0!!.size step 4) {
                                serverRandomPub0!!.copyOfRange(i, i + 4).forEach { byte -> req.cipherData!![index++] = com.nuvoton.otaserver.UnsignedInt8(byte) }
                            }

                            var crc16Result = req.countCrc16()
                            req.cipheringData(ecdhSessionKey!!, iv!!, Cipher.ENCRYPT_MODE)
                            var crc32Result = req.countCrc32()

                            val data = req.prepareData()
//                            writer.write(data)
//                            readAmount = reader.read(buffer, 0, PACKET_LENGTH)
                            if(serverCallBack!=null){ //WPHU 新增窗口
                                serverCallBack!!.toWrite(data)
                                buffer = serverCallBack!!.getBuffer()
                            }

                            val rsp = com.nuvoton.otaserver.OTAField(OTACommand.CMD_ECDH_RAND_PUB0)
                            rsp.putResponse(buffer)

                            crc32Result = rsp.countCrc32(true)
                            rsp.cipheringData(ecdhSessionKey!!, iv!!, Cipher.DECRYPT_MODE)
                            crc16Result = rsp.countCrc16(true)
                            val statusList = ArrayList(rsp.cipherData!!.subList(0, 4))
                            status = com.nuvoton.otaserver.UInt32(statusList)

                            state = if (crc16Result && crc32Result && status.number == OTAStatusCode.STS_OK.raw) {
                                updateProgress(state, status.number, 1, 1)
                                OTAWifiState.Req_Ecdh_Rand_Pub1
                            } else {
                                updateError(state, status.number)
                                OTAWifiState.Error
                            }
                        }
                        OTAWifiState.Req_Ecdh_Rand_Pub1 -> {
                            val req = com.nuvoton.otaserver.OTAField(OTACommand.CMD_ECDH_RAND_PUB1)
                            var index = 0
                            for (i in 0 until serverRandomPub1!!.size step 4) {
                                serverRandomPub1!!.copyOfRange(i, i + 4).forEach { byte -> req.cipherData!![index++] = com.nuvoton.otaserver.UnsignedInt8(byte) }
                            }

                            var crc16Result = req.countCrc16()
                            req.cipheringData(ecdhSessionKey!!, iv!!, Cipher.ENCRYPT_MODE)
                            var crc32Result = req.countCrc32()

                            val data = req.prepareData()
//                            writer.write(data)
//                            readAmount = reader.read(buffer, 0, PACKET_LENGTH)
                            if(serverCallBack!=null){ //WPHU 新增窗口
                                serverCallBack!!.toWrite(data)
                                buffer = serverCallBack!!.getBuffer()
                            }

                            val rsp = com.nuvoton.otaserver.OTAField(OTACommand.CMD_ECDH_RAND_PUB1)
                            rsp.putResponse(buffer)

                            crc32Result = rsp.countCrc32(true)
                            rsp.cipheringData(ecdhSessionKey!!, iv!!, Cipher.DECRYPT_MODE)
                            crc16Result = rsp.countCrc16(true)
                            val statusList = ArrayList(rsp.cipherData!!.subList(0, 4))
                            status = com.nuvoton.otaserver.UInt32(statusList)

                            state = if (crc16Result && crc32Result && status.number == OTAStatusCode.STS_OK.raw) {
                                updateProgress(state, status.number, 1, 1)
                                OTAWifiState.Req_Ecdh_Get_Rand_Pub0
                            } else {
                                updateError(state, status.number)
                                OTAWifiState.Error
                            }
                        }
                        OTAWifiState.Req_Ecdh_Get_Rand_Pub0 -> {
                            val req = com.nuvoton.otaserver.OTAField(OTACommand.CMD_ECDH_GET_RAND_PUB0)
                            var crc16Result = req.countCrc16()
                            req.cipheringData(ecdhSessionKey!!, iv!!, Cipher.ENCRYPT_MODE)
                            var crc32Result = req.countCrc32()

//                            writer.write(req.prepareData())
//                            readAmount = reader.read(buffer, 0, PACKET_LENGTH)
                            if(serverCallBack!=null){ //WPHU 新增窗口
                                serverCallBack!!.toWrite(req.prepareData())
                                buffer = serverCallBack!!.getBuffer()
                            }

                            val rsp = com.nuvoton.otaserver.OTAField(OTACommand.CMD_ECDH_GET_RAND_PUB0)
                            rsp.putResponse(buffer)
                            crc32Result = rsp.countCrc32(true)
                            rsp.cipheringData(ecdhSessionKey!!, iv!!, Cipher.DECRYPT_MODE)
                            crc16Result = rsp.countCrc16(true)

                            status = com.nuvoton.otaserver.UInt32(ArrayList(rsp.cipherData!!.subList(0, 4)))
                            val clientRandomKey = ArrayList<com.nuvoton.otaserver.UInt32>()
                            for (i in 4 until 36 step 4) {
                                clientRandomKey.add(com.nuvoton.otaserver.UInt32(ArrayList(rsp.cipherData!!.subList(i, i + 4))))
                            }
                            clientRandomPub0 = ByteArray(0)
                            clientRandomKey.forEach { u32 -> u32.getUInt8List().forEach { u8 -> clientRandomPub0 = clientRandomPub0!! + u8.byte } }
                            state = if (crc16Result && crc32Result && status.number == OTAStatusCode.STS_OK.raw) {
                                updateProgress(state, status.number, 1, 1)
                                OTAWifiState.Req_Ecdh_Get_Rand_Pub1
                            } else {
                                updateError(state, status.number)
                                OTAWifiState.Error
                            }
                        }
                        OTAWifiState.Req_Ecdh_Get_Rand_Pub1 -> {
                            val req = com.nuvoton.otaserver.OTAField(OTACommand.CMD_ECDH_GET_RAND_PUB1)
                            var crc16Result = req.countCrc16()
                            req.cipheringData(ecdhSessionKey!!, iv!!, Cipher.ENCRYPT_MODE)
                            var crc32Result = req.countCrc32()

//                            writer.write(req.prepareData())
//                            readAmount = reader.read(buffer, 0, PACKET_LENGTH)
                            if(serverCallBack!=null){ //WPHU 新增窗口
                                serverCallBack!!.toWrite(req.prepareData())
                                buffer = serverCallBack!!.getBuffer()
                            }

                            val rsp = com.nuvoton.otaserver.OTAField(OTACommand.CMD_ECDH_GET_RAND_PUB1)
                            rsp.putResponse(buffer)
                            crc32Result = rsp.countCrc32(true)
                            rsp.cipheringData(ecdhSessionKey!!, iv!!, Cipher.DECRYPT_MODE)
                            crc16Result = rsp.countCrc16(true)

                            status = com.nuvoton.otaserver.UInt32(ArrayList(rsp.cipherData!!.subList(0, 4)))
                            val clientRandomKey = ArrayList<com.nuvoton.otaserver.UInt32>()
                            for (i in 4 until 36 step 4) {
                                clientRandomKey.add(com.nuvoton.otaserver.UInt32(ArrayList(rsp.cipherData!!.subList(i, i + 4))))
                            }
                            clientRandomPub1 = ByteArray(0)
                            clientRandomKey.forEach { u32 -> u32.getUInt8List().forEach { u8 -> clientRandomPub1 = clientRandomPub1!! + u8.byte } }
                            if (crc16Result && crc32Result && status.number == OTAStatusCode.STS_OK.raw) {
                                updateProgress(state, status.number, 1, 1)

                                state = when {
                                    fwPathSys != null -> OTAWifiState.Req_Auth_Key_Sys
                                    fwPathSys == null && fwPathApp != null -> OTAWifiState.Req_Auth_Key_App
                                    else -> OTAWifiState.Disconnect
                                }

                                generateSecret()
                            } else {
                                updateError(state, status.number)
                                state = OTAWifiState.Error
                            }
                        }
                        OTAWifiState.Req_Auth_Key_Sys -> {
                            fwByteArraySys = fwPathSys!! //mStorage!!.readFile(fwPathSys)
                            val cBL32ByteArray = fwByteArraySys?.copyOfRange(0, fwBL3xSize)
                            NuvotonLogger.debugMessage(TAG, "cBL32 read = ${com.nuvoton.otaserver.EncryptHelper.byteArrayToString(cBL32ByteArray!!)}")
                            val req = com.nuvoton.otaserver.OTAField(OTACommand.CMD_AUTH_KPROM)
                            val hashArray = com.nuvoton.otaserver.EncryptHelper.getSHA256(cBL32ByteArray!!)
                            NuvotonLogger.debugMessage(TAG, "cBL32 SHA-256=${com.nuvoton.otaserver.EncryptHelper.byteArrayToString(hashArray)}")
                            val hashList = ArrayList<com.nuvoton.otaserver.UInt32>()
                            for (i in 0 until hashArray.size step 4) {
                                hashList.add(com.nuvoton.otaserver.UInt32(hashArray.copyOfRange(i, i + 4)))
                            }
                            var index = 0
                            hashList.forEach { u32 -> u32.getUInt8List().forEach { u8 -> req.cipherData!![index++] = u8 } }
                            var crc16Result = req.countCrc16()
                            req.cipheringData(secretKey!!, iv!!, Cipher.ENCRYPT_MODE)
                            var crc32Result = req.countCrc32()

//                            writer.write(req.prepareData())
//                            readAmount = reader.read(buffer, 0, PACKET_LENGTH)
                            if(serverCallBack != null){ //WPHU 新增窗口
                                serverCallBack!!.toWrite(req.prepareData())
                                LoggerInstance.shared.debugMessage(TAG, "Write=${byteArrayToString(req.prepareData())}")
                                buffer = serverCallBack!!.getBuffer()
                                LoggerInstance.shared.debugMessage(TAG, "buffer=${byteArrayToString(buffer)}")
                            }

                            val rsp = com.nuvoton.otaserver.OTAField(OTACommand.CMD_AUTH_KPROM)
                            rsp.putResponse(buffer)

                            crc32Result = rsp.countCrc32(true)
                            rsp.cipheringData(secretKey!!, iv!!, Cipher.DECRYPT_MODE)

                            crc16Result = rsp.countCrc16(true)

                            status = com.nuvoton.otaserver.UInt32(ArrayList(rsp.cipherData!!.subList(0, 4)))

                            state = if (crc16Result && crc32Result && status.number == OTAStatusCode.STS_OK.raw) {
                                updateProgress(state, status.number, 1, 1)
                                OTAWifiState.Req_Set_Mass_Write_Sys
                            } else {
                                updateError(state, status.number)
                                OTAWifiState.Error
                            }
                        }
                        OTAWifiState.Req_Set_Mass_Write_Sys -> {
                            val req = com.nuvoton.otaserver.OTAField(OTACommand.CMD_SET_MASS_WRITE)
                            val startAddress = com.nuvoton.otaserver.UInt32(fwByteArraySys!!.copyOfRange(fwAddrOffset, fwAddrOffset + 4))
//                            val startAddress = UInt32(0x140000)
                            startAddress.calculate(com.nuvoton.otaserver.Arithmetic.Sub, fwMetadataSize)
                            val totalDataLength = com.nuvoton.otaserver.UInt32(fwByteArraySys!!.size.toLong())
                            var index = 0
                            startAddress.getUInt8List().forEach { u8 -> req.cipherData!![index++] = u8 }
                            totalDataLength.getUInt8List().forEach { u8 -> req.cipherData!![index++] = u8 }

                            var crc16Result = req.countCrc16()
                            req.cipheringData(secretKey!!, iv!!, Cipher.ENCRYPT_MODE)
                            var crc32Result = req.countCrc32()

//                            writer.write(req.prepareData())
//                            reader.read(buffer, 0, PACKET_LENGTH)
                            if(serverCallBack!=null){ //WPHU 新增窗口
                                serverCallBack!!.toWrite(req.prepareData())
                                buffer = serverCallBack!!.getBuffer()
                            }

                            val rsp = com.nuvoton.otaserver.OTAField(OTACommand.CMD_SET_MASS_WRITE)
                            rsp.putResponse(buffer)

                            crc32Result = rsp.countCrc32(true)
                            rsp.cipheringData(secretKey!!, iv!!, Cipher.DECRYPT_MODE)
                            crc16Result = rsp.countCrc16(true)

                            status = com.nuvoton.otaserver.UInt32(ArrayList(rsp.cipherData!!.subList(0, 4)))

                            state = if (crc16Result && crc32Result && status.number == OTAStatusCode.STS_OK.raw) {
                                updateProgress(state, status.number, 1, 1)
                                OTAWifiState.Req_Mass_Write_Sys
                            } else {
                                updateError(state, status.number)
                                OTAWifiState.Error
                            }
                        }
                        OTAWifiState.Req_Mass_Write_Sys -> {
                            var req: com.nuvoton.otaserver.OTAField
                            var rsp: com.nuvoton.otaserver.OTAField
                            val dataSize = 48L
                            var crc16Result = true
                            var crc32Result = true
                            for ((packetId, i) in (0 until fwByteArraySys!!.size.toLong() step dataSize).withIndex()) {
                                req = com.nuvoton.otaserver.OTAField(OTACommand.CMD_MASS_WRITE)
                                req.packetId = com.nuvoton.otaserver.UInt16(packetId.toLong())
                                val packetEnd = i + if (i + dataSize > fwByteArraySys!!.size.toLong()) fwByteArraySys!!.size.toLong() % dataSize else dataSize
                                val data = fwByteArraySys!!.copyOfRange(i.toInt(), packetEnd.toInt())
                                val dataList = ArrayList<com.nuvoton.otaserver.UInt32>()
                                for (j in 0 until data.size step 4) {
                                    dataList.add(com.nuvoton.otaserver.UInt32(data.copyOfRange(j, j + 4)))
                                }
                                var index = 0
                                dataList.forEach { u32 -> u32.getUInt8List().forEach { u8 -> req.cipherData!![index++] = u8 } }
                                crc16Result = req.countCrc16()
                                req.cipheringData(secretKey!!, iv!!, Cipher.ENCRYPT_MODE)
                                crc32Result = req.countCrc32()

//                                writer.write(req.prepareData())
//                                reader.read(buffer, 0, PACKET_LENGTH)
                                if(serverCallBack!=null){ //WPHU 新增窗口
                                    serverCallBack!!.toWrite(req.prepareData())
                                    buffer = serverCallBack!!.getBuffer()
                                }

                                rsp = com.nuvoton.otaserver.OTAField(OTACommand.CMD_MASS_WRITE)
                                rsp.putResponse(buffer)

                                crc32Result = rsp.countCrc32(true)
                                rsp.cipheringData(secretKey!!, iv!!, Cipher.DECRYPT_MODE)
                                crc16Result = rsp.countCrc16(true)

                                status = com.nuvoton.otaserver.UInt32(ArrayList(rsp.cipherData!!.subList(0, 4)))

                                if (crc16Result && crc32Result && status.number == OTAStatusCode.STS_OK.raw) {
                                    updateProgress(state, status.number, packetId + 1, (fwByteArraySys!!.size / dataSize + 1).toInt())
                                } else {
                                    updateError(state, status.number)
                                    state = OTAWifiState.Error
                                    break
                                }
                            }
                            state = if (crc16Result && crc32Result &&
                                    (status.number == OTAStatusCode.ERR_OLD_FW_VER.raw || status.number == OTAStatusCode.STS_OK.raw)) {
                                if (fwPathApp != null) OTAWifiState.Req_Auth_Key_App else OTAWifiState.Disconnect
                            } else {
                                updateError(state, status.number)
                                OTAWifiState.Error
                            }
                        }
                        OTAWifiState.Req_Auth_Key_App -> {
                            // send auth key request for BL33
                            fwByteArrayApp = fwPathApp!! //mStorage!!.readFile(fwPathApp)
                            val cBL33ByteArray = fwByteArrayApp?.copyOfRange(0, fwBL3xSize)
                            NuvotonLogger.debugMessage(TAG, "cBL32 read = ${com.nuvoton.otaserver.EncryptHelper.byteArrayToString(cBL33ByteArray!!)}")
                            val req = com.nuvoton.otaserver.OTAField(OTACommand.CMD_AUTH_KPROM)
                            val hashArray = com.nuvoton.otaserver.EncryptHelper.getSHA256(cBL33ByteArray)
                            NuvotonLogger.debugMessage(TAG, "cBL33 SHA-256=${com.nuvoton.otaserver.EncryptHelper.byteArrayToString(hashArray)}")
                            val hashList = ArrayList<com.nuvoton.otaserver.UInt32>()
                            for (i in 0 until hashArray.size step 4) {
                                hashList.add(com.nuvoton.otaserver.UInt32(hashArray.copyOfRange(i, i + 4)))
                            }
                            var index = 0
                            hashList.forEach { u32 -> u32.getUInt8List().forEach { u8 -> req.cipherData!![index++] = u8 } }
                            var crc16Result = req.countCrc16()
                            req.cipheringData(secretKey!!, iv!!, Cipher.ENCRYPT_MODE)
                            var crc32Result = req.countCrc32()

//                            writer.write(req.prepareData())
//                            readAmount = reader.read(buffer, 0, PACKET_LENGTH)
                            if(serverCallBack!=null){ //WPHU 新增窗口
                                serverCallBack!!.toWrite(req.prepareData())
                                buffer = serverCallBack!!.getBuffer()
                            }

                            val rsp = com.nuvoton.otaserver.OTAField(OTACommand.CMD_AUTH_KPROM)
                            rsp.putResponse(buffer)

                            crc32Result = rsp.countCrc32(true)
                            rsp.cipheringData(secretKey!!, iv!!, Cipher.DECRYPT_MODE)
                            crc16Result = rsp.countCrc16(true)

                            status = com.nuvoton.otaserver.UInt32(ArrayList(rsp.cipherData!!.subList(0, 4)))

                            state = if (crc16Result && crc32Result && status.number == OTAStatusCode.STS_OK.raw) {
                                updateProgress(state, status.number, 1, 1)
                                OTAWifiState.Req_Set_Mass_Write_App
                            } else {
                                updateError(state, status.number)
                                OTAWifiState.Error
                            }
                        }
                        OTAWifiState.Req_Set_Mass_Write_App -> {
                            val req = com.nuvoton.otaserver.OTAField(OTACommand.CMD_SET_MASS_WRITE)
                            val startAddress = com.nuvoton.otaserver.UInt32(fwByteArrayApp!!.copyOfRange(fwAddrOffset, fwAddrOffset + 4))
//                            val startAddress = UInt32(0x1A0000)
                            startAddress.calculate(com.nuvoton.otaserver.Arithmetic.Sub, fwMetadataSize)
                            val totalDataLength = com.nuvoton.otaserver.UInt32(fwByteArrayApp!!.size.toLong())
                            var index = 0
                            startAddress.getUInt8List().forEach { u8 -> req.cipherData!![index++] = u8 }
                            totalDataLength.getUInt8List().forEach { u8 -> req.cipherData!![index++] = u8 }

                            var crc16Result = req.countCrc16()
                            req.cipheringData(secretKey!!, iv!!, Cipher.ENCRYPT_MODE)
                            var crc32Result = req.countCrc32()

//                            writer.write(req.prepareData())
//                            reader.read(buffer, 0, PACKET_LENGTH)
                            if(serverCallBack!=null){ //WPHU 新增窗口
                                serverCallBack!!.toWrite(req.prepareData())
                                buffer = serverCallBack!!.getBuffer()
                            }

                            val rsp = com.nuvoton.otaserver.OTAField(OTACommand.CMD_SET_MASS_WRITE)
                            rsp.putResponse(buffer)

                            crc32Result = rsp.countCrc32(true)
                            rsp.cipheringData(secretKey!!, iv!!, Cipher.DECRYPT_MODE)
                            crc16Result = rsp.countCrc16(true)

                            status = com.nuvoton.otaserver.UInt32(ArrayList(rsp.cipherData!!.subList(0, 4)))

                            state = if (crc16Result && crc32Result && status.number == OTAStatusCode.STS_OK.raw) {
                                updateProgress(state, status.number, 1, 1)
                                OTAWifiState.Req_Mass_Write_App
                            } else {
                                updateError(state, status.number)
                                OTAWifiState.Error
                            }
                        }
                        OTAWifiState.Req_Mass_Write_App -> {
                            var req: com.nuvoton.otaserver.OTAField
                            var rsp: com.nuvoton.otaserver.OTAField
                            val dataSize = 48L
                            var crc16Result = true
                            var crc32Result = true
                            for ((packetId, i) in (0 until fwByteArrayApp!!.size.toLong() step dataSize).withIndex()) {
                                req = com.nuvoton.otaserver.OTAField(OTACommand.CMD_MASS_WRITE)
                                req.packetId = com.nuvoton.otaserver.UInt16(packetId.toLong())
                                val packetEnd = i + if (i + dataSize > fwByteArrayApp!!.size.toLong()) fwByteArrayApp!!.size.toLong() % dataSize else dataSize
                                val data = fwByteArrayApp!!.copyOfRange(i.toInt(), packetEnd.toInt())
                                val dataList = ArrayList<com.nuvoton.otaserver.UInt32>()
                                for (j in 0 until data.size step 4) {
                                    dataList.add(com.nuvoton.otaserver.UInt32(data.copyOfRange(j, j + 4)))
                                }
                                var index = 0
                                dataList.forEach { u32 -> u32.getUInt8List().forEach { u8 -> req.cipherData!![index++] = u8 } }
                                crc16Result = req.countCrc16()
                                req.cipheringData(secretKey!!, iv!!, Cipher.ENCRYPT_MODE)
                                crc32Result = req.countCrc32()

//                                writer.write(req.prepareData())
//                                reader.read(buffer, 0, PACKET_LENGTH)
                                if(serverCallBack!=null){ //WPHU 新增窗口
                                    serverCallBack!!.toWrite(req.prepareData())
                                    buffer = serverCallBack!!.getBuffer()
                                }

                                rsp = com.nuvoton.otaserver.OTAField(OTACommand.CMD_MASS_WRITE)
                                rsp.putResponse(buffer)

                                crc32Result = rsp.countCrc32(true)
                                rsp.cipheringData(secretKey!!, iv!!, Cipher.DECRYPT_MODE)
                                crc16Result = rsp.countCrc16(true)

                                status = com.nuvoton.otaserver.UInt32(ArrayList(rsp.cipherData!!.subList(0, 4)))

                                if (crc16Result && crc32Result && status.number == OTAStatusCode.STS_OK.raw) {
                                    updateProgress(state, status.number, packetId + 1, (fwByteArrayApp!!.size / dataSize).toInt())
                                } else {
                                    updateError(state, status.number)
                                    state = OTAWifiState.Error
                                    break
                                }
                            }
                            state = if (crc16Result && crc32Result &&
                                    (status.number == OTAStatusCode.ERR_OLD_FW_VER.raw || status.number == OTAStatusCode.STS_OK.raw)) {
                                OTAWifiState.Disconnect
                            } else {
                                updateError(state, status.number)
                                OTAWifiState.Error
                            }
                        }
                        OTAWifiState.Disconnect -> {
                            // Disconnect request
                            val req = com.nuvoton.otaserver.OTAField(OTACommand.CMD_DISCONNECT)
                            val updateFlag = com.nuvoton.otaserver.UInt16(1)
                            var index = 0
                            updateFlag.getUInt8List().forEach { u8 -> req.cipherData!![index++] = u8 }

                            var crc16Result = req.countCrc16()
                            req.cipheringData(secretKey!!, iv!!, Cipher.ENCRYPT_MODE)
                            var crc32Result = req.countCrc32()

//                            writer.write(req.prepareData())
//                            reader.read(buffer, 0, PACKET_LENGTH)
                            if(serverCallBack!=null){ //WPHU 新增窗口
                                serverCallBack!!.toWrite(req.prepareData())
                                buffer = serverCallBack!!.getBuffer()
                            }

                            val rsp = com.nuvoton.otaserver.OTAField(OTACommand.CMD_DISCONNECT)
                            rsp.putResponse(buffer)
                            crc32Result = rsp.countCrc32(true)
                            rsp.cipheringData(secretKey!!, iv!!, Cipher.DECRYPT_MODE)
                            crc16Result = rsp.countCrc16(true)

                            status = com.nuvoton.otaserver.UInt32(ArrayList(rsp.cipherData!!.subList(0, 4)))

                            if (crc16Result && crc32Result && status.number == OTAStatusCode.STS_OK.raw) {
                                updateProgress(state, status.number, 1, 1)
                                LoggerInstance.shared.debugMessage(TAG + "Disconnect write rsp", "packetId=${rsp.packetId!!.number}, checksum ok")
                                isRunning = false
                            } else {
                                state = OTAWifiState.Error
                                LoggerInstance.shared.debugMessage(TAG + "Disconnect write rsp", "packetId=${rsp.packetId!!.number}, checksum failed")
                            }
                        }
                        OTAWifiState.Error -> {
                            when (status.number) {
                                OTAStatusCode.ERR_OLD_FW_VER.raw -> {

                                }
                                OTAStatusCode.ERR_CMD_CHECKSUM.raw -> {
                                }
                                OTAStatusCode.STS_REBOOT.raw -> {
                                }
                                else -> {
                                }
                            }
                        }
                    }
                }catch (e: Exception) {
                    e.printStackTrace()
//                    socketInterface?.closeSocket()
                    isRunning = false
                    state = OTAWifiState.Idle
                }
            }
//            socketInterface?.closeSocket()
            state = OTAWifiState.Idle
        }

        private fun prepareRandomKeys() {
            keys = com.nuvoton.otaserver.EncryptHelper.shared.generateNewKeys()
            val privateKey = keys!!["privateKey"] as BCECPrivateKey
            val publicKey = keys!!["publicKey"] as BCECPublicKey
            serverRandomPub0 = publicKey.w.affineX.toByteArray()
            if (serverRandomPub0!!.size == 31) serverRandomPub0 = byteArrayOf(0) + serverRandomPub0!!
            if (serverRandomPub0!!.size == 33) serverRandomPub0 = serverRandomPub0!!.copyOfRange(1, 33)
            serverRandomPub1 = publicKey.w.affineY.toByteArray()
            if (serverRandomPub1!!.size == 31) serverRandomPub1 = byteArrayOf(0) + serverRandomPub1!!
            if (serverRandomPub1!!.size == 33) serverRandomPub1 = serverRandomPub1!!.copyOfRange(1, 33)
            serverRandomPri = privateKey.d.toByteArray()
            if (serverRandomPri!!.size == 31) serverRandomPri = byteArrayOf(0) + serverRandomPri!!
            if (serverRandomPri!!.size == 33) serverRandomPri = serverRandomPri!!.copyOfRange(1, 33)
        }

        private fun generateSecret() {
//            val encapsuledServerKeys = EncryptHelper.shared.encapsuleKeys(serverRandomPub0!!, serverRandomPub1!!, serverRandomPri!!)
            val clientPublicKey = com.nuvoton.otaserver.EncryptHelper.shared.encapsulePublicKey(clientRandomPub0!!, clientRandomPub1!!)
            val serverPrivateKey = keys!!["privateKey"]

            secretKey = com.nuvoton.otaserver.EncryptHelper.shared.generateSecret(clientPublicKey, serverPrivateKey as PrivateKey)
//            secretKey = EncryptHelper.shared.generateSecret(clientRandomPub0!!, clientRandomPub1!!, encapsuledServerKeys["privateKey"] as PrivateKey)
            debugByteArray(secretKey!!, "secretKey")
        }
    }
}