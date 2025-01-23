package com.nuvoton.otaserver

import com.nuvoton.otaserver.utility.LoggerInstance
import org.jetbrains.annotations.TestOnly
import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey
import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.spongycastle.jce.interfaces.ECKey
import org.spongycastle.jce.spec.ECNamedCurveSpec
import org.spongycastle.jce.spec.ECParameterSpec
import org.spongycastle.jce.spec.ECPrivateKeySpec
import java.math.BigInteger
import java.security.*
import java.security.spec.*
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Created by cchsu20 on 2018/4/30.
 */
class EncryptHelper private constructor() {
    private val TAG = "EncryptHelper"
    private val P_256_CURVE_STRING = "prime256v1"
    private val ecParameterSpec = ECGenParameterSpec(P_256_CURVE_STRING)

    private object Holder { val INSTANCE = EncryptHelper() }
    companion object {
        val shared: EncryptHelper by lazy { Holder.INSTANCE }

        fun byteArrayToString(byteArray: ByteArray): String {
            var string = ""
            for (byte in byteArray) {
                string += String.format("%02X", byte)
            }
            return string
        }

        fun stringToByteArray(chunkSize: Int, string: String): ByteArray {
            val byteArray = ByteArray(string.length / 2)
            val chunks = string.chunked(chunkSize)
            var i=0
            for (chunk in chunks) {
                byteArray[i++] = chunk.toLong(16).toChar().toByte()
            }
            return byteArray
        }

        fun charArrayToByteArray(charArray: CharArray): ByteArray {
            val byteArray = ByteArray(charArray.size)
            var index = 0
            for (char in charArray) {
                byteArray[index++] = char.toByte()
            }
            return byteArray
        }

        fun byteArrayToLong(byteArray: ByteArray): Long {
            var long: Long = 0
            for ((index, b) in byteArray.withIndex()) {
                val shiftBit = (byteArray.size-index-1)*8
                long = long.or(b.toLong().and(0xFF).shl(shiftBit))
            }
            return long
        }

        fun getSHA256(byteArray: ByteArray): ByteArray {
            val shaCode = MessageDigest.getInstance("SHA-256")
            return shaCode.digest(byteArray)
        }
    }

    init {
        Security.addProvider(org.spongycastle.jce.provider.BouncyCastleProvider())
    }

    fun generateNewKeys(): HashMap<String, ECKey>  {
        val keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "SC")
        keyPairGenerator.initialize(ecParameterSpec)
        val keyPair = keyPairGenerator.generateKeyPair()
        val privateKey = keyPair.private as BCECPrivateKey
        val publicKey = keyPair.public as BCECPublicKey
        val keys = HashMap<String, ECKey>()
        keys["privateKey"] = privateKey
        keys["publicKey"] = publicKey
        LoggerInstance.shared.debugMessage(TAG, "genPub=${publicKey.w.affineX.toByteArray().size}/${publicKey.w.affineY.toByteArray().size}")
        return keys
    }

    fun generateSecret(devicePub0: ByteArray, devicePub1: ByteArray, privateKey: PrivateKey): ByteArray {
        val kf = KeyFactory.getInstance("ECDH", "SC")

        val spec = org.spongycastle.jce.ECNamedCurveTable.getParameterSpec(P_256_CURVE_STRING)
        val params = ECNamedCurveSpec(P_256_CURVE_STRING, spec.curve, spec.g, spec.n)
        val temp = if (devicePub0.size == 32) byteArrayOf(0x00) + devicePub0 else devicePub0
        System.arraycopy(devicePub0, 0, temp, 1, temp.size - 1)
        val w = ECPoint(BigInteger(1, temp), BigInteger(1, devicePub1))
        val devicePublicKey = kf.generatePublic(ECPublicKeySpec(w, params))

        val kg = KeyAgreement.getInstance("ECDH", "SC")
        kg.init(privateKey)
        kg.doPhase(devicePublicKey, true)

        return kg.generateSecret()
    }

    fun generateSecret(devicePub0: ByteArray, devicePub1: ByteArray, privateKey: ByteArray): ByteArray {
        val pub0 = if (devicePub0.size == 32) byteArrayOf(0x00) + devicePub0 else devicePub0
        val pub1 = if (devicePub1.size == 32) byteArrayOf(0x00) + devicePub1 else devicePub1
        val pri = if (privateKey.size == 32) byteArrayOf(0x00) + privateKey else privateKey

        val kf = KeyFactory.getInstance("ECDH", "SC")
        val spec = org.spongycastle.jce.ECNamedCurveTable.getParameterSpec(P_256_CURVE_STRING)

        val ecPrivateKeySpec = ECPrivateKeySpec(BigInteger(1, pri), ECParameterSpec(spec.curve, spec.g, spec.n, spec.h, spec.seed))
        val serverPrivateKey = kf.generatePrivate(ecPrivateKeySpec)

        val params = ECNamedCurveSpec(P_256_CURVE_STRING, spec.curve, spec.g, spec.n)
        val w = ECPoint(BigInteger(1, pub0), BigInteger(1, pub1))
        val devicePublicKey = kf.generatePublic(ECPublicKeySpec(w, params))

        val kg = KeyAgreement.getInstance("ECDH", "SC")
        kg.init(serverPrivateKey)
        kg.doPhase(devicePublicKey, true)

        return kg.generateSecret()
    }

    fun generateSecret(publicKey: PublicKey, privateKey: PrivateKey): ByteArray {
        val kg = KeyAgreement.getInstance("ECDH", "SC")
        kg.init(privateKey)
        kg.doPhase(publicKey, true)

        return kg.generateSecret()
    }

    fun encapsuleKeys(pub0: ByteArray, pub1: ByteArray, pri: ByteArray): HashMap<String, ECKey> {
        val kf = KeyFactory.getInstance("ECDH", "SC")

        val spec = org.spongycastle.jce.ECNamedCurveTable.getParameterSpec(P_256_CURVE_STRING)
        val ecPrivateKeySpec = ECPrivateKeySpec(BigInteger(1, pri), ECParameterSpec(spec.curve, spec.g, spec.n, spec.h, spec.seed))
        val privateKey = kf.generatePrivate(ecPrivateKeySpec)
        val params = ECNamedCurveSpec(P_256_CURVE_STRING, spec.curve, spec.g, spec.n)
        val pub0New = if (pub0.size == 32) byteArrayOf(0x00) + pub0 else pub0

        val w = ECPoint(BigInteger(1, pub0New), BigInteger(1, pub1))
        LoggerInstance.shared.debugMessage(TAG, "ecpoint: ${w.affineX}, ${w.affineY}")
        val publicKey = kf.generatePublic(ECPublicKeySpec(w, params))
        return hashMapOf("privateKey" to privateKey as BCECPrivateKey, "publicKey" to publicKey as BCECPublicKey)
    }

    fun encapsulePublicKey(pub0: ByteArray, pub1: ByteArray): BCECPublicKey {
        val kf = KeyFactory.getInstance("ECDH", "SC")

        val spec = org.spongycastle.jce.ECNamedCurveTable.getParameterSpec(P_256_CURVE_STRING)
        val params = ECNamedCurveSpec(P_256_CURVE_STRING, spec.curve, spec.g, spec.n)
        val pub0New = if (pub0.size == 32) byteArrayOf(0x00) + pub0 else pub0

        val w = ECPoint(BigInteger(1, pub0New), BigInteger(1, pub1))
        LoggerInstance.shared.debugMessage(TAG, "ecpoint: ${w.affineX.toString()}, ${w.affineY.toString()}")
        val publicKey = kf.generatePublic(ECPublicKeySpec(w, params))
        return publicKey as BCECPublicKey
    }

    fun aes256DoingData(content: ByteArray, sessionKey: ByteArray, iv: ByteArray, mode: Int): ByteArray {
        return try {
            LoggerInstance.shared.debugMessage(TAG+", aes256", "sessionKey=${byteArrayToString(sessionKey)}")
            LoggerInstance.shared.debugMessage(TAG+", aes256", "iv=${byteArrayToString(iv!!)}")
            val secretKeySpec = SecretKeySpec(sessionKey, "AES")
            val ivSpec = IvParameterSpec(iv)
            val cipher = Cipher.getInstance("AES/CFB/NoPadding")
            cipher.init(mode, secretKeySpec, ivSpec)
            cipher.doFinal(content)
        }catch (e: Exception) {
            e.printStackTrace()
            val error = "Error"
            error.toByteArray()
        }
    }

    fun wordSwap(byteArray: ByteArray): ByteArray {
        val wordLength = 4
        var temp: ByteArray
        var result = ByteArray(0)
        val indexLimit = byteArray.size / wordLength
        for (i in 0 until indexLimit) {
            temp = byteArray.copyOfRange(i*wordLength, (i+1)*wordLength)
            result += temp.reversedArray()
        }
        return result
    }

    @TestOnly
    fun testAES256() {
        val sessionKey = "38001f3960f80ab538a3518a1c49f91da5457185c2e0757a55673ac86618c3c3"
        val iv = "5EAA905319FB5960EA43A854E7132F13"
        var sessionKeyArray = stringToByteArray(2, sessionKey)
        var ivArray = stringToByteArray(2, iv)
        val data = "952C4C42E3ACDECFE95BE62877945DE96EE18D0CF6E95AE458BAB92229A11F4C"
        var dataArray = stringToByteArray(2, data)
        val dummy = "00000000000000000000000000000000"
        var dummyArray = stringToByteArray(2, dummy)

        for (kR in 0..1) {
            for (kS in 0..1) {
                for (dR in 0..1) {
                    for (dS in 0..1) {
                        for (iR in 0..1) {
                            for (iS in 0..1) {
                                var keyTemp = if (kR == 0) sessionKeyArray else sessionKeyArray.reversedArray()
                                keyTemp = if (kS == 1) shared.wordSwap(keyTemp) else keyTemp
                                val secretKeySpec = SecretKeySpec(keyTemp, "AES")

                                var ivTemp = if (iR == 0) ivArray else ivArray.reversedArray()
                                ivTemp = if (iS == 1) shared.wordSwap(ivTemp) else ivTemp
                                val ivParameterSpec = IvParameterSpec(ivTemp)

                                var dataTemp = if (dR == 0) dataArray else dataArray.reversedArray()
                                dataTemp = if (dS == 1) shared.wordSwap(dataTemp)+dummyArray else dataTemp+dummyArray
                                val cipher = Cipher.getInstance("AES/CFB/NoPadding")
                                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec)
                                val result = cipher.doFinal(dataTemp)
                                val rString = byteArrayToString(result)

                                val keyString = byteArrayToString(keyTemp)
                                val ivString = byteArrayToString(ivTemp)
                                val dataString = byteArrayToString(dataTemp)

                                LoggerInstance.shared.debugMessage(TAG, "$kR/$kS/$dR/$dS/$iR/$iS, \nkeyString=$keyString, \nivString=$ivString, \ndataString=$dataString, \nresult=$rString\n")
                            }
                        }
                    }
                }
            }
        }
    }

    @TestOnly
    fun testSpongyCastleAES() {
        val sessionKey = "38001f3960f80ab538a3518a1c49f91da5457185c2e0757a55673ac86618c3c3"
        val iv = "5eaa90536059fb1954a843ea132f13e7"
        var sessionKeyArray = stringToByteArray(2, sessionKey)
        var ivArray = stringToByteArray(2, iv)
        val data = "4c1fa12922b9ba58e45ae9f60c8de16ee95d947728e65be9cfdeace3424c2c95"
        var dataArray = stringToByteArray(2, data)
        val dummy = "00000000000000000000000000000000"
        var dummyArray = stringToByteArray(2, dummy)

        for (keyReversed in 0..1) {
            for (dataReversed in 0..1) {
                for (dataWordSwap in 0..1) {
                    for (ivReversed in 0..1) {
                        val keyTemp = if (keyReversed == 0) sessionKeyArray else sessionKeyArray.reversedArray()
                        val secretKeySpec = SecretKeySpec(keyTemp, "AES")

                        val ivTemp = if (keyReversed == 0) ivArray else ivArray.reversedArray()
                        val ivParameterSpec = IvParameterSpec(ivTemp)

                        var dataTemp = if (dataReversed == 0) dataArray else dataArray.reversedArray()
                        dataTemp = if (dataWordSwap == 1) shared.wordSwap(dataTemp) else dataTemp
                        val cipher = Cipher.getInstance("AES/CFB/NoPadding")
                        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec)
                        val result = cipher.doFinal(dataTemp)
                        val rString = byteArrayToString(result)

                        var string = byteArrayToString(keyTemp)
                        LoggerInstance.shared.debugMessage("$TAG, $keyReversed/$dataReversed/$dataWordSwap/$ivReversed", "key=$string")
                        string = byteArrayToString(ivTemp)
                        LoggerInstance.shared.debugMessage("$TAG, $keyReversed/$dataReversed/$dataWordSwap/$ivReversed", "iv=$string")
                        string = byteArrayToString(dataTemp)
                        LoggerInstance.shared.debugMessage("$TAG, $keyReversed/$dataReversed/$dataWordSwap/$ivReversed", "data=$string")
                        LoggerInstance.shared.debugMessage("$TAG, $keyReversed/$dataReversed/$dataWordSwap/$ivReversed", "result=$rString\n")
                    }
                }
            }
        }
    }

    @TestOnly
    fun examineKeys() {
        val kf = KeyFactory.getInstance("ECDH", "SC")

        val spec = org.spongycastle.jce.ECNamedCurveTable.getParameterSpec(P_256_CURVE_STRING)
        val ecPrivateKeySpec = ECPrivateKeySpec(BigInteger(1, cBL2.privateByteArray), ECParameterSpec(spec.curve, spec.g, spec.n, spec.h, spec.seed))
        val privateKey = kf.generatePrivate(ecPrivateKeySpec)
        val params = ECNamedCurveSpec(P_256_CURVE_STRING, spec.curve, spec.g, spec.n)
        val w = ECPoint(BigInteger(cBL1.pub0ByteArray), BigInteger(cBL1.pub1ByteArray))
        LoggerInstance.shared.debugMessage(TAG, "ecpoint: ${w.affineX.toString()}, ${w.affineY.toString()}")
        val publicKey = kf.generatePublic(ECPublicKeySpec(w, params))

        val kg = KeyAgreement.getInstance("ECDH", "SC")
        kg.init(privateKey)
        kg.doPhase(publicKey, true)
        val secret = kg.generateSecret()

        var string = ""
        for (s in secret) {
            string += String.format("%02x", s)
        }

        LoggerInstance.shared.debugMessage(TAG, "secret: $secret, string: $string")

//        kg.init(cBL1_pri)
//        kg.doPhase(cBL1_pub, true)
//        val secret = kg.generateSecret()
    }

    /**
     * Class to generate private/public key from strings
     */

    class CustomKeys constructor(val private: String, val public0: String, val public1: String){
        private val TAG = "CustomKeys"
        private val OCTET_STRING_BEGIN_TAG: Byte = 0x04
        private val PRI_KEY_LEN = 32
        private val CHUNK_LENGTH = 2
        private val HEX_RADIX = 16
        var privateByteArray = ByteArray(PRI_KEY_LEN)
        var pub0ByteArray = ByteArray(PRI_KEY_LEN)
        var pub1ByteArray = ByteArray(PRI_KEY_LEN)
        init {
            var chunks = private.chunked(CHUNK_LENGTH)
            var i=0
            for (chunk in chunks) {
                privateByteArray[i++] = chunk.toLong(HEX_RADIX).toChar().toByte()
            }
            LoggerInstance.shared.debugMessage(TAG, "private done: i=$i")

            i=0
            chunks = public0.chunked(CHUNK_LENGTH)
            for (chunk in chunks) {
                pub0ByteArray[i++] = chunk.toLong(HEX_RADIX).toChar().toByte()
            }

            chunks = public1.chunked(CHUNK_LENGTH)

            i=0
            for (chunk in chunks) {
                pub1ByteArray[i++] = chunk.toLong(HEX_RADIX).toChar().toByte()
            }
            LoggerInstance.shared.debugMessage(TAG, "public done: i=$i")
        }
    }

    fun getSHA256(name: String): ByteArray {
        val shaCode = MessageDigest.getInstance("SHA-256")
        return if (name == "cBL32") {
            val origin = stringToByteArray(2, cBL32_pub0) + stringToByteArray(2, cBL32_pub1)
            LoggerInstance.shared.debugMessage(TAG, byteArrayToString(origin))
            shaCode.digest(origin)
        }else {
            val origin = stringToByteArray(2, cBL33_pub0) + stringToByteArray(2, cBL33_pub1)
            LoggerInstance.shared.debugMessage(TAG, byteArrayToString(origin))
            shaCode.digest(origin)
        }
    }

    @TestOnly
    fun testSHA256() {
        val shaCode = MessageDigest.getInstance("SHA-256")
        for (keySequence in 0..1) {
            for (reversed in 0..1) {
                for (wordSwap in 0..1) {
                    var pub0: ByteArray
                    var pub1: ByteArray
                    if (keySequence == 1) {
                        pub0 = stringToByteArray(2, cBL32_pub1)
                        pub1 = stringToByteArray(2, cBL32_pub0)
                    }else {
                        pub0 = stringToByteArray(2, cBL32_pub0)
                        pub1 = stringToByteArray(2, cBL32_pub1)
                    }
                    if (reversed == 1) {
                        pub0 = pub0.reversedArray()
                        pub1 = pub1.reversedArray()
                    }
                    if (wordSwap == 1) {
                        pub0 = wordSwap(pub0)
                        pub1 = wordSwap(pub1)
                    }
                    val result = shaCode.digest(pub0+pub1)
                    LoggerInstance.shared.debugMessage(TAG+"$keySequence/$reversed/$wordSwap", byteArrayToString(pub0+pub1))
                    LoggerInstance.shared.debugMessage(TAG+"$keySequence/$reversed/$wordSwap", byteArrayToString(result))
                }
            }
        }
    }

    fun getServerPubKeys(): ByteArray {
        val pub0ByteArray = stringToByteArray(2, cBL32_pub0).reversedArray()
        val pub1ByteArray = stringToByteArray(2, cBL32_pub1).reversedArray()
        return pub0ByteArray + pub1ByteArray
    }

    fun getServerPubKey(index: Int): ByteArray {
        return if (index == 0) stringToByteArray(2, cBL32_pub0)
               else stringToByteArray(2, cBL32_pub1)
    }

    /**
     * Server keys
     */
    val cServerKeys = CustomKeys(
            "cbede8baf6f8480e31c6eeb9699a2c5a94f6fa20c2e84e67516bd8c6fc906839",
            "4c1fa12922b9ba58e45ae9f60c8de16ee95d947728e65be9cfdeace3424c2c95",
            "e390c40ee19ec86d213506f6d0b4178e5f0d94ebece7f7eac494d2b7d3a47126"
    )
    /* BL2&Server ECDH(shared key): "38001f3960f80ab538a3518a1c49f91da5457185c2e0757a55673ac86618c3c3" */

    /**
     * BL2 public
     */
    val cBL2_pub0 = "755b3819f05a3e9f32d4d599062834aac5220f75955378414a8f63716a152ce2"
    val cBL2_pub1 = "91c413f1915ed7b47473fd797647ba3d83e8224377909af5b30c530eaad79fd7"

    /**
     * BL32 public key
     */
    val cBL32_pub0 = "4c1fa12922b9ba58e45ae9f60c8de16ee95d947728e65be9cfdeace3424c2c95"
    val cBL32_pub1 = "e390c40ee19ec86d213506f6d0b4178e5f0d94ebece7f7eac494d2b7d3a47126"

    /**
     * BL33 public key
     */
    val cBL33_pub0 = "ef2ae8fa29fa088afc0ade93250920f210274f88b97931656ae95dee494b3742"
    val cBL33_pub1 = "209a1d7dcdfa631211cd7e1c157c9fe3f532a48fb532ae23e2de543ba329f41f"

    /**
     * BL1 private key and public keys
     */
    val cBL1 = CustomKeys(
            "d0ab2cb9eb88976e82f107598077ce50d8c7b67def7039ee5ba39ee0dd3be411",
            "d32438a1b4428541c564eeed79669b4bd3bf601c758469545e013c8fe8af7ef6",
            "476de8f3c6e6c48a8bacf1e1827cfb82501833c2bb816344f996533b1b031706")
    val cBL2 = CustomKeys(
            "380a67fcfc01ca7073da7c2c54296a61327f77262a7d4674c3d8e29a63e3fa20",
            "755b3819f05a3e9f32d4d599062834aac5220f75955378414a8f63716a152ce2",
            "91c413f1915ed7b47473fd797647ba3d83e8224377909af5b30c530eaad79fd7")

    // extract cBL2_pub1 {0xaad79fd7, 0xb30c530e, 0x77909af5, 0x83e82243, 0x7647ba3d, 0x7473fd79, 0x915ed7b4, 0x91c413f1};
}