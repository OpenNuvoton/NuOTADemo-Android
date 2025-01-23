package com.nuvoton.otaserver

/**
 * Created by cchsu20 on 2018/7/10.
 */

enum class Arithmetic(arithmetic: String) {
    Add("add"),
    Sub("subtract"),
    Div("divide"),
    Multi("multiply")
}

class UnsignedInt8 {
    var uint8: Int = 0
    var byte: Byte = 0x00

    constructor(uint8: Int) {
        this.uint8 = uint8
        this.byte = uint8.and(0xFF).toByte()
    }
    constructor(raw: Byte) {
        this.byte = raw
        this.uint8 = raw.toInt().and(0xFF)
    }

    override fun toString(): String {
        return "uint8=$uint8, byte=${byte.toString(16)}"
    }
}

open class UIntPrototype {
    private var uint8List: ArrayList<UnsignedInt8>? = null
    private var bytesCount = 0
    var number: Long = 0

    constructor(bytesCount: Int, number: Long, inLittleEndian: Boolean) {
        uint8List = arrayListOf()
        this.bytesCount = bytesCount
        this.number = number
        if (inLittleEndian) {
            for (i in 0 until bytesCount) uint8List!!.add(UnsignedInt8(number.shr(i * 8).and(0xFF).toInt()))
        }else {
            for (i in 0 until bytesCount) uint8List!!.add(UnsignedInt8(number.shr((bytesCount - 1 - i) * 8).and(0xFF).toInt()))
        }
    }

    constructor(bytesCount: Int, bytes: ByteArray, isLittleEndian: Boolean) {
        uint8List = arrayListOf()
        this.bytesCount = bytesCount
        if (isLittleEndian) {
            for (i in 0 until bytesCount) uint8List!!.add(UnsignedInt8(bytes[bytesCount - 1 - i]))
        }else {
            for (i in 0 until bytesCount) uint8List!!.add(UnsignedInt8(bytes[i]))
        }
        uint8List!!.forEachIndexed { index, uint8 ->
            number = number.or(uint8.byte.toLong().and(0xFF).shl((bytesCount - 1 - index)*8))
        }
    }

    constructor(u8List: ArrayList<UnsignedInt8>, isLittleEndian: Boolean) {
        uint8List = if (isLittleEndian) {
            u8List.reversed() as ArrayList<UnsignedInt8>
        }else {
            u8List
        }
        this.bytesCount = u8List.size
        uint8List!!.forEachIndexed { index, uint8 ->
            number = number.or(uint8.byte.toLong().and(0xFF).shl((u8List.size - 1 - index)*8))
        }
    }

    fun getUInt8List(inLittle: Boolean = true): ArrayList<UnsignedInt8> {
        return if (inLittle) uint8List!!.reversed() as ArrayList<UnsignedInt8> else uint8List!!
    }

    fun calculate(type: Arithmetic, value: Long) {
        when(type) {
            Arithmetic.Add -> { this.number += value }
            Arithmetic.Sub -> { this.number -= value }
            Arithmetic.Multi -> { this.number *= value }
            Arithmetic.Div -> { this.number /= value }
        }
        uint8List!!.clear()
        for (i in 0 until bytesCount) uint8List!!.add(UnsignedInt8(number.shr((bytesCount - 1 - i) * 8).and(0xFF).toInt()))
    }
}

class UInt16 : UIntPrototype {
    constructor(number: Long, inLittleEndian: Boolean = false) : super(2, number, inLittleEndian)
    constructor(bytes: ByteArray, isLittleEndian: Boolean = true) : super(2, bytes, isLittleEndian)
    constructor(u8List: ArrayList<UnsignedInt8>, isLittleEndian: Boolean = true) : super(u8List, isLittleEndian)
}

class UInt32 : UIntPrototype {
    constructor(number: Long, inLittleEndian: Boolean = false) : super(4, number, inLittleEndian)
    constructor(bytes: ByteArray, isLittleEndian: Boolean = true) : super(4, bytes, isLittleEndian)
    constructor(u8List: ArrayList<UnsignedInt8>, isLittleEndian: Boolean = true) : super(u8List, isLittleEndian)
}