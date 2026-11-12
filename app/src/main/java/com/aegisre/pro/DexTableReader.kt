package com.aegisre.pro

import java.nio.ByteBuffer
import java.nio.ByteOrder

data class DexBrowseResult(
    val classNames: List<String>,
    val methodNames: List<String>,
    val stringSamples: List<String>,
    val warning: String? = null
)

/**
 * Bounded, read-only DEX table reader. It never executes bytecode.
 * Lists are intentionally capped for predictable memory use on mobile devices.
 */
object DexTableReader {
    private const val HEADER_SIZE = 112
    private const val MAX_ITEMS = 100_000
    private const val MAX_DISPLAY = 500

    fun inspect(bytes: ByteArray): DexBrowseResult {
        return try {
            require(bytes.size >= HEADER_SIZE) { "DEX header is truncated" }
            val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            require(bytes[0] == 'd'.code.toByte() && bytes[1] == 'e'.code.toByte() &&
                bytes[2] == 'x'.code.toByte() && bytes[3] == 10.toByte() && bytes[7] == 0.toByte()
            ) { "Invalid DEX magic" }

            val fileSize = u32(b, 32)
            require(fileSize in HEADER_SIZE.toLong()..bytes.size.toLong()) { "Invalid DEX file_size" }
            require(u32(b, 36) == HEADER_SIZE.toLong()) { "Unsupported DEX header_size" }
            require(u32(b, 40) == 0x12345678L) { "Unsupported DEX endian tag" }

            val stringCount = count(b, 56)
            val stringOff = offset(b, 60)
            val typeCount = count(b, 64)
            val typeOff = offset(b, 68)
            val methodCount = count(b, 88)
            val methodOff = offset(b, 92)
            val classCount = count(b, 96)
            val classOff = offset(b, 100)

            require(stringCount <= MAX_ITEMS && typeCount <= MAX_ITEMS &&
                methodCount <= MAX_ITEMS && classCount <= MAX_ITEMS) { "DEX table exceeds safety limit" }
            checkTable(fileSize, stringOff, stringCount, 4)
            checkTable(fileSize, typeOff, typeCount, 4)
            checkTable(fileSize, methodOff, methodCount, 8)
            checkTable(fileSize, classOff, classCount, 32)

            val strings = ArrayList<String>(stringCount)
            repeat(stringCount) { i ->
                val dataOff = u32(b, stringOff + i * 4)
                require(dataOff <= Int.MAX_VALUE.toLong()) { "DEX string offset is too large" }
                strings += readDexString(bytes, fileSize.toInt(), dataOff.toInt())
            }

            val types = ArrayList<String>(typeCount)
            repeat(typeCount) { i ->
                val descriptorIndex = u32(b, typeOff + i * 4)
                require(descriptorIndex < strings.size.toLong()) { "DEX type descriptor index is invalid" }
                types += strings[descriptorIndex.toInt()]
            }

            val classes = ArrayList<String>()
            repeat(classCount) { i ->
                val typeIndex = u32(b, classOff + i * 32)
                require(typeIndex < types.size.toLong()) { "DEX class type index is invalid" }
                classes += types[typeIndex.toInt()]
            }

            val methods = ArrayList<String>()
            repeat(methodCount) { i ->
                val item = methodOff + i * 8
                val classIndex = u16(b, item)
                val nameIndex = u32(b, item + 4)
                require(classIndex < types.size) { "DEX method owner index is invalid" }
                require(nameIndex < strings.size.toLong()) { "DEX method name index is invalid" }
                methods += "${types[classIndex]}->${strings[nameIndex.toInt()]}"
            }

            DexBrowseResult(
                classNames = classes.take(MAX_DISPLAY),
                methodNames = methods.take(MAX_DISPLAY),
                stringSamples = strings.asSequence()
                    .filter { it.length >= 3 && it.any(Char::isLetterOrDigit) }
                    .take(MAX_DISPLAY)
                    .toList()
            )
        } catch (e: Exception) {
            DexBrowseResult(emptyList(), emptyList(), emptyList(), e.message ?: "DEX parsing failed")
        }
    }

    private fun count(b: ByteBuffer, offset: Int): Int {
        val value = u32(b, offset)
        require(value <= Int.MAX_VALUE) { "Invalid DEX table count" }
        return value.toInt()
    }

    private fun offset(b: ByteBuffer, offset: Int): Int {
        val value = u32(b, offset)
        require(value <= Int.MAX_VALUE) { "Invalid DEX table offset" }
        return value.toInt()
    }

    private fun u32(b: ByteBuffer, offset: Int): Long {
        require(offset >= 0 && offset + 4 <= b.limit()) { "DEX header/table out of bounds" }
        return b.getInt(offset).toLong() and 0xffffffffL
    }

    private fun u16(b: ByteBuffer, offset: Int): Int {
        require(offset >= 0 && offset + 2 <= b.limit()) { "DEX table out of bounds" }
        return b.getShort(offset).toInt() and 0xffff
    }

    private fun checkTable(fileSize: Long, offset: Int, count: Int, itemSize: Int) {
        if (count == 0) return
        require(offset >= HEADER_SIZE && offset.toLong() + count.toLong() * itemSize <= fileSize) {
            "DEX table points outside file"
        }
    }

    /** Decode DEX MUTF-8 using the declared UTF-16 code-unit length. */
    private fun readDexString(bytes: ByteArray, fileSize: Int, offset: Int): String {
        require(offset in HEADER_SIZE until fileSize) { "DEX string offset out of bounds" }
        var cursor = offset
        var encodedLength = 0
        var shift = 0
        while (true) {
            require(cursor < fileSize && shift <= 28) { "Invalid DEX string length" }
            val value = bytes[cursor++].toInt() and 0xff
            encodedLength = encodedLength or ((value and 0x7f) shl shift)
            if (value and 0x80 == 0) break
            shift += 7
        }
        require(encodedLength in 0..65_535) { "DEX string is too long" }
        val chars = CharArray(encodedLength)
        var out = 0
        while (true) {
            require(cursor < fileSize) { "Unterminated DEX string" }
            val first = bytes[cursor++].toInt() and 0xff
            if (first == 0) break
            val codeUnit = when {
                first and 0x80 == 0 -> first
                first and 0xe0 == 0xc0 -> {
                    require(cursor < fileSize) { "Truncated MUTF-8 sequence" }
                    val second = bytes[cursor++].toInt() and 0xff
                    require(second and 0xc0 == 0x80) { "Invalid MUTF-8 continuation byte" }
                    ((first and 0x1f) shl 6) or (second and 0x3f)
                }
                first and 0xf0 == 0xe0 -> {
                    require(cursor + 1 < fileSize) { "Truncated MUTF-8 sequence" }
                    val second = bytes[cursor++].toInt() and 0xff
                    val third = bytes[cursor++].toInt() and 0xff
                    require(second and 0xc0 == 0x80 && third and 0xc0 == 0x80) {
                        "Invalid MUTF-8 continuation bytes"
                    }
                    ((first and 0x0f) shl 12) or ((second and 0x3f) shl 6) or (third and 0x3f)
                }
                else -> error("Invalid MUTF-8 leading byte")
            }
            require(out < encodedLength) { "DEX string exceeds declared UTF-16 length" }
            chars[out++] = codeUnit.toChar()
        }
        require(out == encodedLength) { "DEX string length does not match its UTF-16 length" }
        return String(chars)
    }
}
