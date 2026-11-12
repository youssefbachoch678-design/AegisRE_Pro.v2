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
                bytes[2] == 'x'.code.toByte() && bytes[3] == 10.toByte()) { "Invalid DEX magic" }

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
            checkTable(bytes, stringOff, stringCount, 4)
            checkTable(bytes, typeOff, typeCount, 4)
            checkTable(bytes, methodOff, methodCount, 8)
            checkTable(bytes, classOff, classCount, 32)

            val strings = ArrayList<String>(stringCount)
            repeat(stringCount) { i ->
                val dataOff = u32(b, stringOff + i * 4)
                strings += readDexString(bytes, dataOff)
            }

            val types = ArrayList<String>(typeCount)
            repeat(typeCount) { i ->
                val descriptorIndex = u32(b, typeOff + i * 4)
                types += strings.getOrElse(descriptorIndex.toInt()) { "<invalid-string-index>" }
            }

            val classes = ArrayList<String>()
            repeat(classCount) { i ->
                val typeIndex = u32(b, classOff + i * 32)
                classes += types.getOrElse(typeIndex) { "<invalid-type-index>" }
            }

            val methods = ArrayList<String>()
            repeat(methodCount) { i ->
                val item = methodOff + i * 8
                val classIndex = u16(b, item)
                val nameIndex = u32(b, item + 4)
                val owner = types.getOrElse(classIndex) { "<invalid-owner>" }
                val method = strings.getOrElse(nameIndex.toInt()) { "<invalid-name>" }
                methods += "$owner->$method"
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

    private fun checkTable(bytes: ByteArray, offset: Int, count: Int, itemSize: Int) {
        if (count == 0) return
        require(offset >= HEADER_SIZE && offset.toLong() + count.toLong() * itemSize <= bytes.size.toLong()) {
            "DEX table points outside file"
        }
    }

    private fun readDexString(bytes: ByteArray, offset: Int): String {
        require(offset in HEADER_SIZE until bytes.size) { "DEX string offset out of bounds" }
        var cursor = offset
        var shift = 0
        while (true) {
            require(cursor < bytes.size && shift <= 28) { "Invalid DEX string length" }
            val value = bytes[cursor++].toInt() and 0xff
            if (value and 0x80 == 0) break
            shift += 7
        }
        val start = cursor
        while (cursor < bytes.size && bytes[cursor].toInt() != 0) cursor++
        require(cursor < bytes.size) { "Unterminated DEX string" }
        return String(bytes, start, cursor - start, Charsets.UTF_8)
    }
}
