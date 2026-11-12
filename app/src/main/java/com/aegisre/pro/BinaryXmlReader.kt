package com.aegisre.pro

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Small, bounds-checked Android binary XML (AXML) reader.
 * It extracts start-tag names and attributes only; it does not resolve resource IDs.
 */
internal object BinaryXmlReader {
    data class Element(val name: String, val attributes: Map<String, String>)

    fun read(bytes: ByteArray): List<Element> {
        require(bytes.size >= 8) { "Binary XML header is truncated" }
        val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        require(u16(b, 0) == 0x0003) { "Not Android binary XML" }
        val documentSize = u32(b, 4).toInt()
        require(documentSize in 8..bytes.size) { "Invalid binary XML size" }
        var cursor = u16(b, 2)
        var strings: List<String> = emptyList()
        val elements = mutableListOf<Element>()
        while (cursor + 8 <= documentSize) {
            val type = u16(b, cursor)
            val headerSize = u16(b, cursor + 2)
            val chunkSize = u32(b, cursor + 4).toInt()
            require(headerSize >= 8 && chunkSize >= headerSize && cursor.toLong() + chunkSize <= documentSize) {
                "Invalid binary XML chunk bounds"
            }
            when (type) {
                0x0001 -> strings = parseStringPool(b, cursor, chunkSize)
                0x0102 -> {
                    require(strings.isNotEmpty()) { "Binary XML string pool missing" }
                    require(chunkSize >= 36) { "Truncated start-element chunk" }
                    val name = strings.getOrNull(u32(b, cursor + 20).toInt()) ?: "<unknown>"
                    val attributeStart = u16(b, cursor + 24)
                    val attributeSize = u16(b, cursor + 26)
                    val attributeCount = u16(b, cursor + 28)
                    require(attributeSize >= 20 && attributeCount <= 512) { "Invalid attribute table" }
                    val attrsStart = cursor + 16 + attributeStart
                    require(attrsStart.toLong() + attributeCount.toLong() * attributeSize <= cursor + chunkSize) {
                        "Attribute table outside chunk"
                    }
                    val attrs = linkedMapOf<String, String>()
                    repeat(attributeCount) { index ->
                        val at = attrsStart + index * attributeSize
                        val attrName = strings.getOrNull(u32(b, at + 4).toInt()) ?: return@repeat
                        val rawIndex = u32(b, at + 8).toInt()
                        val raw = strings.getOrNull(rawIndex)
                        val valueType = b.get(at + 15).toInt() and 0xff
                        val data = u32(b, at + 16)
                        val value = raw ?: when (valueType) {
                            0x03 -> strings.getOrNull(data.toInt()) ?: data.toString()
                            0x12 -> if (data == 0L) "false" else "true"
                            0x10, 0x11 -> data.toString()
                            else -> data.toString()
                        }
                        attrs[attrName] = value
                    }
                    elements += Element(name, attrs)
                }
            }
            cursor += chunkSize
        }
        return elements
    }

    private fun parseStringPool(b: ByteBuffer, start: Int, chunkSize: Int): List<String> {
        require(chunkSize >= 28) { "Truncated string pool" }
        val count = u32(b, start + 8).toInt()
        val flags = u32(b, start + 16)
        val stringsStart = u32(b, start + 20).toInt()
        require(count in 0..100_000 && 28L + count * 4L <= chunkSize && stringsStart in 28..chunkSize) {
            "Invalid string pool bounds"
        }
        val utf8 = flags and 0x100L != 0L
        return (0 until count).map { index ->
            val relative = u32(b, start + 28 + index * 4).toInt()
            val pos = start + stringsStart + relative
            require(pos in start until start + chunkSize) { "String offset outside pool" }
            if (utf8) {
                var p = pos
                p += decodeLength8(b, p).second
                val (byteLength, used) = decodeLength8(b, p)
                p += used
                require(p.toLong() + byteLength <= start + chunkSize) { "UTF-8 string outside pool" }
                val data = ByteArray(byteLength) { b.get(p + it) }
                String(data, Charsets.UTF_8)
            } else {
                var p = pos
                val (charLength, used) = decodeLength16(b, p)
                p += used
                require(p.toLong() + charLength.toLong() * 2 <= start + chunkSize) { "UTF-16 string outside pool" }
                val chars = CharArray(charLength) { b.getShort(p + it * 2).toInt().toChar() }
                String(chars)
            }
        }
    }

    private fun decodeLength8(b: ByteBuffer, offset: Int): Pair<Int, Int> {
        val first = b.get(offset).toInt() and 0xff
        return if (first and 0x80 == 0) first to 1 else {
            (((first and 0x7f) shl 8) or (b.get(offset + 1).toInt() and 0xff)) to 2
        }
    }

    private fun decodeLength16(b: ByteBuffer, offset: Int): Pair<Int, Int> {
        val first = u16(b, offset)
        return if (first and 0x8000 == 0) first to 2 else {
            (((first and 0x7fff) shl 16) or u16(b, offset + 2)) to 4
        }
    }

    private fun u16(b: ByteBuffer, offset: Int): Int {
        require(offset >= 0 && offset + 2 <= b.limit()) { "Binary XML read out of bounds" }
        return b.getShort(offset).toInt() and 0xffff
    }

    private fun u32(b: ByteBuffer, offset: Int): Long {
        require(offset >= 0 && offset + 4 <= b.limit()) { "Binary XML read out of bounds" }
        return b.getInt(offset).toLong() and 0xffffffffL
    }
}
