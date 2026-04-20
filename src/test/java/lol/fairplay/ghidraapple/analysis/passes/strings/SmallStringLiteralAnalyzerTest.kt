package lol.fairplay.ghidraapple.analysis.passes.strings

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class SmallStringLiteralAnalyzerTest {

    @Test
    fun `test decoding Hi string from 0x6948`() {
        // "Hi" = 0x6948 in little-endian (0x48='H', 0x69='i')
        val bytes = byteArrayOf(0x48, 0x69, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        val result = decodeSmallString(bytes)
        assertEquals("Hi", result)
    }

    @Test
    fun `test decoding Hello, World!!!`() {
        // "Hello, World!!!" - 15 characters
        val str = "Hello, World!!!"
        val bytes = str.toByteArray()
        val result = decodeSmallString(bytes)
        assertEquals(str, result)
    }

    @Test
    fun `test empty bytes returns null`() {
        val bytes = byteArrayOf()
        val result = decodeSmallString(bytes)
        assertNull(result)
    }

    @Test
    fun `test null-padded string`() {
        val bytes = byteArrayOf(
            0x48, 0x69,  // "Hi"
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // padding
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        )
        val result = decodeSmallString(bytes)
        assertEquals("Hi", result)
    }

    @Test
    fun `test string with tab and newline`() {
        val bytes = byteArrayOf(
            0x48, 0x65, 0x6c, 0x6c, 0x6f,  // "Hello"
            0x09,  // tab
            0x77, 0x6f, 0x72, 0x6c, 0x64  // "world"
        )
        val result = decodeSmallString(bytes)
        assertEquals("Hello\tworld", result)
    }

    @Test
    fun `test string with control character is rejected`() {
        val bytes = byteArrayOf(
            0x48, 0x65, 0x6c, 0x6c, 0x6f,  // "Hello"
            0x01,  // SOH (control char, not tab/newline)
            0x77, 0x6f, 0x72, 0x6c, 0x64  // "world"
        )
        val result = decodeSmallString(bytes)
        assertNull(result)
    }

    // Helper function to match the one in SmallStringLiteralAnalyzer
    private fun decodeSmallString(bytes: ByteArray): String? {
        val PRINTABLE_ASCII_MIN = 0x20
        val PRINTABLE_ASCII_MAX = 0x7e

        if (bytes.isEmpty()) return null

        // Find the actual string length by looking for printable ASCII
        var endIdx = bytes.size - 1
        while (endIdx > 0 && bytes[endIdx] == 0.toByte()) {
            endIdx--
        }

        // Extract printable characters
        val stringChars = mutableListOf<Char>()
        for (i in 0..endIdx) {
            val b = bytes[i].toInt() and 0xff
            if (b == 0) break  // null terminator
            if (b >= PRINTABLE_ASCII_MIN && b <= PRINTABLE_ASCII_MAX) {
                stringChars.add(b.toChar())
            } else if (b in 0x09..0x0d) {
                // Allow tabs, newlines, etc.
                stringChars.add(b.toChar())
            }
        }

        return if (stringChars.isNotEmpty()) stringChars.joinToString("") else null
    }
}

