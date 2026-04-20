package lol.fairplay.ghidraapple.analysis.passes.strings

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Listing
import ghidra.program.model.listing.Program
import ghidra.util.Msg
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor

/**
 * Reconstructs small string literals encoded directly in ARM64 registers.
 *
 * Small strings in Swift are stored inline within the 16-byte `_StringObject` structure,
 * using one or more 64-bit registers to hold the content and an additional register
 * for the discriminator.
 *
 * ## Detected Patterns
 *
 * ### Pattern 1: Short string (≤ 4 bytes)
 * ```
 * mov w8, #0x6948           ; "Hi" in little-endian
 * mov x9, #-0x1e00000000000000  ; discriminator with isSmall bit set
 * ```
 *
 * ### Pattern 2: Long small string (5-16 bytes)
 * ```
 * mov x0, #0x6548           ; "He" (bytes 0-1)
 * movk x0, #0x6c6c, lsl #16 ; "ll" (bytes 2-3)
 * movk x0, #0x2c6f, lsl #32 ; "o," (bytes 4-5)
 * movk x0, #0x5720, lsl #48 ; " W" (bytes 6-7)
 * mov x1, #0xef21...        ; remaining bytes + discriminator
 * ```
 *
 * ## Discriminator Bits
 *
 * The discriminator value contains Swift string metadata:
 *   - bit 63: isImmortal (1 = string literal)
 *   - bit 62: isASCII (1 = all characters are ASCII-7)
 *   - bit 61: isSmall (1 = small string, content is inline)
 *   - bit 60: isForeign (0 = native, 1 = bridged)
 *
 * For typical small string literals: discriminator has high bits = 0xe... (1110 binary)
 *
 * ## References
 *
 * - Swift String Implementation: https://github.com/apple/swift/blob/main/stdlib/public/core/String.swift
 * - StringObject Source: https://github.com/swiftlang/swift/blob/main/stdlib/public/core/StringObject.swift
 * - SmallString Source: https://github.com/swiftlang/swift/blob/main/stdlib/public/core/SmallString.swift
 */
class SmallStringLiteralAnalyzer : AbstractAnalyzer(
    NAME,
    DESCRIPTION,
    AnalyzerType.INSTRUCTION_ANALYZER
) {
    companion object {
        private const val NAME = "Small String Literal Reconstruction"
        private const val DESCRIPTION =
            "Reconstructs small string literals encoded in ARM64 mov/movk sequences"

        private const val MAX_MOVK_SEQUENCE = 3  // max movk instructions after initial mov
        private const val PRINTABLE_ASCII_MIN = 0x20
        private const val PRINTABLE_ASCII_MAX = 0x7e

        private const val DEBUG_ADDRESS = "1017162a8"
    }

    private fun debugPrintln(address: String?, message: String) {
        if (address?.lowercase() == DEBUG_ADDRESS.lowercase()) {
            println(message)
        }
    }

    init {
        setDefaultEnablement(true)
        setPrototype()
    }

    override fun canAnalyze(program: Program): Boolean =
        program.language.processor == ghidra.program.model.lang.Processor.findOrPossiblyCreateProcessor(
            "AARCH64"
        )

    override fun added(
        program: Program,
        set: AddressSetView,
        monitor: TaskMonitor,
        log: MessageLog,
    ): Boolean {
        val listing = program.listing
        var count = 0

        try {
            val instructions = listing.getInstructions(set, true)

            while (instructions.hasNext()) {
                if (monitor.isCancelled) throw CancelledException()

                val inst = instructions.next() ?: continue

                // Look for mov or movz instructions with immediate values
                val isMov = inst.mnemonicString == "mov" || inst.mnemonicString == "movz"
                if (!isMov) continue

                val addressStr = inst.address.toString()
                debugPrintln(addressStr, "[SmallStringAnalyzer] ========== PROCESSING INSTRUCTION ==========")
                debugPrintln(addressStr, "[SmallStringAnalyzer] Address: ${inst.address}, Mnemonic: ${inst.mnemonicString}")

                val destReg = inst.getRegister(0) ?: continue
                val scalar = inst.getScalar(1) ?: continue

                val destRegName = destReg.name
                val initialValue = scalar.unsignedValue

                debugPrintln(addressStr, "[SmallStringAnalyzer] Destination register: $destRegName")
                debugPrintln(addressStr, "[SmallStringAnalyzer] Initial immediate value: 0x%016x".format(initialValue))

                val accumulatedBytes = mutableListOf<Byte>()

                val firstBytes = scalar.unsignedValue.toBytes()
                debugPrintln(addressStr, "[SmallStringAnalyzer] First bytes (from initial mov): ${firstBytes.joinToString(" ") { "%02x".format(it) }}")
                accumulatedBytes.addAll(firstBytes.toList())

                debugPrintln(addressStr, "[SmallStringAnalyzer] STEP 1: Collecting movks for first register")
                debugPrintln(addressStr, "[SmallStringAnalyzer] >>> Entering collectMovksForRegister for '${destReg.name}'")
                val lastFirstRegInst = collectMovksForRegister(
                    listing,
                    inst,
                    destReg.name,
                    0, // byte offset 0 for first register
                    accumulatedBytes,
                    addressStr
                )
                debugPrintln(addressStr, "[SmallStringAnalyzer] <<< Exiting collectMovksForRegister, accumulatedBytes now: ${accumulatedBytes.joinToString(" ") { "%02x".format(it) }}")

                // Try to collect second register
                debugPrintln(addressStr, "[SmallStringAnalyzer] STEP 2: Collecting second register (if present)")
                debugPrintln(addressStr, "[SmallStringAnalyzer] >>> Entering collectSecondRegisterIfPresent")
                val discriminatorInst = collectSecondRegisterIfPresent(
                    listing,
                    lastFirstRegInst,
                    accumulatedBytes,
                    addressStr
                ) ?: lastFirstRegInst
                debugPrintln(addressStr, "[SmallStringAnalyzer] <<< Exiting collectSecondRegisterIfPresent, accumulatedBytes now: ${accumulatedBytes.joinToString(" ") { "%02x".format(it) }}")
                val stringBytes = accumulatedBytes.toByteArray()
                debugPrintln(addressStr, "[SmallStringAnalyzer] FINAL STATE: Collected bytes at ${inst.address}: ${stringBytes.joinToString(" ") { "%02x".format(it) }}")

                // Verify the accumulated bytes contain a valid discriminator (bit 61 set = isSmall)
                // The discriminator is encoded in byte 15 (the most significant byte)
                // Bit pattern (from MSB): isImmortal(1) | isASCII(1) | isSmall(1) | isForeign(1) | ...
                // For small string literals, we need isSmall bit (bit 5 of byte 15) to be set
                if (stringBytes.size < 16) {
                    debugPrintln(addressStr, "[SmallStringAnalyzer] VALIDATION FAILED: Only ${stringBytes.size} bytes, need 16 for discriminator")
                    continue
                }

                val discriminatorByte = stringBytes[15].toInt() and 0xff
                val hasSmallBit = (discriminatorByte and 0x20) != 0  // Check bit 5 (isSmall)

                debugPrintln(addressStr, "[SmallStringAnalyzer] Discriminator byte [15]: 0x%02x".format(discriminatorByte))
                debugPrintln(addressStr, "[SmallStringAnalyzer] Discriminator bits: %s (isImmortal=%d, isASCII=%d, isSmall=%d)".format(
                    (discriminatorByte).toString(2).padStart(8, '0'),
                    (discriminatorByte shr 7) and 1,
                    (discriminatorByte shr 6) and 1,
                    (discriminatorByte shr 5) and 1
                ))

                if (!hasSmallBit) {
                    debugPrintln(addressStr, "[SmallStringAnalyzer] VALIDATION FAILED: isSmall bit not set in discriminator 0x%02x".format(discriminatorByte))
                    continue
                }

                // Decode the string content
                debugPrintln(addressStr, "[SmallStringAnalyzer] STEP 3: Decoding string content")
                val stringValue = decodeSmallString(stringBytes, addressStr)
                if (stringValue == null) {
                    debugPrintln(addressStr, "[SmallStringAnalyzer] DECODING FAILED: Could not decode string")
                    continue
                }

                debugPrintln(addressStr, "[SmallStringAnalyzer] ✓ SUCCESS at ${inst.address}: \"$stringValue\"")

                // Add a reference and comment at the discriminator instruction
                if (stringValue.isNotEmpty()) {
                    runCatching {
                        val codeUnit = listing.getCodeUnitAt(discriminatorInst.address) ?: return@runCatching
                        val comment = "Small string: \"$stringValue\""
                        val existing = codeUnit.getComment(CommentType.EOL)
                        if (existing == null || !existing.contains(comment)) {
                            val mergedComment = if (existing.isNullOrBlank()) {
                                comment
                            } else {
                                "$existing | $comment"
                            }
                            codeUnit.setComment(CommentType.EOL, mergedComment)
                        }
                    }.onFailure {
                        Msg.warn(this, "Could not set comment at ${discriminatorInst.address}: ${it.message}")
                    }

                    count++
                    monitor.message = "Small strings resolved: $count"
                }

                debugPrintln(addressStr, "[SmallStringAnalyzer] ===========================================\n")
            }
        } catch (_: CancelledException) {
            return false
        }

        monitor.message = "Small strings resolved: $count"
        return true
    }

    /**
     * Collects movk instructions for a given register starting from the specified instruction.
     *
     * Modifies accumulatedBytes in-place by inserting the decoded bytes from each movk instruction
     * at the appropriate position based on the shift amount and byteOffset.
     *
     * Returns the last movk instruction processed, or the input instruction if no movks found.
     */
    private fun collectMovksForRegister(
        listing: Listing,
        startInst: Instruction,
        regName: String,
        byteOffset: Int,
        accumulatedBytes: MutableList<Byte>,
        addressStr: String
    ): Instruction {
        var current = startInst
        var movkCount = 0

        debugPrintln(addressStr, "[SmallStringAnalyzer] Starting collectMovksForRegister for register '$regName' at byteOffset=$byteOffset")
        debugPrintln(addressStr, "[SmallStringAnalyzer] Initial accumulatedBytes state: ${accumulatedBytes.joinToString(" ") { "%02x".format(it) }}")

        while (movkCount < MAX_MOVK_SEQUENCE) {
            val nextMovk = listing.getInstructionAfter(current.address) ?: break
            if (nextMovk.mnemonicString != "movk") break
            if (nextMovk.getRegister(0)?.name != regName) break

            val immValue = nextMovk.getScalar(1)?.unsignedValue ?: break

            // Ghidra returns the value already shifted, so convert directly to bytes
            // The bytes will be in the correct positions due to the shift being embedded
            val valueBytes = immValue.toBytes()

            debugPrintln(addressStr, "[SmallStringAnalyzer]   MOVK #$movkCount at ${nextMovk.address}")
            debugPrintln(addressStr, "[SmallStringAnalyzer]     Imm value (full/shiftado): 0x%016x".format(immValue))
            debugPrintln(addressStr, "[SmallStringAnalyzer]     Value bytes (8-byte LE): ${valueBytes.joinToString(" ") { "%02x".format(it) }}")

            // Merge these 8 bytes into accumulatedBytes starting at byteOffset
            // Use OR to combine bytes instead of overwriting, since different movks
            // have different shift positions (embedded in immValue by Ghidra)
            for ((idx, b) in valueBytes.withIndex()) {
                val byteIdx = byteOffset + idx
                if (byteIdx < accumulatedBytes.size) {
                    val combined = (accumulatedBytes[byteIdx].toInt() and 0xff) or (b.toInt() and 0xff)
                    debugPrintln(addressStr, "[SmallStringAnalyzer]       Combining byte at index $byteIdx: 0x%02x | 0x%02x = 0x%02x".format(accumulatedBytes[byteIdx], b, combined.toByte()))
                    accumulatedBytes[byteIdx] = combined.toByte()
                } else {
                    debugPrintln(addressStr, "[SmallStringAnalyzer]       Adding new byte at index $byteIdx: 0x%02x".format(b))
                    accumulatedBytes.add(b)
                }
            }

            debugPrintln(addressStr, "[SmallStringAnalyzer]     After MOVK #$movkCount: ${accumulatedBytes.joinToString(" ") { "%02x".format(it) }}")

            current = nextMovk
            movkCount++
        }

        debugPrintln(addressStr, "[SmallStringAnalyzer] collectMovksForRegister finished: processed $movkCount movks")
        debugPrintln(addressStr, "[SmallStringAnalyzer] Final state: ${accumulatedBytes.joinToString(" ") { "%02x".format(it) }}")

        return current
    }

    /**
     * Attempts to collect a second register with more string data (for 9-16 byte strings).
     *
     * Returns the last instruction of the second register sequence (either last movk or initial mov),
     * or the discriminator instruction if found directly after the first register.
     *
     * For dual-register strings, collects the second register's bytes into accumulatedBytes.
     * Even if the second register contains a discriminator, its bytes are added to accumulatedBytes
     * since they may contain string data.
     */
    private fun collectSecondRegisterIfPresent(
        listing: Listing,
        lastFirstRegInst: Instruction,
        accumulatedBytes: MutableList<Byte>,
        addressStr: String
    ): Instruction? {
        // Next instruction should be either second register mov, discriminator, or something else
        val next = listing.getInstructionAfter(lastFirstRegInst.address) ?: return null

        debugPrintln(addressStr, "[SmallStringAnalyzer] Looking for second register after ${lastFirstRegInst.address}")
        debugPrintln(addressStr, "[SmallStringAnalyzer]   Next instruction: ${next.mnemonicString} at ${next.address}")

        // Stop at branch instructions
        val mnemonic = next.mnemonicString
        if (mnemonic == "bl" || mnemonic == "blr" || mnemonic == "b" ||
            mnemonic == "br" || mnemonic.startsWith("b.")
        ) {
            debugPrintln(addressStr, "[SmallStringAnalyzer]   Branch instruction found, stopping search")
            return null
        }

        val reg = next.getRegister(0) ?: return null
        val scalar = next.getScalar(1) ?: return null
        val value = scalar.unsignedValue

        debugPrintln(addressStr, "[SmallStringAnalyzer]   Register: ${reg.name}, Mnemonic: $mnemonic, Value: 0x%016x".format(value))

        // Check if it's mov/movz
        if (mnemonic != "mov" && mnemonic != "movz") {
            debugPrintln(addressStr, "[SmallStringAnalyzer]   Not a mov/movz, skipping")
            return null
        }

        // Add the second register's initial value at byte offset 8
        // This applies to both low values (string data) and high values (discriminator with possible string data)
        val secondRegBytes = value.toBytes()
        debugPrintln(addressStr, "[SmallStringAnalyzer]   Adding second register bytes at offset 8: ${secondRegBytes.joinToString(" ") { "%02x".format(it) }}")

        for ((idx, b) in secondRegBytes.withIndex()) {
            val byteIdx = 8 + idx
            if (byteIdx < accumulatedBytes.size) {
                val combined = (accumulatedBytes[byteIdx].toInt() and 0xff) or (b.toInt() and 0xff)
                debugPrintln(addressStr, "[SmallStringAnalyzer]     Combining byte at index $byteIdx: 0x%02x | 0x%02x = 0x%02x".format(accumulatedBytes[byteIdx], b, combined.toByte()))
                accumulatedBytes[byteIdx] = combined.toByte()
            } else {
                debugPrintln(addressStr, "[SmallStringAnalyzer]     Adding new byte at index $byteIdx: 0x%02x".format(b))
                accumulatedBytes.add(b)
            }
        }
        debugPrintln(addressStr, "[SmallStringAnalyzer]   After second register mov: ${accumulatedBytes.joinToString(" ") { "%02x".format(it) }}")

        // Low value - it's a second register mov with string data, collect its movks
        val secondRegName = reg.name
        debugPrintln(addressStr, "[SmallStringAnalyzer]   Low value - collecting movks for second register '$secondRegName'")

        // Collect movks on the second register
        return collectMovksForRegister(
            listing,
            next,
            secondRegName,
            8, // byte offset for second register
            accumulatedBytes,
            addressStr
        )
    }



    /**
     * Decodes a small string from accumulated bytes.
     * The format is:
     * - Bytes 0-14: string content (up to 15 chars)
     * - Byte 15: high nibble is discriminator, low nibble may be padding or last char
     *
     * Returns the decoded string, or null if it doesn't look like valid ASCII.
     */
    private fun decodeSmallString(bytes: ByteArray, addressStr: String): String? {
        if (bytes.isEmpty()) return null

        debugPrintln(addressStr, "[SmallStringAnalyzer]   Input bytes (${bytes.size} total): ${bytes.joinToString(" ") { "%02x".format(it) }}")

        // Find the actual string length by looking for printable ASCII
        var endIdx = bytes.size - 1
        while (endIdx > 0 && bytes[endIdx] == 0.toByte()) {
            endIdx--
        }

        debugPrintln(addressStr, "[SmallStringAnalyzer]   Scanning from byte 0 to $endIdx (skipped ${bytes.size - 1 - endIdx} trailing zeros)")

        // Extract printable characters
        val stringChars = mutableListOf<Char>()
        for (i in 0..endIdx) {
            val b = bytes[i].toInt() and 0xff

            if (b == 0) {
                debugPrintln(addressStr, "[SmallStringAnalyzer]     Byte[$i]: 0x${"%02x".format(b)} (${b}) -> null terminator, stopping")
                break  // null terminator
            } else if (b in PRINTABLE_ASCII_MIN..PRINTABLE_ASCII_MAX) {
                stringChars.add(b.toChar())
                debugPrintln(addressStr, "[SmallStringAnalyzer]     Byte[$i]: 0x${"%02x".format(b)} (${b}) -> '${b.toChar()}' (printable ASCII)")
            } else if (b in 0x09..0x0d) {
                // Allow tabs, newlines, etc.
                stringChars.add(b.toChar())
                val description = when (b) {
                    0x09 -> "\\t (tab)"
                    0x0a -> "\\n (newline)"
                    0x0b -> "\\v (vertical tab)"
                    0x0c -> "\\f (form feed)"
                    0x0d -> "\\r (carriage return)"
                    else -> "special char"
                }
                debugPrintln(addressStr, "[SmallStringAnalyzer]     Byte[$i]: 0x${"%02x".format(b)} (${b}) -> $description")
            } else {
                debugPrintln(addressStr, "[SmallStringAnalyzer]     Byte[$i]: 0x${"%02x".format(b)} (${b}) -> not printable (skipped)")
            }
        }

        val result = if (stringChars.isNotEmpty()) stringChars.joinToString("") else null
        debugPrintln(addressStr, "[SmallStringAnalyzer]   Decoded string: \"$result\" (${stringChars.size} chars)")

        return result
    }

    /**
     * Converts a Long to a byte array (little-endian).
     */
    private fun Long.toBytes(): ByteArray {
        return byteArrayOf(
            (this and 0xffL).toByte(),
            ((this shr 8) and 0xffL).toByte(),
            ((this shr 16) and 0xffL).toByte(),
            ((this shr 24) and 0xffL).toByte(),
            ((this shr 32) and 0xffL).toByte(),
            ((this shr 40) and 0xffL).toByte(),
            ((this shr 48) and 0xffL).toByte(),
            ((this shr 56) and 0xffL).toByte(),
        )
    }
}
















