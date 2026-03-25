package lol.fairplay.ghidraapple.analysis.passes.swift

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.lang.Register
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Listing
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.util.Msg
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor

/**
 * Reconstructs cross-references for Swift string literals passed to ObjC methods via
 * _bridgeToObjectiveC.
 *
 * Detects the following ARM64 pattern:
 *
 *   adrp  xN, page_base
 *   add   xN, xN, #offset         ← points directly at character data
 *   sub   xM, xN, #adjustment     ← optional Swift ABI artifact — ignored
 *   orr   xK, xM, #swift_tag      ← bit 63 set
 *   ...
 *   bl    _bridgeToObjectiveC
 *
 * The `sub` instruction is a Swift ABI artifact: the compiler adjusts the pointer
 * from the character data address back to the StringStorage object header. Since
 * `add` already points at the characters, we ignore `sub` entirely and always use
 * pageBase + addOffset as the string address.
 *
 * Reference: https://github.com/apple/swift/blob/main/stdlib/public/core/StringObject.swift
 *
 * When the pattern is found, adds a DATA reference from the `orr` instruction
 * to the resolved string address, and adds an EOL comment on the
 * `bl _bridgeToObjectiveC` showing the string value.
 */
class SwiftBridgedStringAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER) {
    companion object {
        private const val NAME = "Swift: Bridged String Argument Reconstruction"
        private const val DESCRIPTION =
            "Resolves Swift string literals passed to ObjC via _bridgeToObjectiveC (adrp+add+sub+orr pattern)"

        private const val SWIFT_TAG_MASK = Long.MIN_VALUE // 0x8000000000000000
        private const val MAX_BACKTRACK_STEPS = 20
    }

    init {
        setDefaultEnablement(true)
    }

    override fun canAnalyze(program: Program): Boolean = true

    override fun added(
        program: Program,
        set: AddressSetView,
        monitor: TaskMonitor,
        log: MessageLog,
    ): Boolean {
        val listing = program.listing
        val refMgr = program.referenceManager
        var count = 0

        try {
            val instructions = listing.getInstructions(set, true)

            while (instructions.hasNext()) {
                if (monitor.isCancelled) throw CancelledException()

                val inst = instructions.next() ?: continue

                if (!isBridgeToObjectiveC(inst)) continue

                val orrInst = findOrrWithSwiftTag(listing, inst) ?: continue

                val stringAddr = resolveStringAddress(listing, orrInst) ?: continue

                val stringValue = readStringAt(program, stringAddr) ?: continue

                runCatching {
                    refMgr.addMemoryReference(
                        orrInst.address,
                        stringAddr,
                        RefType.DATA,
                        SourceType.ANALYSIS,
                        0,
                    )
                }.onFailure {
                    Msg.warn(this, "Could not add xref at ${orrInst.address}: ${it.message}")
                }

                runCatching {
                    val codeUnit = program.listing.getCodeUnitAt(inst.address) ?: return@runCatching
                    val comment = "\"$stringValue\""
                    val existing = codeUnit.getComment(ghidra.program.model.listing.CommentType.EOL)
                    if (existing == null || !existing.contains(comment)) {
                        codeUnit.setComment(ghidra.program.model.listing.CommentType.EOL, comment)
                    }
                }.onFailure {
                    Msg.warn(this, "Could not set comment at ${inst.address}: ${it.message}")
                }

                count++
                monitor.message = "Swift bridged strings resolved: $count"
            }
        } catch (_: CancelledException) {
            return false
        }

        monitor.message = "Swift bridged strings resolved: $count"
        return true
    }

    /**
     * Returns true if the instruction is a call to _bridgeToObjectiveC.
     */
    private fun isBridgeToObjectiveC(inst: Instruction): Boolean {
        if (inst.mnemonicString != "bl") return false
        return inst.referencesFrom.any { ref ->
            val sym = inst.program.symbolTable.getPrimarySymbol(ref.toAddress)
            sym?.name?.contains("_bridgeToObjectiveC") == true
        }
    }

    /**
     * Backtracks from [anchor] looking for an ORR instruction that sets bit 63 (Swift tag).
     * Returns the ORR instruction or null if not found within [MAX_BACKTRACK_STEPS].
     */
    private fun findOrrWithSwiftTag(listing: Listing, anchor: Instruction): Instruction? {
        var current = anchor
        repeat(MAX_BACKTRACK_STEPS) {
            current = listing.getInstructionBefore(current.address) ?: return null
            if (current.mnemonicString != "orr") return@repeat
            for (i in 0 until current.numOperands) {
                val scalar = current.getScalar(i) ?: continue
                if ((scalar.unsignedValue and SWIFT_TAG_MASK) != 0L) return current
            }
        }
        return null
    }

    /**
     * Resolves the string address from the adrp+add chain ending at [orrInst].
     * The `sub` instruction, if present, is ignored — see class-level KDoc.
     */
    private fun resolveStringAddress(
        listing: Listing,
        orrInst: Instruction,
    ): Address? {
        val orrSourceReg = orrInst.getRegister(1) ?: return null
        val chain = findAdrpAddSubChain(listing, orrInst, orrSourceReg) ?: return null
        return try {
            chain.pageBase.add(chain.addOffset)
        } catch (_: Exception) {
            null
        }
    }

    private data class AdrpChain(val pageBase: Address, val addOffset: Long)

    /**
     * Walks backwards from [orrInst] looking for the first sub or add that writes to
     * [orrSourceReg], then continues back to find the adrp+add pair.
     * Only handles immediate sub — register-based sub (e.g. sub x8, x8, x12) is skipped.
     * The sub offset value is intentionally discarded.
     */
    private fun findAdrpAddSubChain(
        listing: Listing,
        orrInst: Instruction,
        orrSourceReg: Register,
    ): AdrpChain? {
        var current = orrInst
        for (i in 0 until MAX_BACKTRACK_STEPS) {
            current = listing.getInstructionBefore(current.address) ?: return null
            val mnemonic = current.mnemonicString
            val destReg = current.getRegister(0) ?: continue

            when {
                mnemonic == "sub" && destReg.name == orrSourceReg.name -> {
                    // Skip register-based sub (e.g. sub x8, x8, x12) — not our pattern
                    current.getScalar(2) ?: continue
                    // sub is a Swift ABI artifact — trace back through its source register
                    // but discard the sub offset entirely
                    val subSourceReg = current.getRegister(1) ?: return null
                    val (page, add) = findAdrpAddSequence(listing, current, subSourceReg) ?: return null
                    return AdrpChain(page, add)
                }
                mnemonic == "add" && destReg.name == orrSourceReg.name -> {
                    val addOffset = current.getScalar(2)?.unsignedValue ?: 0L
                    val addSourceReg = current.getRegister(1) ?: return null
                    val adrpInst = findAdrp(listing, current, addSourceReg) ?: return null
                    val page = getAdrpBase(adrpInst) ?: return null
                    return AdrpChain(page, addOffset)
                }
            }
        }
        return null
    }

    /**
     * Finds the ADRP + ADD pair for [reg] searching backwards from [from].
     * Returns (pageBase, addOffset) or null.
     */
    private fun findAdrpAddSequence(
        listing: Listing,
        from: Instruction,
        reg: Register,
    ): Pair<Address, Long>? {
        var addOffset = 0L
        var current = from

        repeat(MAX_BACKTRACK_STEPS) {
            current = listing.getInstructionBefore(current.address) ?: return null
            val mnemonic = current.mnemonicString
            val destReg = current.getRegister(0) ?: return@repeat

            when {
                mnemonic == "add" && destReg.name == reg.name -> {
                    addOffset = current.getScalar(2)?.unsignedValue ?: 0L
                }
                mnemonic == "adrp" && destReg.name == reg.name -> {
                    val page = getAdrpBase(current) ?: return null
                    return Pair(page, addOffset)
                }
            }
        }
        return null
    }

    /**
     * Finds the ADRP instruction for [reg] searching backwards from [from].
     */
    private fun findAdrp(
        listing: Listing,
        from: Instruction,
        reg: Register,
    ): Instruction? {
        var current = from
        repeat(MAX_BACKTRACK_STEPS) {
            current = listing.getInstructionBefore(current.address) ?: return null
            if (current.mnemonicString == "adrp" &&
                current.getRegister(0)?.name == reg.name
            ) return current
        }
        return null
    }

    /**
     * Extracts the resolved page base address from an ADRP instruction.
     * Prefers already-resolved memory references, falls back to scalar.
     */
    private fun getAdrpBase(adrpInst: Instruction): Address? {
        val refs = adrpInst.referencesFrom
        if (refs.isNotEmpty()) return refs.first().toAddress
        val scalar = adrpInst.getScalar(1) ?: return null
        return adrpInst.address.addressSpace.getAddress(scalar.unsignedValue)
    }

    /**
     * Reads the string value at [addr] from the program listing.
     * Returns null if there is no string data there.
     */
    private fun readStringAt(program: Program, addr: Address): String? {
        return runCatching {
            val data = program.listing.getDataAt(addr) ?: return null
            val value = data.value
            if (value is String && value.isNotEmpty()) value else null
        }.getOrNull()
    }
}