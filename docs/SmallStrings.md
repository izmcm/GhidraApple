# Small Strings

## Overview

Small strings in Swift are stored **inline** within the `String` structure itself, rather than using dynamic memory allocation. This makes them extremely efficient in terms of performance and memory usage.

## What is a Small String?

A small string is a string that fits entirely within the 16 bytes of Swift's `_StringObject` structure (on 64-bit platforms):

```
struct _StringObject {
  var _countAndFlagsBits: UInt64   // 8 bytes
  var _object: BridgeObject        // 8 bytes
}
```

For small strings, the string content is not stored at a separate memory address - it is stored **directly** within these 16 bytes.

## Practical Example

### Swift Code
```swift
import Foundation
func testSmallString() -> String {
    return "Hi"
}

testSmallString()
```

The function returns the string `"Hi"` (2 characters), which is definitely a small string.

### Compilation and Disassembly
```bash
swiftc -O testStrings.swift -o test
objdump -d test > test_disasm.txt
```

### Assembly Output (ARM64/Apple Silicon)

**Short string `"Hi"` (2 chars):**
```assembly
1000008c8: 528d2908    mov w8, #0x6948             ; =26952
1000008cc: d2fc4009    mov x9, #-0x1e00000000000000 ; =-2161727821137838080
```

**Longer small string `"Hello, World!!!"` (15 chars - maximum capacity):**
```assembly
100000670: d28ca900    	mov	x0, #0x6548             ; =25928
100000674: f2ad8d80    	movk	x0, #0x6c6c, lsl #16
100000678: f2c58de0    	movk	x0, #0x2c6f, lsl #32
10000067c: f2eae400    	movk	x0, #0x5720, lsl #48
100000680: d28e4de1    	mov	x1, #0x726f             ; =29295
100000684: f2ac8d81    	movk	x1, #0x646c, lsl #16
100000688: f2c42421    	movk	x1, #0x2121, lsl #32
10000068c: f2fde421    	movk	x1, #0xef21, lsl #48
100000690: d65f03c0    	ret
```

## Decoding the Assembly

These two ARM64 values encode the small string `"Hi"` in an extremely efficient way:

### First move: `mov w8, #0x6948`
- `0x6948` in hexadecimal = `Hi` in ASCII
  - `0x69` = 'i' (105 in decimal)
  - `0x48` = 'H' (72 in decimal)

This places the string characters directly in a register!

### Second move: `mov x9, #-0x1e00000000000000`
- This value is the **discriminator** that identifies this as a small string
- In binary: `1110 0000 0000...` (high bits)
- The 4 most significant bits (`1110`) indicate:
  - `1` = Immortal (string literal, no ARC needed)
  - `1` = isASCII (all characters are ASCII)
  - `1` = isSmall (it is a small string)
  - `0` = (reserved bit)

### Extended example: `"Hello, World!!!"` (15 characters - MAXIMUM for small strings)

For the maximum-capacity small string, the compiler fills all 16 bytes:

**Register x0 (first 8 bytes: "Hello, W")**
```
mov x0, #0x6548           → x0 = 0x0000000000006548 ("He")
movk x0, #0x6c6c, lsl #16 → x0 = 0x00006c6c6548 ("Hell")
movk x0, #0x2c6f, lsl #32 → x0 = 0x2c6f6c6c6548 ("Hello,")
movk x0, #0x5720, lsl #48 → x0 = 0x5720 2c6f 6c6c 6548 ("Hello, W")
```

Hex breakdown: `48 65 6c 6c 6f 2c 20 57`
ASCII: `H e l l o , (space) W`

**Register x1 (second 8 bytes: "orld!!!" + discriminator)**
```
mov x1, #0x726f           → x1 = 0x000000000000726f ("or")
movk x1, #0x646c, lsl #16 → x1 = 0x0000646c726f ("orld")
movk x1, #0x2121, lsl #32 → x1 = 0x0000212146646c726f ("orld!!")
movk x1, #0xef21, lsl #48 → x1 = 0xef21 2121 646c 726f (orld!!! + discriminator)
```

The `#0xef21` in the high 16 bits contains:
- **Count**: 15 characters encoded in the bits
- **Discriminator bits**: isSmall=1, isASCII=1, isImmortal=1
- **Remaining data**: last character `!` (0x21)

## Memory Layout of a Small String

On 64-bit platforms, the structure of a small string has **15 bytes for content** and uses **only the high nibble of byte 15 for the discriminator**:

```
Byte:   0   1   2   3   4   5   6   7   8   9  10  11  12  13  14   15
       [a] [b] [c] [d] [e] [f] [g] [h] [i] [j] [k] [l] [m] [n] [o] [disc|x]
        ↑                                                      ↑        ↑
        └─────────── 15 characters content ───────────────────┘        └─ discriminator (high 4 bits)
```

For `"Hi"` with padding:
```
Byte:   0   1   2   3   4   5   6   7   8   9  10  11  12  13  14   15
       [H] [i] [?] [?] [?] [?] [?] [?] [?] [?] [?] [?] [?] [?] [?] [E...] 
        ↑   ↑                                                         ↑
    content (2 chars)                                            discriminator bits
```

For `"Hello, World!!!"` (15 characters - MAXIMUM capacity):
```
Byte:   0   1   2   3   4   5   6   7   8   9  10  11  12  13  14   15
       [H] [e] [l] [l] [o] [,] [ ] [W] [o] [r] [l] [d] [!] [!] [!] [E...]
        ↑                                                             ↑
    15 characters content (fully packed)                     discriminator bits
```

Register layout in hexadecimal:
```
x0 = 0x5720 2c6f 6c6c 6548  → "Hello, W" (8 bytes)
x1 = 0xef21 2121 646c 726f  →  "orld!!!" (7 bytes) + discriminator 0xef21 (high nibble = 1110)
```

Discriminator value `0xef21` in binary:
```
0xef21 = 1110 1111 0010 0001
         ╲───┬───╱ ╲────┬────╱
          1110      remaining bits
            ↑
      Discriminator (Immortal + ASCII + Small)
```

The discriminator (high nibble) encodes:
- `1110` = Immortal + ASCII + Small + not Foreign

## Bit Encoding (Discriminator)

Swift uses 4 specific bits to mark the string type:

```
bit 63 (b63): isImmortal   - String literal (no memory management needed)
bit 62 (b62): isASCII      - All characters are ASCII
bit 61 (b61): isSmall      - Is a small string
bit 60 (b60): isForeign    - Cannot provide contiguous UTF-8 access
```

## References

- [Swift String Implementation](https://github.com/apple/swift/blob/main/stdlib/public/core/String.swift)
- [`_StringObject` official documentation (provided in source)](https://github.com/swiftlang/swift/blob/main/stdlib/public/core/StringObject.swift)
- [`_SmallString` official documentation (provided in source)](https://github.com/swiftlang/swift/blob/main/stdlib/public/core/SmallString.swift)

