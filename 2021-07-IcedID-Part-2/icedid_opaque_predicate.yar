rule icedid_opaque_predicate {
    strings:
        $opaque_predicate = { 8D ?? FF                    // lea REG32, [REG32-1]
                              0F ?? ??                    // imul REG32, REG32
                              83 ?? 01                    // and REG32, 1
                              (74 | 75 | 0F 84 | 0F 85)   // short/far jz/jnz
                            }

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and #opaque_predicate > 10
}
