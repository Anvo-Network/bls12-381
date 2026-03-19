// ARM64/AArch64 assembly for BLS12-381 field arithmetic
// Implements Montgomery multiplication, addition, subtraction, doubling,
// negation, and their lazy (non-reducing) variants for 384-bit field elements.
//
// AAPCS64 calling convention:
//   x0-x7:  argument/result (caller-saved)
//   x8-x17: temporaries (caller-saved)
//   x18:    platform register (MUST NOT USE)
//   x19-x28: callee-saved
//   x29: frame pointer, x30: link register

.text

// Symbol naming: Mach-O prefixes an underscore; ELF does not
#ifdef __APPLE__
  #define GLOBL(name)     .globl _##name
  #define LABEL(name)     _##name:
  #define END_FUNC(name)
#else
  #define GLOBL(name)     .globl name ; .type name, %function
  #define LABEL(name)     name:
  #define END_FUNC(name)  .size name, .-name
#endif

// BLS12-381 field modulus p (little-endian limbs)
// p = 0x1a0111ea397fe69a 4b1ba7b6434bacd7 64774b84f38512bf
//     6730d2a0f6b0f624 1eabfffeb153ffff b9feffffffffaaab
// d[0] = 0xb9feffffffffaaab
// d[1] = 0x1eabfffeb153ffff
// d[2] = 0x6730d2a0f6b0f624
// d[3] = 0x64774b84f38512bf
// d[4] = 0x4b1ba7b6434bacd7
// d[5] = 0x1a0111ea397fe69a

// Montgomery constant INP = 0x89f3fffcfffcfffd

// ─── Macros to load 64-bit constants ────────────────────────────────────

.macro load_mod0 reg
    movz \reg, #0xaaab
    movk \reg, #0xffff, lsl #16
    movk \reg, #0xffff, lsl #32
    movk \reg, #0xb9fe, lsl #48
.endm

.macro load_mod1 reg
    movz \reg, #0xffff
    movk \reg, #0x53ff, lsl #16
    movk \reg, #0xfffe, lsl #32
    movk \reg, #0x1eab, lsl #48
.endm

.macro load_mod2 reg
    movz \reg, #0xf624
    movk \reg, #0xf6b0, lsl #16
    movk \reg, #0xd2a0, lsl #32
    movk \reg, #0x6730, lsl #48
.endm

.macro load_mod3 reg
    movz \reg, #0x12bf
    movk \reg, #0xf385, lsl #16
    movk \reg, #0x4b84, lsl #32
    movk \reg, #0x6477, lsl #48
.endm

.macro load_mod4 reg
    movz \reg, #0xacd7
    movk \reg, #0x434b, lsl #16
    movk \reg, #0xa7b6, lsl #32
    movk \reg, #0x4b1b, lsl #48
.endm

.macro load_mod5 reg
    movz \reg, #0xe69a
    movk \reg, #0x397f, lsl #16
    movk \reg, #0x11ea, lsl #32
    movk \reg, #0x1a01, lsl #48
.endm

.macro load_inp reg
    movz \reg, #0xfffd
    movk \reg, #0xfffc, lsl #16
    movk \reg, #0xfffc, lsl #32
    movk \reg, #0x89f3, lsl #48
.endm

// ─── _ladd: lazy add (no reduction) ────────────────────────────────────
// void bls12_381::_ladd(fp* z, const fp* x, const fp* y)
GLOBL(_ZN9bls12_3815_laddEPNS_2fpEPKS0_S3_)
LABEL(_ZN9bls12_3815_laddEPNS_2fpEPKS0_S3_)
    ldp  x3, x4, [x1]
    ldp  x5, x6, [x1, #16]
    ldp  x7, x8, [x1, #32]
    ldp  x9, x10, [x2]
    ldp  x11, x12, [x2, #16]
    ldp  x13, x14, [x2, #32]
    adds x3, x3, x9
    adcs x4, x4, x10
    adcs x5, x5, x11
    adcs x6, x6, x12
    adcs x7, x7, x13
    adc  x8, x8, x14
    stp  x3, x4, [x0]
    stp  x5, x6, [x0, #16]
    stp  x7, x8, [x0, #32]
    ret
END_FUNC(_ZN9bls12_3815_laddEPNS_2fpEPKS0_S3_)

// ─── _ldouble: lazy double (no reduction) ──────────────────────────────
// void bls12_381::_ldouble(fp* z, const fp* x)
GLOBL(_ZN9bls12_3818_ldoubleEPNS_2fpEPKS0_)
LABEL(_ZN9bls12_3818_ldoubleEPNS_2fpEPKS0_)
    ldp  x3, x4, [x1]
    ldp  x5, x6, [x1, #16]
    ldp  x7, x8, [x1, #32]
    adds x3, x3, x3
    adcs x4, x4, x4
    adcs x5, x5, x5
    adcs x6, x6, x6
    adcs x7, x7, x7
    adc  x8, x8, x8
    stp  x3, x4, [x0]
    stp  x5, x6, [x0, #16]
    stp  x7, x8, [x0, #32]
    ret
END_FUNC(_ZN9bls12_3818_ldoubleEPNS_2fpEPKS0_)

// ─── _lsubtract: lazy subtract (no reduction) ─────────────────────────
// void bls12_381::_lsubtract(fp* z, const fp* x, const fp* y)
GLOBL(_ZN9bls12_38110_lsubtractEPNS_2fpEPKS0_S3_)
LABEL(_ZN9bls12_38110_lsubtractEPNS_2fpEPKS0_S3_)
    ldp  x3, x4, [x1]
    ldp  x5, x6, [x1, #16]
    ldp  x7, x8, [x1, #32]
    ldp  x9, x10, [x2]
    ldp  x11, x12, [x2, #16]
    ldp  x13, x14, [x2, #32]
    subs x3, x3, x9
    sbcs x4, x4, x10
    sbcs x5, x5, x11
    sbcs x6, x6, x12
    sbcs x7, x7, x13
    sbc  x8, x8, x14
    stp  x3, x4, [x0]
    stp  x5, x6, [x0, #16]
    stp  x7, x8, [x0, #32]
    ret
END_FUNC(_ZN9bls12_38110_lsubtractEPNS_2fpEPKS0_S3_)

// ─── _add: modular add (z = x + y mod p) ──────────────────────────────
// void bls12_381::_add(fp* z, const fp* x, const fp* y)
GLOBL(_ZN9bls12_3814_addEPNS_2fpEPKS0_S3_)
LABEL(_ZN9bls12_3814_addEPNS_2fpEPKS0_S3_)
    ldp  x3, x4, [x1]
    ldp  x5, x6, [x1, #16]
    ldp  x7, x8, [x1, #32]
    ldp  x9, x10, [x2]
    ldp  x11, x12, [x2, #16]
    ldp  x13, x14, [x2, #32]
    // z = x + y
    adds x3, x3, x9
    adcs x4, x4, x10
    adcs x5, x5, x11
    adcs x6, x6, x12
    adcs x7, x7, x13
    adc  x8, x8, x14
    // try z - p
    load_mod0 x15
    subs x9, x3, x15
    load_mod1 x15
    sbcs x10, x4, x15
    load_mod2 x15
    sbcs x11, x5, x15
    load_mod3 x15
    sbcs x12, x6, x15
    load_mod4 x15
    sbcs x13, x7, x15
    load_mod5 x15
    sbcs x14, x8, x15
    // if no borrow (carry set), use subtracted result
    csel x3, x9, x3, cs
    csel x4, x10, x4, cs
    csel x5, x11, x5, cs
    csel x6, x12, x6, cs
    csel x7, x13, x7, cs
    csel x8, x14, x8, cs
    stp  x3, x4, [x0]
    stp  x5, x6, [x0, #16]
    stp  x7, x8, [x0, #32]
    ret
END_FUNC(_ZN9bls12_3814_addEPNS_2fpEPKS0_S3_)

// ─── _double: modular double (z = 2*x mod p) ──────────────────────────
// void bls12_381::_double(fp* z, const fp* x)
GLOBL(_ZN9bls12_3817_doubleEPNS_2fpEPKS0_)
LABEL(_ZN9bls12_3817_doubleEPNS_2fpEPKS0_)
    ldp  x3, x4, [x1]
    ldp  x5, x6, [x1, #16]
    ldp  x7, x8, [x1, #32]
    // z = x + x
    adds x3, x3, x3
    adcs x4, x4, x4
    adcs x5, x5, x5
    adcs x6, x6, x6
    adcs x7, x7, x7
    adc  x8, x8, x8
    // try z - p
    load_mod0 x15
    subs x9, x3, x15
    load_mod1 x15
    sbcs x10, x4, x15
    load_mod2 x15
    sbcs x11, x5, x15
    load_mod3 x15
    sbcs x12, x6, x15
    load_mod4 x15
    sbcs x13, x7, x15
    load_mod5 x15
    sbcs x14, x8, x15
    // if no borrow, use subtracted result
    csel x3, x9, x3, cs
    csel x4, x10, x4, cs
    csel x5, x11, x5, cs
    csel x6, x12, x6, cs
    csel x7, x13, x7, cs
    csel x8, x14, x8, cs
    stp  x3, x4, [x0]
    stp  x5, x6, [x0, #16]
    stp  x7, x8, [x0, #32]
    ret
END_FUNC(_ZN9bls12_3817_doubleEPNS_2fpEPKS0_)

// ─── _subtract: modular subtract (z = x - y mod p) ────────────────────
// void bls12_381::_subtract(fp* z, const fp* x, const fp* y)
GLOBL(_ZN9bls12_3819_subtractEPNS_2fpEPKS0_S3_)
LABEL(_ZN9bls12_3819_subtractEPNS_2fpEPKS0_S3_)
    ldp  x3, x4, [x1]
    ldp  x5, x6, [x1, #16]
    ldp  x7, x8, [x1, #32]
    ldp  x9, x10, [x2]
    ldp  x11, x12, [x2, #16]
    ldp  x13, x14, [x2, #32]
    // z = x - y
    subs x3, x3, x9
    sbcs x4, x4, x10
    sbcs x5, x5, x11
    sbcs x6, x6, x12
    sbcs x7, x7, x13
    sbcs x8, x8, x14
    // if borrow (carry clear), conditionally add p
    load_mod0 x15
    csel x15, x15, xzr, cc
    load_mod0 x9           // reload for add (reuse macro)
    csel x9, x9, xzr, cc
    load_mod1 x10
    csel x10, x10, xzr, cc
    load_mod2 x11
    csel x11, x11, xzr, cc
    load_mod3 x12
    csel x12, x12, xzr, cc
    load_mod4 x13
    csel x13, x13, xzr, cc
    load_mod5 x14
    csel x14, x14, xzr, cc
    adds x3, x3, x9
    adcs x4, x4, x10
    adcs x5, x5, x11
    adcs x6, x6, x12
    adcs x7, x7, x13
    adc  x8, x8, x14
    stp  x3, x4, [x0]
    stp  x5, x6, [x0, #16]
    stp  x7, x8, [x0, #32]
    ret
END_FUNC(_ZN9bls12_3819_subtractEPNS_2fpEPKS0_S3_)

// ─── __negate: negate without zero check (z = p - x) ──────────────────
// void bls12_381::__negate(fp* z, const fp* x)
// The C++ wrapper checks isZero() before calling this.
GLOBL(_ZN9bls12_3818__negateEPNS_2fpEPKS0_)
LABEL(_ZN9bls12_3818__negateEPNS_2fpEPKS0_)
    ldp  x3, x4, [x1]
    ldp  x5, x6, [x1, #16]
    ldp  x7, x8, [x1, #32]
    load_mod0 x9
    load_mod1 x10
    load_mod2 x11
    load_mod3 x12
    load_mod4 x13
    load_mod5 x14
    subs x9, x9, x3
    sbcs x10, x10, x4
    sbcs x11, x11, x5
    sbcs x12, x12, x6
    sbcs x13, x13, x7
    sbc  x14, x14, x8
    stp  x9, x10, [x0]
    stp  x11, x12, [x0, #16]
    stp  x13, x14, [x0, #32]
    ret
END_FUNC(_ZN9bls12_3818__negateEPNS_2fpEPKS0_)

// ─── _multiply: Montgomery multiplication (fused CIOS) ─────────────────
// void bls12_381::_multiply(fp* z, const fp* x, const fp* y)
//
// Algorithm: Coarsely Integrated Operand Scanning (CIOS)
// Fuses multiplication and Montgomery reduction in each round.
// 6 rounds, each interleaving v*y[j] and m*MODULUS[j].
// Only needs a 6-limb accumulator t[0..5] plus carry registers.
//
// Register allocation:
//   x19 = saved z pointer
//   x20 = saved y pointer
//   x21-x26 = MODULUS limbs (callee-saved, loaded once)
//   x27 = INP constant
//   x28 = saved x pointer
//   x3-x8 = t[0]-t[5] accumulator
//   x9 = c[0], x10 = c[1], x11 = c[2] (carry registers)
//   x12 = v (current x[i])
//   x13 = m (Montgomery factor)
//   x14-x17 = temporaries for mul/umulh results
GLOBL(_ZN9bls12_3819_multiplyEPNS_2fpEPKS0_S3_)
LABEL(_ZN9bls12_3819_multiplyEPNS_2fpEPKS0_S3_)
    // Save callee-saved registers
    stp  x29, x30, [sp, #-16]!
    stp  x19, x20, [sp, #-16]!
    stp  x21, x22, [sp, #-16]!
    stp  x23, x24, [sp, #-16]!
    stp  x25, x26, [sp, #-16]!
    stp  x27, x28, [sp, #-16]!

    mov  x19, x0          // save z
    mov  x28, x1          // save x
    mov  x20, x2          // save y

    // Load modulus into callee-saved registers
    load_mod0 x21
    load_mod1 x22
    load_mod2 x23
    load_mod3 x24
    load_mod4 x25
    load_mod5 x26
    load_inp  x27

    // Zero the accumulator t[0..5]
    mov  x3, xzr           // t[0]
    mov  x4, xzr           // t[1]
    mov  x5, xzr           // t[2]
    mov  x6, xzr           // t[3]
    mov  x7, xzr           // t[4]
    mov  x8, xzr           // t[5]

    // ════════════════════════════════════════════════════════════════════
    // Round 0:  v = x[0]
    // ════════════════════════════════════════════════════════════════════
    ldr  x12, [x28]        // v = x->d[0]

    // (c[1], c[0]) = v * y[0]     (+ t[0], but t[0]=0 in round 0)
    ldr  x14, [x20]        // y[0]
    mul  x9, x12, x14      // c[0] = lo(v * y[0])
    umulh x10, x12, x14    // c[1] = hi(v * y[0])

    // m = c[0] * INP
    mul  x13, x9, x27

    // c[2] = madd0(m, MODULUS[0], c[0])  -- hi of (m*mod[0] + c[0]), lo discarded
    mul  x14, x13, x21
    umulh x11, x13, x21
    adds x14, x14, x9      // lo + c[0] (lo discarded, carry into hi)
    adc  x11, x11, xzr     // c[2] = hi + carry

    // (c[1], c[0]) = madd1(v, y[1], c[1])  =>  (hi,lo) = v*y[1] + c[1]
    ldr  x14, [x20, #8]    // y[1]
    mul  x15, x12, x14
    umulh x16, x12, x14
    adds x9, x15, x10      // c[0] = lo(v*y[1]) + c[1]
    adc  x10, x16, xzr     // c[1] = hi(v*y[1]) + carry

    // (c[2], t[0]) = madd2(m, MODULUS[1], c[2], c[0])  =>  (hi,lo) = m*mod[1] + c[2] + c[0]
    mul  x15, x13, x22
    umulh x16, x13, x22
    adds x15, x15, x11     // lo(m*mod[1]) + c[2]
    adc  x16, x16, xzr     // hi + carry
    adds x3, x15, x9       // t[0] = above + c[0]
    adc  x11, x16, xzr     // c[2] = hi + carry

    // (c[1], c[0]) = madd1(v, y[2], c[1])
    ldr  x14, [x20, #16]   // y[2]
    mul  x15, x12, x14
    umulh x16, x12, x14
    adds x9, x15, x10      // c[0] = lo + c[1]
    adc  x10, x16, xzr     // c[1] = hi + carry

    // (c[2], t[1]) = madd2(m, MODULUS[2], c[2], c[0])
    mul  x15, x13, x23
    umulh x16, x13, x23
    adds x15, x15, x11
    adc  x16, x16, xzr
    adds x4, x15, x9       // t[1]
    adc  x11, x16, xzr     // c[2]

    // (c[1], c[0]) = madd1(v, y[3], c[1])
    ldr  x14, [x20, #24]   // y[3]
    mul  x15, x12, x14
    umulh x16, x12, x14
    adds x9, x15, x10
    adc  x10, x16, xzr

    // (c[2], t[2]) = madd2(m, MODULUS[3], c[2], c[0])
    mul  x15, x13, x24
    umulh x16, x13, x24
    adds x15, x15, x11
    adc  x16, x16, xzr
    adds x5, x15, x9       // t[2]
    adc  x11, x16, xzr     // c[2]

    // (c[1], c[0]) = madd1(v, y[4], c[1])
    ldr  x14, [x20, #32]   // y[4]
    mul  x15, x12, x14
    umulh x16, x12, x14
    adds x9, x15, x10
    adc  x10, x16, xzr

    // (c[2], t[3]) = madd2(m, MODULUS[4], c[2], c[0])
    mul  x15, x13, x25
    umulh x16, x13, x25
    adds x15, x15, x11
    adc  x16, x16, xzr
    adds x6, x15, x9       // t[3]
    adc  x11, x16, xzr     // c[2]

    // (c[1], c[0]) = madd1(v, y[5], c[1])
    ldr  x14, [x20, #40]   // y[5]
    mul  x15, x12, x14
    umulh x16, x12, x14
    adds x9, x15, x10      // c[0]
    adc  x10, x16, xzr     // c[1]

    // (t[5], t[4]) = madd3(m, MODULUS[5], c[0], c[2], c[1])
    // madd3(a,b,c,d,e): (hi,lo) = a*b + (c+d) + e  (carry from c+d goes to hi)
    mul  x15, x13, x26
    umulh x16, x13, x26
    adds x14, x9, x11      // c[0] + c[2]
    adc  x17, xzr, xzr     // carry from c[0]+c[2]
    adds x7, x15, x14      // t[4] = lo(m*mod[5]) + (c[0]+c[2])
    adc  x16, x16, x17     // hi + carry_from_cd + carry_from_lo
    add  x8, x16, x10      // t[5] = hi + c[1]  -- no further overflow in CIOS

    // ════════════════════════════════════════════════════════════════════
    // CIOS round macro for rounds 1-5.
    // Inputs: xi_off = byte offset of x[i]
    // Uses and updates t[0..5] in x3..x8.
    // ════════════════════════════════════════════════════════════════════
.macro cios_round xi_off
    ldr  x12, [x28, #\xi_off]  // v = x->d[i]

    // (c[1], c[0]) = madd1(v, y[0], t[0])  =>  (hi,lo) = v*y[0] + t[0]
    ldr  x14, [x20]        // y[0]
    mul  x15, x12, x14
    umulh x16, x12, x14
    adds x9, x15, x3       // c[0] = lo(v*y[0]) + t[0]
    adc  x10, x16, xzr     // c[1] = hi + carry

    // m = c[0] * INP
    mul  x13, x9, x27

    // c[2] = madd0(m, MODULUS[0], c[0])
    mul  x14, x13, x21
    umulh x11, x13, x21
    adds x14, x14, x9      // lo + c[0] (lo discarded)
    adc  x11, x11, xzr     // c[2]

    // (c[1], c[0]) = madd2(v, y[1], c[1], t[1])  =>  (hi,lo) = v*y[1] + c[1] + t[1]
    ldr  x14, [x20, #8]
    mul  x15, x12, x14
    umulh x16, x12, x14
    adds x15, x15, x10     // lo(v*y[1]) + c[1]
    adc  x16, x16, xzr
    adds x9, x15, x4       // c[0] = above + t[1]
    adc  x10, x16, xzr     // c[1]

    // (c[2], t[0]) = madd2(m, MODULUS[1], c[2], c[0])
    mul  x15, x13, x22
    umulh x16, x13, x22
    adds x15, x15, x11
    adc  x16, x16, xzr
    adds x3, x15, x9       // t[0]
    adc  x11, x16, xzr     // c[2]

    // (c[1], c[0]) = madd2(v, y[2], c[1], t[2])
    ldr  x14, [x20, #16]
    mul  x15, x12, x14
    umulh x16, x12, x14
    adds x15, x15, x10
    adc  x16, x16, xzr
    adds x9, x15, x5       // c[0] = lo + t[2]
    adc  x10, x16, xzr     // c[1]

    // (c[2], t[1]) = madd2(m, MODULUS[2], c[2], c[0])
    mul  x15, x13, x23
    umulh x16, x13, x23
    adds x15, x15, x11
    adc  x16, x16, xzr
    adds x4, x15, x9       // t[1]
    adc  x11, x16, xzr     // c[2]

    // (c[1], c[0]) = madd2(v, y[3], c[1], t[3])
    ldr  x14, [x20, #24]
    mul  x15, x12, x14
    umulh x16, x12, x14
    adds x15, x15, x10
    adc  x16, x16, xzr
    adds x9, x15, x6
    adc  x10, x16, xzr

    // (c[2], t[2]) = madd2(m, MODULUS[3], c[2], c[0])
    mul  x15, x13, x24
    umulh x16, x13, x24
    adds x15, x15, x11
    adc  x16, x16, xzr
    adds x5, x15, x9       // t[2]
    adc  x11, x16, xzr     // c[2]

    // (c[1], c[0]) = madd2(v, y[4], c[1], t[4])
    ldr  x14, [x20, #32]
    mul  x15, x12, x14
    umulh x16, x12, x14
    adds x15, x15, x10
    adc  x16, x16, xzr
    adds x9, x15, x7
    adc  x10, x16, xzr

    // (c[2], t[3]) = madd2(m, MODULUS[4], c[2], c[0])
    mul  x15, x13, x25
    umulh x16, x13, x25
    adds x15, x15, x11
    adc  x16, x16, xzr
    adds x6, x15, x9       // t[3]
    adc  x11, x16, xzr     // c[2]

    // (c[1], c[0]) = madd2(v, y[5], c[1], t[5])
    ldr  x14, [x20, #40]
    mul  x15, x12, x14
    umulh x16, x12, x14
    adds x15, x15, x10
    adc  x16, x16, xzr
    adds x9, x15, x8       // c[0]
    adc  x10, x16, xzr     // c[1]

    // (t[5], t[4]) = madd3(m, MODULUS[5], c[0], c[2], c[1])
    mul  x15, x13, x26
    umulh x16, x13, x26
    adds x14, x9, x11      // c[0] + c[2]
    adc  x17, xzr, xzr     // carry from c[0]+c[2]
    adds x7, x15, x14      // t[4] = lo(m*mod[5]) + (c[0]+c[2])
    adc  x16, x16, x17     // hi + carry_from_cd
    add  x8, x16, x10      // t[5] = hi + c[1]
.endm

    // Round 1
    cios_round 8
    // Round 2
    cios_round 16
    // Round 3
    cios_round 24
    // Round 4
    cios_round 32
    // Round 5
    cios_round 40

    // ── Conditional subtraction ──
    // if t >= p, subtract p
    subs x9, x3, x21       // t[0] - mod[0]
    sbcs x10, x4, x22
    sbcs x11, x5, x23
    sbcs x12, x6, x24
    sbcs x14, x7, x25
    sbcs x15, x8, x26

    // if no borrow (carry set), use subtracted result
    csel x3, x9, x3, cs
    csel x4, x10, x4, cs
    csel x5, x11, x5, cs
    csel x6, x12, x6, cs
    csel x7, x14, x7, cs
    csel x8, x15, x8, cs

    // Store result
    stp  x3, x4, [x19]
    stp  x5, x6, [x19, #16]
    stp  x7, x8, [x19, #32]

    // Restore callee-saved registers
    ldp  x27, x28, [sp], #16
    ldp  x25, x26, [sp], #16
    ldp  x23, x24, [sp], #16
    ldp  x21, x22, [sp], #16
    ldp  x19, x20, [sp], #16
    ldp  x29, x30, [sp], #16
    ret
END_FUNC(_ZN9bls12_3819_multiplyEPNS_2fpEPKS0_S3_)

// ─── Non-executable stack ──────────────────────────────────────────────
#ifndef __APPLE__
.section .note.GNU-stack,"",@progbits
#endif
