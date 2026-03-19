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

// ─── _multiply: Montgomery multiplication ──────────────────────────────
// void bls12_381::_multiply(fp* z, const fp* x, const fp* y)
//
// Algorithm: schoolbook 6x6 multiply producing 12 limbs,
// then 6 rounds of Montgomery reduction, then conditional subtraction.
// This matches the x86_64 __multiply implementation.
//
// Register allocation:
//   x19 = saved z pointer
//   x20 = saved y pointer
//   x21-x26 = modulus limbs (loaded once)
//   x27 = INP constant
//   x28 = saved x pointer
//   r0-r11 (product limbs) stored on stack between phases
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

    // Load modulus into callee-saved registers (used in reduction phase)
    load_mod0 x21
    load_mod1 x22
    load_mod2 x23
    load_mod3 x24
    load_mod4 x25
    load_mod5 x26
    load_inp  x27

    // ── Phase 1: Schoolbook 6x6 multiplication ──
    // Product limbs: t0..t11 (768 bits)
    // We accumulate into registers and spill lower limbs to stack

    // Allocate stack space for the 12 product limbs
    sub  sp, sp, #96       // 12 * 8 bytes

    // Zero accumulators
    mov  x3, xzr           // t0
    mov  x4, xzr           // t1
    mov  x5, xzr           // t2
    mov  x6, xzr           // t3
    mov  x7, xzr           // t4
    mov  x8, xzr           // t5
    mov  x9, xzr           // t6
    mov  x10, xzr          // t7
    mov  x11, xzr          // t8
    mov  x12, xzr          // t9
    mov  x13, xzr          // t10
    mov  x14, xzr          // t11

    // ── i=0: x[0] * y[0..5] ──
    ldr  x15, [x28]        // x[0]
    ldr  x16, [x20]        // y[0]
    mul  x3, x15, x16
    umulh x4, x15, x16
    ldr  x16, [x20, #8]    // y[1]
    mul  x17, x15, x16
    umulh x0, x15, x16
    adds x4, x4, x17
    adc  x5, x5, x0
    ldr  x16, [x20, #16]   // y[2]
    mul  x17, x15, x16
    umulh x0, x15, x16
    adds x5, x5, x17
    adc  x6, x6, x0
    ldr  x16, [x20, #24]   // y[3]
    mul  x17, x15, x16
    umulh x0, x15, x16
    adds x6, x6, x17
    adc  x7, x7, x0
    ldr  x16, [x20, #32]   // y[4]
    mul  x17, x15, x16
    umulh x0, x15, x16
    adds x7, x7, x17
    adc  x8, x8, x0
    ldr  x16, [x20, #40]   // y[5]
    mul  x17, x15, x16
    umulh x0, x15, x16
    adds x8, x8, x17
    adc  x9, x9, x0

    // Store t0, keep t1..t6+ in regs
    str  x3, [sp]          // t0 -> stack

    // ── i=1: x[1] * y[0..5], accumulate into t1..t7 ──
    ldr  x15, [x28, #8]    // x[1]
    ldr  x16, [x20]        // y[0]
    mul  x17, x15, x16
    umulh x0, x15, x16
    adds x4, x4, x17
    adcs x5, x5, x0
    adc  x3, xzr, xzr      // carry
    ldr  x16, [x20, #8]
    mul  x17, x15, x16
    umulh x0, x15, x16
    adds x5, x5, x17
    adcs x6, x6, x0
    adc  x1, xzr, xzr
    add  x6, x6, x3        // delayed carry
    ldr  x16, [x20, #16]
    mul  x17, x15, x16
    umulh x0, x15, x16
    adds x6, x6, x17
    adcs x7, x7, x0
    adc  x3, xzr, xzr
    add  x7, x7, x1
    ldr  x16, [x20, #24]
    mul  x17, x15, x16
    umulh x0, x15, x16
    adds x7, x7, x17
    adcs x8, x8, x0
    adc  x1, xzr, xzr
    add  x8, x8, x3
    ldr  x16, [x20, #32]
    mul  x17, x15, x16
    umulh x0, x15, x16
    adds x8, x8, x17
    adcs x9, x9, x0
    adc  x3, xzr, xzr
    add  x9, x9, x1
    ldr  x16, [x20, #40]
    mul  x17, x15, x16
    umulh x0, x15, x16
    adds x9, x9, x17
    adc  x10, x10, x0
    add  x10, x10, x3

    str  x4, [sp, #8]      // t1 -> stack

    // ── i=2..5: same pattern ──
    // For brevity and correctness, use a cleaner accumulation pattern.
    // We reload the approach: for each i, multiply x[i] by all y[j],
    // adding into the running product with careful carry propagation.

.macro mul_acc_round xi_off, store_off, acc0, acc1, acc2, acc3, acc4, acc5, acc6
    ldr  x15, [x28, #\xi_off]
    // y[0]
    ldr  x16, [x20]
    mul  x17, x15, x16
    umulh x0, x15, x16
    adds \acc0, \acc0, x17
    adcs \acc1, \acc1, x0
    adc  x3, xzr, xzr
    // y[1]
    ldr  x16, [x20, #8]
    mul  x17, x15, x16
    umulh x0, x15, x16
    adds \acc1, \acc1, x17
    adcs \acc2, \acc2, x0
    adc  x1, xzr, xzr
    adds \acc2, \acc2, x3
    adc  x1, x1, xzr
    // y[2]
    ldr  x16, [x20, #16]
    mul  x17, x15, x16
    umulh x0, x15, x16
    adds \acc2, \acc2, x17
    adcs \acc3, \acc3, x0
    adc  x3, xzr, xzr
    adds \acc3, \acc3, x1
    adc  x3, x3, xzr
    // y[3]
    ldr  x16, [x20, #24]
    mul  x17, x15, x16
    umulh x0, x15, x16
    adds \acc3, \acc3, x17
    adcs \acc4, \acc4, x0
    adc  x1, xzr, xzr
    adds \acc4, \acc4, x3
    adc  x1, x1, xzr
    // y[4]
    ldr  x16, [x20, #32]
    mul  x17, x15, x16
    umulh x0, x15, x16
    adds \acc4, \acc4, x17
    adcs \acc5, \acc5, x0
    adc  x3, xzr, xzr
    adds \acc5, \acc5, x1
    adc  x3, x3, xzr
    // y[5]
    ldr  x16, [x20, #40]
    mul  x17, x15, x16
    umulh x0, x15, x16
    adds \acc5, \acc5, x17
    adcs \acc6, \acc6, x0
    add  \acc6, \acc6, x3
    // store lowest accumulator
    str  \acc0, [sp, #\store_off]
.endm

    // i=2: acc in x5,x6,x7,x8,x9,x10,x11
    mul_acc_round 16, 16, x5, x6, x7, x8, x9, x10, x11
    // i=3: acc in x6,x7,x8,x9,x10,x11,x12
    mul_acc_round 24, 24, x6, x7, x8, x9, x10, x11, x12
    // i=4: acc in x7,x8,x9,x10,x11,x12,x13
    mul_acc_round 32, 32, x7, x8, x9, x10, x11, x12, x13
    // i=5: acc in x8,x9,x10,x11,x12,x13,x14
    mul_acc_round 40, 40, x8, x9, x10, x11, x12, x13, x14

    // Product limbs t0..t5 are on stack [sp..sp+40]
    // t6..t11 are in x9, x10, x11, x12, x13, x14

    // Store remaining limbs to stack
    str  x9,  [sp, #48]
    str  x10, [sp, #56]
    str  x11, [sp, #64]
    str  x12, [sp, #72]
    str  x13, [sp, #80]
    str  x14, [sp, #88]

    // ── Phase 2: Montgomery reduction ──
    // Load all 12 product limbs into registers for reduction
    // We need: t0..t5 for lower half, t6..t11 for upper half
    ldp  x3, x4, [sp]      // t0, t1
    ldp  x5, x6, [sp, #16] // t2, t3
    ldp  x7, x8, [sp, #32] // t4, t5
    ldp  x9, x10, [sp, #48]  // t6, t7
    ldp  x11, x12, [sp, #64] // t8, t9
    ldp  x13, x14, [sp, #72] // t10, t11
    // Fix: reload properly
    ldr  x13, [sp, #80]    // t10
    ldr  x14, [sp, #88]    // t11

    // Free stack space
    add  sp, sp, #96

    // Montgomery reduction: 6 rounds
    // Each round: m = t_low * INP (mod 2^64), then t += m * MODULUS, shift right by 64 bits

    // ── Reduction round macro ──
    // Input: lowest limb in \tlow. After round, \tlow is consumed and
    // the accumulator shifts up.
.macro mont_round tlow, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11
    // m = tlow * INP
    mul  x15, \tlow, x27

    // tlow += m * mod[0] (result is 0 mod 2^64, carry propagates)
    mul  x16, x15, x21
    umulh x17, x15, x21
    adds \tlow, \tlow, x16  // zeroes out tlow
    adc  x0, x17, xzr

    // t1 += m * mod[1] + carry
    mul  x16, x15, x22
    umulh x17, x15, x22
    adds \t1, \t1, x16
    adc  x17, x17, xzr
    adds \t1, \t1, x0
    adc  x0, x17, xzr

    // t2 += m * mod[2] + carry
    mul  x16, x15, x23
    umulh x17, x15, x23
    adds \t2, \t2, x16
    adc  x17, x17, xzr
    adds \t2, \t2, x0
    adc  x0, x17, xzr

    // t3 += m * mod[3] + carry
    mul  x16, x15, x24
    umulh x17, x15, x24
    adds \t3, \t3, x16
    adc  x17, x17, xzr
    adds \t3, \t3, x0
    adc  x0, x17, xzr

    // t4 += m * mod[4] + carry
    mul  x16, x15, x25
    umulh x17, x15, x25
    adds \t4, \t4, x16
    adc  x17, x17, xzr
    adds \t4, \t4, x0
    adc  x0, x17, xzr

    // t5 += m * mod[5] + carry (propagates into t6)
    mul  x16, x15, x26
    umulh x17, x15, x26
    adds \t5, \t5, x16
    adc  x17, x17, xzr
    adds \t5, \t5, x0
    adcs \t6, \t6, x17
    // carry propagates through remaining upper limbs
    adcs \t7, \t7, xzr
    adcs \t8, \t8, xzr
    adcs \t9, \t9, xzr
    adcs \t10, \t10, xzr
    adc  \t11, \t11, xzr
.endm

    // Round 0: consume t0 (x3)
    mont_round x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14
    // Round 1: consume t1 (x4)
    mont_round x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x3
    // Round 2: consume t2 (x5)
    mont_round x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x3, x4
    // Round 3: consume t3 (x6)
    mont_round x6, x7, x8, x9, x10, x11, x12, x13, x14, x3, x4, x5
    // Round 4: consume t4 (x7)
    mont_round x7, x8, x9, x10, x11, x12, x13, x14, x3, x4, x5, x6
    // Round 5: consume t5 (x8)
    mont_round x8, x9, x10, x11, x12, x13, x14, x3, x4, x5, x6, x7

    // After 6 rounds, result is in x9, x10, x11, x12, x13, x14
    // (the registers that were t6..t11, now shifted down)

    // ── Phase 3: Conditional subtraction ──
    // if result >= p, subtract p
    subs x3, x9, x21       // result[0] - mod[0]
    sbcs x4, x10, x22
    sbcs x5, x11, x23
    sbcs x6, x12, x24
    sbcs x7, x13, x25
    sbcs x8, x14, x26

    // if no borrow (carry set), use subtracted result
    csel x9, x3, x9, cs
    csel x10, x4, x10, cs
    csel x11, x5, x11, cs
    csel x12, x6, x12, cs
    csel x13, x7, x13, cs
    csel x14, x8, x14, cs

    // Store result
    stp  x9, x10, [x19]
    stp  x11, x12, [x19, #16]
    stp  x13, x14, [x19, #32]

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
