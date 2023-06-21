R"********(
#ifndef _UAPI__LINUX_LINUX_H__
#define _UAPI__LINUX_LINUX_H__

// START COPIED FROM LINUX
// these macros/types/functions are copied from Linux, specifically from x86_64 where arch is
// of relevance.

#define __always_inline __attribute__((always_inline))

#define BITS_PER_LONG 64

typedef __signed__ char __s8;
typedef unsigned char __u8;
typedef __u8 u8;
typedef __u8 uint8_t;
typedef __signed__ short __s16;
typedef __s16 s16;
typedef __s16 int16_t;
typedef unsigned short __u16;
typedef __u16 u16;
typedef __u16 uint16_t;
typedef __signed__ int __s32;
typedef __s32 s32;
typedef __s32 int32_t;
typedef unsigned int __u32;
typedef unsigned long size_t;
typedef long ssize_t;
typedef unsigned long uintptr_t;
__extension__ typedef __signed__ long long __s64;
__extension__ typedef unsigned long long __u64;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __le32;
typedef __u32 u32;
typedef __u32 uint32_t;
typedef __u32 __be32;
typedef __u64 __le64;
typedef __u64 __be64;
typedef __u16 __sum16;
typedef __u32 __wsum;
typedef unsigned __poll_t;
typedef __u64 u64;
typedef __u64 uint64_t;
typedef __s64 s64;
typedef __s64 int64_t;
typedef int pid_t;
typedef int bool;

#define __aligned_u64 __u64 __attribute__((aligned(8)))

#define NULL ((void*)0)
#define ENOSPC 28

#if defined(__x86_64__)

#define PAGE_SIZE 4096
#define PAGE_MASK (~(PAGE_SIZE-1))
#define THREAD_SIZE_ORDER 2
#define THREAD_SIZE (PAGE_SIZE << THREAD_SIZE_ORDER)
#define TOP_OF_KERNEL_STACK_PADDING 0

struct pt_regs {
/*
 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
 * unless syscall needs a complete, fully filled "struct pt_regs".
 */
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;
    unsigned long bx;
/* These regs are callee-clobbered. Always saved on kernel entry. */
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;
    unsigned long cx;
    unsigned long dx;
    unsigned long si;
    unsigned long di;
/*
 * On syscall entry, this is syscall#. On CPU exception, this is error code.
 * On hw interrupt, it's IRQ number:
 */
    unsigned long orig_ax;
/* Return frame for iretq */
    unsigned long ip;
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;
    unsigned long ss;
/* top of stack page */
};

#elif defined(__aarch64__)

#define PSR_MODE_EL0t   0x00000000
#define PSR_MODE_MASK   0x0000000f

#define PAGE_SIZE 4096 // on all systems I saw, CONFIG_ARM64_PAGE_SHIFT=12
#define PAGE_MASK (~(PAGE_SIZE-1))

#define KASAN_THREAD_SHIFT  0
#define MIN_THREAD_SHIFT    (14 + KASAN_THREAD_SHIFT)
// if CONFIG_VMAP_STACK is enabled & PAGE_SHIFT is 12, then this path gets selected:
#define THREAD_SHIFT        MIN_THREAD_SHIFT
#define THREAD_SIZE  (1UL << THREAD_SHIFT)

struct user_pt_regs {
    __u64       regs[31];
    __u64       sp;
    __u64       pc;
    __u64       pstate;
};

// this changes!
// this copy is from 5.16.0
struct pt_regs {
    union {
        struct user_pt_regs user_regs;
        struct {
            u64 regs[31];
            u64 sp;
            u64 pc;
            u64 pstate;
        };
    };
    u64 orig_x0;
#ifdef __AARCH64EB__
    u32 unused2;
    s32 syscallno;
#else
    s32 syscallno;
    u32 unused2;
#endif
    u64 sdei_ttbr1;
    /* Only valid when ARM64_HAS_IRQ_PRIO_MASKING is enabled. */
    u64 pmr_save;
    u64 stackframe[2];

    /* Only valid for some EL1 exceptions. */
    u64 lockdep_hardirqs;
    u64 exit_rcu;
};

#endif

# ifndef likely
#  define likely(x) __builtin_expect(x, 1)
# endif
# ifndef unlikely
#  define unlikely(x) __builtin_expect(x, 0)
# endif

static __always_inline unsigned long __fls(unsigned long word)
{
    int num = BITS_PER_LONG - 1;

#if BITS_PER_LONG == 64
    if (!(word & (~0ul << 32))) {
        num -= 32;
        word <<= 32;
    }
#endif
    if (!(word & (~0ul << (BITS_PER_LONG-16)))) {
        num -= 16;
        word <<= 16;
    }
    if (!(word & (~0ul << (BITS_PER_LONG-8)))) {
        num -= 8;
        word <<= 8;
    }
    if (!(word & (~0ul << (BITS_PER_LONG-4)))) {
        num -= 4;
        word <<= 4;
    }
    if (!(word & (~0ul << (BITS_PER_LONG-2)))) {
        num -= 2;
        word <<= 2;
    }
    if (!(word & (~0ul << (BITS_PER_LONG-1))))
        num -= 1;
    return num;
}

static __always_inline int fls(unsigned int x)
{
    int r = 32;

    if (!x)
        return 0;
    if (!(x & 0xffff0000u)) {
        x <<= 16;
        r -= 16;
    }
    if (!(x & 0xff000000u)) {
        x <<= 8;
        r -= 8;
    }
    if (!(x & 0xf0000000u)) {
        x <<= 4;
        r -= 4;
    }
    if (!(x & 0xc0000000u)) {
        x <<= 2;
        r -= 2;
    }
    if (!(x & 0x80000000u)) {
        x <<= 1;
        r -= 1;
    }
    return r;
}

static __always_inline int fls64(__u64 x)
{
    if (x == 0)
        return 0;
    return __fls(x) + 1;
}

static inline __attribute__((const))
int __ilog2_u32(u32 n)
{
    return fls(n) - 1;
}

static inline __attribute__((const))
int __ilog2_u64(u64 n)
{
    return fls64(n) - 1;
}

static inline unsigned fls_long(unsigned long l)
{
    if (sizeof(l) == 4)
        return fls(l);
    return fls64(l);
}

static inline __attribute__((const))
unsigned long __roundup_pow_of_two(unsigned long n)
{
    return 1UL << fls_long(n - 1);
}

/**
 * __rounddown_pow_of_two() - round down to nearest power of two
 * @n: value to round down
 */
static inline __attribute__((const))
unsigned long __rounddown_pow_of_two(unsigned long n)
{
    return 1UL << (fls_long(n) - 1);
}

/**
 * const_ilog2 - log base 2 of 32-bit or a 64-bit constant unsigned value
 * @n: parameter
 *
 * Use this where sparse expects a true constant expression, e.g. for array
 * indices.
 */
#define const_ilog2(n)              \
(                       \
    __builtin_constant_p(n) ? (     \
        (n) < 2 ? 0 :           \
        (n) & (1ULL << 63) ? 63 :   \
        (n) & (1ULL << 62) ? 62 :   \
        (n) & (1ULL << 61) ? 61 :   \
        (n) & (1ULL << 60) ? 60 :   \
        (n) & (1ULL << 59) ? 59 :   \
        (n) & (1ULL << 58) ? 58 :   \
        (n) & (1ULL << 57) ? 57 :   \
        (n) & (1ULL << 56) ? 56 :   \
        (n) & (1ULL << 55) ? 55 :   \
        (n) & (1ULL << 54) ? 54 :   \
        (n) & (1ULL << 53) ? 53 :   \
        (n) & (1ULL << 52) ? 52 :   \
        (n) & (1ULL << 51) ? 51 :   \
        (n) & (1ULL << 50) ? 50 :   \
        (n) & (1ULL << 49) ? 49 :   \
        (n) & (1ULL << 48) ? 48 :   \
        (n) & (1ULL << 47) ? 47 :   \
        (n) & (1ULL << 46) ? 46 :   \
        (n) & (1ULL << 45) ? 45 :   \
        (n) & (1ULL << 44) ? 44 :   \
        (n) & (1ULL << 43) ? 43 :   \
        (n) & (1ULL << 42) ? 42 :   \
        (n) & (1ULL << 41) ? 41 :   \
        (n) & (1ULL << 40) ? 40 :   \
        (n) & (1ULL << 39) ? 39 :   \
        (n) & (1ULL << 38) ? 38 :   \
        (n) & (1ULL << 37) ? 37 :   \
        (n) & (1ULL << 36) ? 36 :   \
        (n) & (1ULL << 35) ? 35 :   \
        (n) & (1ULL << 34) ? 34 :   \
        (n) & (1ULL << 33) ? 33 :   \
        (n) & (1ULL << 32) ? 32 :   \
        (n) & (1ULL << 31) ? 31 :   \
        (n) & (1ULL << 30) ? 30 :   \
        (n) & (1ULL << 29) ? 29 :   \
        (n) & (1ULL << 28) ? 28 :   \
        (n) & (1ULL << 27) ? 27 :   \
        (n) & (1ULL << 26) ? 26 :   \
        (n) & (1ULL << 25) ? 25 :   \
        (n) & (1ULL << 24) ? 24 :   \
        (n) & (1ULL << 23) ? 23 :   \
        (n) & (1ULL << 22) ? 22 :   \
        (n) & (1ULL << 21) ? 21 :   \
        (n) & (1ULL << 20) ? 20 :   \
        (n) & (1ULL << 19) ? 19 :   \
        (n) & (1ULL << 18) ? 18 :   \
        (n) & (1ULL << 17) ? 17 :   \
        (n) & (1ULL << 16) ? 16 :   \
        (n) & (1ULL << 15) ? 15 :   \
        (n) & (1ULL << 14) ? 14 :   \
        (n) & (1ULL << 13) ? 13 :   \
        (n) & (1ULL << 12) ? 12 :   \
        (n) & (1ULL << 11) ? 11 :   \
        (n) & (1ULL << 10) ? 10 :   \
        (n) & (1ULL <<  9) ?  9 :   \
        (n) & (1ULL <<  8) ?  8 :   \
        (n) & (1ULL <<  7) ?  7 :   \
        (n) & (1ULL <<  6) ?  6 :   \
        (n) & (1ULL <<  5) ?  5 :   \
        (n) & (1ULL <<  4) ?  4 :   \
        (n) & (1ULL <<  3) ?  3 :   \
        (n) & (1ULL <<  2) ?  2 :   \
        1) :                \
    -1)

/**
 * ilog2 - log base 2 of 32-bit or a 64-bit unsigned value
 * @n: parameter
 *
 * constant-capable log of base 2 calculation
 * - this can be used to initialise global variables from constant data, hence
 * the massive ternary operator construction
 *
 * selects the appropriately-sized optimised version depending on sizeof(n)
 */
#define ilog2(n) \
( \
    __builtin_constant_p(n) ?   \
    const_ilog2(n) :        \
    (sizeof(n) <= 4) ?      \
    __ilog2_u32(n) :        \
    __ilog2_u64(n)          \
 )

/**
 * roundup_pow_of_two - round the given value up to nearest power of two
 * @n: parameter
 *
 * round the given value up to the nearest power of two
 * - the result is undefined when n == 0
 * - this can be used to initialise global variables from constant data
 */
#define roundup_pow_of_two(n)           \
(                       \
    __builtin_constant_p(n) ? (     \
        (n == 1) ? 1 :          \
        (1UL << (ilog2((n) - 1) + 1))   \
                   ) :      \
    __roundup_pow_of_two(n)         \
 )

// END COPIED FROM LINUX
#endif // _UAPI__LINUX_LINUX_H__
)********"
