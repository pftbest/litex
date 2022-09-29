#include "memtest.h"
#include "lfsr.h"

#include <stdio.h>
#include <system.h>

#include <generated/soc.h>
#include <generated/csr.h>

//#define MEMTEST_BUS_DEBUG
//#define MEMTEST_DATA_DEBUG
//#define MEMTEST_ADDR_DEBUG

// Limits the number of errors printed, so that we can still access bios console
#ifndef MEMTEST_DEBUG_MAX_ERRORS
#define MEMTEST_DEBUG_MAX_ERRORS 400
#endif
// Retry reading when an error occurs. Allows to spot if errors happen during read or write.
#ifndef MEMTEST_DATA_RETRIES
#define MEMTEST_DATA_RETRIES 0
#endif

#define KIB 1024
#define MIB (KIB*1024)
#define GIB (MIB*1024)

#define ONEZERO 0xaaaaaaaa
#define ZEROONE 0x55555555

#ifndef MEMTEST_BUS_SIZE
#define MEMTEST_BUS_SIZE (512)
#endif

#define MEMTEST_DATA_RANDOM 1

#ifndef MEMTEST_ADDR_SIZE
#define MEMTEST_ADDR_SIZE (32*1024)
#endif
#define MEMTEST_ADDR_RANDOM 0

static unsigned int seed_to_data_32(unsigned int seed, int random)
{
	return random ? lfsr(32, seed) : seed + 1;
}

static unsigned short seed_to_data_16(unsigned short seed, int random)
{
	return random ? lfsr(16, seed) : seed + 1;
}

#ifdef CSR_CTRL_BASE
int memtest_access(unsigned int *addr)
{
	volatile unsigned int *array = addr;
	int bus_errors;

	/* Get current bus errors */
	bus_errors = ctrl_bus_errors_read();

	/* Check bus Read/Write */
	array[0] = ONEZERO;
	array[1] = array[0];
	array[0] = ZEROONE;
	array[1] = array[0];
	if (ctrl_bus_errors_read() - bus_errors) {
		printf("memtest_access error @ %p, exiting memtest.\n", addr);
		return 1;
	}

	return 0;
}
#endif

int memtest_bus(unsigned int *addr, unsigned long size)
{
	volatile unsigned int *array = addr;
	int i, errors;
	unsigned int rdata;

	errors = 0;

	/* Write One/Zero pattern */
	for(i=0; i<size/4; i++) {
		array[i] = ONEZERO;
	}

	/* Flush caches */
	flush_cpu_dcache();
	flush_l2_cache();

	/* Read/Verify One/Zero pattern */
	for(i=0; i<size/4; i++) {
		rdata = array[i];
		if(rdata != ONEZERO) {
			errors++;
#ifdef MEMTEST_BUS_DEBUG
			if (MEMTEST_DEBUG_MAX_ERRORS < 0 || errors <= MEMTEST_DEBUG_MAX_ERRORS)
				printf("memtest_bus error @ %p: 0x%08x vs 0x%08x\n", addr + i, rdata, ONEZERO);
#endif
		}
	}

	/* Write Zero/One pattern */
	for(i=0; i < size/4; i++) {
		array[i] = ZEROONE;
	}

	/* Flush caches */
	flush_cpu_dcache();
	flush_l2_cache();

	/* Read/Verify One/Zero pattern */
	for(i=0; i<size/4; i++) {
		rdata = array[i];
		if(rdata != ZEROONE) {
			errors++;
#ifdef MEMTEST_BUS_DEBUG
			if (MEMTEST_DEBUG_MAX_ERRORS < 0 || errors <= MEMTEST_DEBUG_MAX_ERRORS)
				printf("memtest_bus error @ %p:: 0x%08x vs 0x%08x\n", addr + i, rdata, ZEROONE);
#endif
		}
	}

	return errors;
}

int memtest_addr(unsigned int *addr, unsigned long size, int random)
{
	volatile unsigned int *array = addr;
	int i, errors;
	unsigned short seed_16;
	unsigned short rdata;

	/* Skip when size < 16KB */
	if (size < 0x10000)
		return 0;

	errors  = 0;
	seed_16 = 1;

	/* Write datas*/
	for(i=0; i<size/4; i++) {
		seed_16 = seed_to_data_16(seed_16, random);
		array[(unsigned int) seed_16] = i;
	}

	/* Flush caches */
	flush_cpu_dcache();
	flush_l2_cache();

	/* Read/Verify datas */
	seed_16 = 1;
	for(i=0; i<size/4; i++) {
		seed_16 = seed_to_data_16(seed_16, random);
		rdata = array[(unsigned int) seed_16];
		if(rdata != i) {
			errors++;
#ifdef MEMTEST_ADDR_DEBUG
			if (MEMTEST_DEBUG_MAX_ERRORS < 0 || errors <= MEMTEST_DEBUG_MAX_ERRORS)
				printf("memtest_addr error @ %p: 0x%08x vs 0x%08x\n", addr + i, rdata, i);
#endif
		}
	}

	return errors;
}

static void print_size(unsigned long size) {
	if (size < KIB)
		printf("%luB", size);
	else if (size < MIB)
		printf("%lu.%luKiB", size/KIB, (size/1   - KIB*(size/KIB))/(KIB/10));
	else if (size < GIB)
		printf("%lu.%luMiB", size/MIB, (size/KIB - KIB*(size/MIB))/(KIB/10));
	else
		printf("%lu.%luGiB", size/GIB, (size/MIB - KIB*(size/GIB))/(KIB/10));
}

static void print_speed(unsigned long speed) {
	print_size(speed);
	printf("/s");
}

static void print_progress(const char * header, unsigned int offset, unsigned int addr)
{
	printf("%s 0x%x-0x%x ", header, offset, offset + addr);
	print_size(addr);
	printf("   \r");
}

#include <stdlib.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#define TEST_NARROW_WRITES (1)

#define rand32() ((unsigned int) rand() | ( (unsigned int) rand() << 16))

#if (ULONG_MAX == 4294967295UL)
    #define rand_ul() rand32()
    #define UL_ONEBITS 0xffffffff
    #define UL_LEN 32
    #define CHECKERBOARD1 0x55555555
    #define CHECKERBOARD2 0xaaaaaaaa
    #define UL_BYTE(x) ((x | x << 8 | x << 16 | x << 24))
#elif (ULONG_MAX == 18446744073709551615ULL)
    #define rand64() (((ul) rand32()) << 32 | ((ul) rand32()))
    #define rand_ul() rand64()
    #define UL_ONEBITS 0xffffffffffffffffUL
    #define UL_LEN 64
    #define CHECKERBOARD1 0x5555555555555555
    #define CHECKERBOARD2 0xaaaaaaaaaaaaaaaa
    #define UL_BYTE(x) (((ul)x | (ul)x<<8 | (ul)x<<16 | (ul)x<<24 | (ul)x<<32 | (ul)x<<40 | (ul)x<<48 | (ul)x<<56))
#else
    #error long on this platform is not 32 or 64 bits
#endif

typedef unsigned long ul;
typedef unsigned long long ull;
typedef unsigned long volatile ulv;
typedef unsigned char volatile u8v;
typedef unsigned short volatile u16v;
typedef int (*fp_t)();

struct test {
    char *name;
    fp_t fp;
};

char progress[] = "-\\|/";
#define PROGRESSLEN 4
#define PROGRESSOFTEN 2500
#define ONE 0x00000001L

union {
    unsigned char bytes[UL_LEN/8];
    ul val;
} mword8;

union {
    unsigned short u16s[UL_LEN/16];
    ul val;
} mword16;

int compare_regions(ulv *bufa, ulv *bufb, size_t count);
int test_stuck_address(unsigned long volatile *bufa, size_t count);
int test_random_value(unsigned long volatile *bufa, unsigned long volatile *bufb, size_t count);
int test_xor_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, size_t count);
int test_sub_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, size_t count);
int test_mul_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, size_t count);
int test_div_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, size_t count);
int test_or_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, size_t count);
int test_and_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, size_t count);
int test_seqinc_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, size_t count);
int test_solidbits_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, size_t count);
int test_checkerboard_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, size_t count);
int test_blockseq_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, size_t count);
int test_walkbits0_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, size_t count);
int test_walkbits1_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, size_t count);
int test_bitspread_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, size_t count);
int test_bitflip_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, size_t count);
#ifdef TEST_NARROW_WRITES
int test_8bit_wide_random(unsigned long volatile *bufa, unsigned long volatile *bufb, size_t count);
int test_16bit_wide_random(unsigned long volatile *bufa, unsigned long volatile *bufb, size_t count);
#endif

/* Function definitions. */

int compare_regions(ulv *bufa, ulv *bufb, size_t count) {
    int r = 0;
    size_t i;
    ulv *p1 = bufa;
    ulv *p2 = bufb;

    for (i = 0; i < count; i++, p1++, p2++) {
        if (*p1 != *p2) {
			{
                fprintf(stderr,
                        "FAILURE: 0x%08lx != 0x%08lx at offset 0x%08lx.\n",
                        (ul) *p1, (ul) *p2, (ul) (i * sizeof(ul)));
            }
            /* printf("Skipping to next test..."); */
            r = -1;
        }
    }
    return r;
}

int test_stuck_address(ulv *bufa, size_t count) {
    ulv *p1 = bufa;
    unsigned int j;
    size_t i;

    printf("           ");
    fflush(stdout);
    for (j = 0; j < 16; j++) {
        printf("\b\b\b\b\b\b\b\b\b\b\b");
        p1 = (ulv *) bufa;
        printf("setting %3u", j);
        fflush(stdout);
        for (i = 0; i < count; i++) {
            *p1 = ((j + i) % 2) == 0 ? (ul) p1 : ~((ul) p1);
            *p1++;
        }
        printf("\b\b\b\b\b\b\b\b\b\b\b");
        printf("testing %3u", j);
        fflush(stdout);
        p1 = (ulv *) bufa;
        for (i = 0; i < count; i++, p1++) {
            if (*p1 != (((j + i) % 2) == 0 ? (ul) p1 : ~((ul) p1))) {
				{
                    fprintf(stderr,
                            "FAILURE: possible bad address line at offset "
                            "0x%08lx.\n",
                            (ul) (i * sizeof(ul)));
                }
                printf("Skipping to next test...\n");
                fflush(stdout);
                return -1;
            }
        }
    }
    printf("\b\b\b\b\b\b\b\b\b\b\b           \b\b\b\b\b\b\b\b\b\b\b");
    fflush(stdout);
    return 0;
}

int test_random_value(ulv *bufa, ulv *bufb, size_t count) {
    ulv *p1 = bufa;
    ulv *p2 = bufb;
    ul j = 0;
    size_t i;

    putchar(' ');
    fflush(stdout);
    for (i = 0; i < count; i++) {
        *p1++ = *p2++ = rand_ul();
        if (!(i % PROGRESSOFTEN)) {
            putchar('\b');
            putchar(progress[++j % PROGRESSLEN]);
            fflush(stdout);
        }
    }
    printf("\b \b");
    fflush(stdout);
    return compare_regions(bufa, bufb, count);
}

int test_xor_comparison(ulv *bufa, ulv *bufb, size_t count) {
    ulv *p1 = bufa;
    ulv *p2 = bufb;
    size_t i;
    ul q = rand_ul();

    for (i = 0; i < count; i++) {
        *p1++ ^= q;
        *p2++ ^= q;
    }
    return compare_regions(bufa, bufb, count);
}

int test_sub_comparison(ulv *bufa, ulv *bufb, size_t count) {
    ulv *p1 = bufa;
    ulv *p2 = bufb;
    size_t i;
    ul q = rand_ul();

    for (i = 0; i < count; i++) {
        *p1++ -= q;
        *p2++ -= q;
    }
    return compare_regions(bufa, bufb, count);
}

int test_mul_comparison(ulv *bufa, ulv *bufb, size_t count) {
    ulv *p1 = bufa;
    ulv *p2 = bufb;
    size_t i;
    ul q = rand_ul();

    for (i = 0; i < count; i++) {
        *p1++ *= q;
        *p2++ *= q;
    }
    return compare_regions(bufa, bufb, count);
}

int test_div_comparison(ulv *bufa, ulv *bufb, size_t count) {
    ulv *p1 = bufa;
    ulv *p2 = bufb;
    size_t i;
    ul q = rand_ul();

    for (i = 0; i < count; i++) {
        if (!q) {
            q++;
        }
        *p1++ /= q;
        *p2++ /= q;
    }
    return compare_regions(bufa, bufb, count);
}

int test_or_comparison(ulv *bufa, ulv *bufb, size_t count) {
    ulv *p1 = bufa;
    ulv *p2 = bufb;
    size_t i;
    ul q = rand_ul();

    for (i = 0; i < count; i++) {
        *p1++ |= q;
        *p2++ |= q;
    }
    return compare_regions(bufa, bufb, count);
}

int test_and_comparison(ulv *bufa, ulv *bufb, size_t count) {
    ulv *p1 = bufa;
    ulv *p2 = bufb;
    size_t i;
    ul q = rand_ul();

    for (i = 0; i < count; i++) {
        *p1++ &= q;
        *p2++ &= q;
    }
    return compare_regions(bufa, bufb, count);
}

int test_seqinc_comparison(ulv *bufa, ulv *bufb, size_t count) {
    ulv *p1 = bufa;
    ulv *p2 = bufb;
    size_t i;
    ul q = rand_ul();

    for (i = 0; i < count; i++) {
        *p1++ = *p2++ = (i + q);
    }
    return compare_regions(bufa, bufb, count);
}

int test_solidbits_comparison(ulv *bufa, ulv *bufb, size_t count) {
    ulv *p1 = bufa;
    ulv *p2 = bufb;
    unsigned int j;
    ul q;
    size_t i;

    printf("           ");
    fflush(stdout);
    for (j = 0; j < 64; j++) {
        printf("\b\b\b\b\b\b\b\b\b\b\b");
        q = (j % 2) == 0 ? UL_ONEBITS : 0;
        printf("setting %3u", j);
        fflush(stdout);
        p1 = (ulv *) bufa;
        p2 = (ulv *) bufb;
        for (i = 0; i < count; i++) {
            *p1++ = *p2++ = (i % 2) == 0 ? q : ~q;
        }
        printf("\b\b\b\b\b\b\b\b\b\b\b");
        printf("testing %3u", j);
        fflush(stdout);
        if (compare_regions(bufa, bufb, count)) {
            return -1;
        }
    }
    printf("\b\b\b\b\b\b\b\b\b\b\b           \b\b\b\b\b\b\b\b\b\b\b");
    fflush(stdout);
    return 0;
}

int test_checkerboard_comparison(ulv *bufa, ulv *bufb, size_t count) {
    ulv *p1 = bufa;
    ulv *p2 = bufb;
    unsigned int j;
    ul q;
    size_t i;

    printf("           ");
    fflush(stdout);
    for (j = 0; j < 64; j++) {
        printf("\b\b\b\b\b\b\b\b\b\b\b");
        q = (j % 2) == 0 ? CHECKERBOARD1 : CHECKERBOARD2;
        printf("setting %3u", j);
        fflush(stdout);
        p1 = (ulv *) bufa;
        p2 = (ulv *) bufb;
        for (i = 0; i < count; i++) {
            *p1++ = *p2++ = (i % 2) == 0 ? q : ~q;
        }
        printf("\b\b\b\b\b\b\b\b\b\b\b");
        printf("testing %3u", j);
        fflush(stdout);
        if (compare_regions(bufa, bufb, count)) {
            return -1;
        }
    }
    printf("\b\b\b\b\b\b\b\b\b\b\b           \b\b\b\b\b\b\b\b\b\b\b");
    fflush(stdout);
    return 0;
}

int test_blockseq_comparison(ulv *bufa, ulv *bufb, size_t count) {
    ulv *p1 = bufa;
    ulv *p2 = bufb;
    unsigned int j;
    size_t i;

    printf("           ");
    fflush(stdout);
    for (j = 0; j < 256; j++) {
        printf("\b\b\b\b\b\b\b\b\b\b\b");
        p1 = (ulv *) bufa;
        p2 = (ulv *) bufb;
        printf("setting %3u", j);
        fflush(stdout);
        for (i = 0; i < count; i++) {
            *p1++ = *p2++ = (ul) UL_BYTE(j);
        }
        printf("\b\b\b\b\b\b\b\b\b\b\b");
        printf("testing %3u", j);
        fflush(stdout);
        if (compare_regions(bufa, bufb, count)) {
            return -1;
        }
    }
    printf("\b\b\b\b\b\b\b\b\b\b\b           \b\b\b\b\b\b\b\b\b\b\b");
    fflush(stdout);
    return 0;
}

int test_walkbits0_comparison(ulv *bufa, ulv *bufb, size_t count) {
    ulv *p1 = bufa;
    ulv *p2 = bufb;
    unsigned int j;
    size_t i;

    printf("           ");
    fflush(stdout);
    for (j = 0; j < UL_LEN * 2; j++) {
        printf("\b\b\b\b\b\b\b\b\b\b\b");
        p1 = (ulv *) bufa;
        p2 = (ulv *) bufb;
        printf("setting %3u", j);
        fflush(stdout);
        for (i = 0; i < count; i++) {
            if (j < UL_LEN) { /* Walk it up. */
                *p1++ = *p2++ = ONE << j;
            } else { /* Walk it back down. */
                *p1++ = *p2++ = ONE << (UL_LEN * 2 - j - 1);
            }
        }
        printf("\b\b\b\b\b\b\b\b\b\b\b");
        printf("testing %3u", j);
        fflush(stdout);
        if (compare_regions(bufa, bufb, count)) {
            return -1;
        }
    }
    printf("\b\b\b\b\b\b\b\b\b\b\b           \b\b\b\b\b\b\b\b\b\b\b");
    fflush(stdout);
    return 0;
}

int test_walkbits1_comparison(ulv *bufa, ulv *bufb, size_t count) {
    ulv *p1 = bufa;
    ulv *p2 = bufb;
    unsigned int j;
    size_t i;

    printf("           ");
    fflush(stdout);
    for (j = 0; j < UL_LEN * 2; j++) {
        printf("\b\b\b\b\b\b\b\b\b\b\b");
        p1 = (ulv *) bufa;
        p2 = (ulv *) bufb;
        printf("setting %3u", j);
        fflush(stdout);
        for (i = 0; i < count; i++) {
            if (j < UL_LEN) { /* Walk it up. */
                *p1++ = *p2++ = UL_ONEBITS ^ (ONE << j);
            } else { /* Walk it back down. */
                *p1++ = *p2++ = UL_ONEBITS ^ (ONE << (UL_LEN * 2 - j - 1));
            }
        }
        printf("\b\b\b\b\b\b\b\b\b\b\b");
        printf("testing %3u", j);
        fflush(stdout);
        if (compare_regions(bufa, bufb, count)) {
            return -1;
        }
    }
    printf("\b\b\b\b\b\b\b\b\b\b\b           \b\b\b\b\b\b\b\b\b\b\b");
    fflush(stdout);
    return 0;
}

int test_bitspread_comparison(ulv *bufa, ulv *bufb, size_t count) {
    ulv *p1 = bufa;
    ulv *p2 = bufb;
    unsigned int j;
    size_t i;

    printf("           ");
    fflush(stdout);
    for (j = 0; j < UL_LEN * 2; j++) {
        printf("\b\b\b\b\b\b\b\b\b\b\b");
        p1 = (ulv *) bufa;
        p2 = (ulv *) bufb;
        printf("setting %3u", j);
        fflush(stdout);
        for (i = 0; i < count; i++) {
            if (j < UL_LEN) { /* Walk it up. */
                *p1++ = *p2++ = (i % 2 == 0)
                    ? (ONE << j) | (ONE << (j + 2))
                    : UL_ONEBITS ^ ((ONE << j)
                                    | (ONE << (j + 2)));
            } else { /* Walk it back down. */
                *p1++ = *p2++ = (i % 2 == 0)
                    ? (ONE << (UL_LEN * 2 - 1 - j)) | (ONE << (UL_LEN * 2 + 1 - j))
                    : UL_ONEBITS ^ (ONE << (UL_LEN * 2 - 1 - j)
                                    | (ONE << (UL_LEN * 2 + 1 - j)));
            }
        }
        printf("\b\b\b\b\b\b\b\b\b\b\b");
        printf("testing %3u", j);
        fflush(stdout);
        if (compare_regions(bufa, bufb, count)) {
            return -1;
        }
    }
    printf("\b\b\b\b\b\b\b\b\b\b\b           \b\b\b\b\b\b\b\b\b\b\b");
    fflush(stdout);
    return 0;
}

int test_bitflip_comparison(ulv *bufa, ulv *bufb, size_t count) {
    ulv *p1 = bufa;
    ulv *p2 = bufb;
    unsigned int j, k;
    ul q;
    size_t i;

    printf("           ");
    fflush(stdout);
    for (k = 0; k < UL_LEN; k++) {
        q = ONE << k;
        for (j = 0; j < 8; j++) {
            printf("\b\b\b\b\b\b\b\b\b\b\b");
            q = ~q;
            printf("setting %3u", k * 8 + j);
            fflush(stdout);
            p1 = (ulv *) bufa;
            p2 = (ulv *) bufb;
            for (i = 0; i < count; i++) {
                *p1++ = *p2++ = (i % 2) == 0 ? q : ~q;
            }
            printf("\b\b\b\b\b\b\b\b\b\b\b");
            printf("testing %3u", k * 8 + j);
            fflush(stdout);
            if (compare_regions(bufa, bufb, count)) {
                return -1;
            }
        }
    }
    printf("\b\b\b\b\b\b\b\b\b\b\b           \b\b\b\b\b\b\b\b\b\b\b");
    fflush(stdout);
    return 0;
}

#ifdef TEST_NARROW_WRITES
int test_8bit_wide_random(ulv* bufa, ulv* bufb, size_t count) {
    u8v *p1, *t;
    ulv *p2;
    int attempt;
    unsigned int b, j = 0;
    size_t i;

    putchar(' ');
    fflush(stdout);
    for (attempt = 0; attempt < 2;  attempt++) {
        if (attempt & 1) {
            p1 = (u8v *) bufa;
            p2 = bufb;
        } else {
            p1 = (u8v *) bufb;
            p2 = bufa;
        }
        for (i = 0; i < count; i++) {
            t = mword8.bytes;
            *p2++ = mword8.val = rand_ul();
            for (b=0; b < UL_LEN/8; b++) {
                *p1++ = *t++;
            }
            if (!(i % PROGRESSOFTEN)) {
                putchar('\b');
                putchar(progress[++j % PROGRESSLEN]);
                fflush(stdout);
            }
        }
        if (compare_regions(bufa, bufb, count)) {
            return -1;
        }
    }
    printf("\b \b");
    fflush(stdout);
    return 0;
}

int test_16bit_wide_random(ulv* bufa, ulv* bufb, size_t count) {
    u16v *p1, *t;
    ulv *p2;
    int attempt;
    unsigned int b, j = 0;
    size_t i;

    putchar( ' ' );
    fflush( stdout );
    for (attempt = 0; attempt < 2; attempt++) {
        if (attempt & 1) {
            p1 = (u16v *) bufa;
            p2 = bufb;
        } else {
            p1 = (u16v *) bufb;
            p2 = bufa;
        }
        for (i = 0; i < count; i++) {
            t = mword16.u16s;
            *p2++ = mword16.val = rand_ul();
            for (b = 0; b < UL_LEN/16; b++) {
                *p1++ = *t++;
            }
            if (!(i % PROGRESSOFTEN)) {
                putchar('\b');
                putchar(progress[++j % PROGRESSLEN]);
                fflush(stdout);
            }
        }
        if (compare_regions(bufa, bufb, count)) {
            return -1;
        }
    }
    printf("\b \b");
    fflush(stdout);
    return 0;
}
#endif

struct test tests[] = {
    { "Random Value", test_random_value },
    { "Compare XOR", test_xor_comparison },
    { "Compare SUB", test_sub_comparison },
    { "Compare MUL", test_mul_comparison },
    { "Compare DIV",test_div_comparison },
    { "Compare OR", test_or_comparison },
    { "Compare AND", test_and_comparison },
    { "Sequential Increment", test_seqinc_comparison },
    { "Solid Bits", test_solidbits_comparison },
    { "Block Sequential", test_blockseq_comparison },
    { "Checkerboard", test_checkerboard_comparison },
    { "Bit Spread", test_bitspread_comparison },
    { "Bit Flip", test_bitflip_comparison },
    { "Walking Ones", test_walkbits1_comparison },
    { "Walking Zeroes", test_walkbits0_comparison },
#ifdef TEST_NARROW_WRITES
    { "8-bit Writes", test_8bit_wide_random },
    { "16-bit Writes", test_16bit_wide_random },
#endif
    { NULL, NULL }
};

int memtest_data(unsigned int *addr, unsigned long size, int random, struct memtest_config *config)
{
	volatile unsigned int *array = addr;
	int i, errors;
	int j, ok_at;
	int progress;
	unsigned int seed_32;
	unsigned int rdata;

	progress = config == NULL ? 1 : config->show_progress;
	errors  = 0;
	seed_32 = 1;

	if (config == NULL || !config->read_only) {
		/* Write datas */
		for(i=0; i<size/4; i++) {
			seed_32 = seed_to_data_32(seed_32, random);
			array[i] = seed_32;
			if (i%0x8000 == 0)
				print_progress("  Write:", (unsigned long)addr, 4*i);
		}
		print_progress("  Write:", (unsigned long)addr, 4*i);
		printf("\n");
	}

	/* Flush caches */
	flush_cpu_dcache();
	flush_l2_cache();

	/* Read/Verify datas */
	seed_32 = 1;
	for(i=0; i<size/4; i++) {
		seed_32 = seed_to_data_32(seed_32, random);

		ok_at = -1;
		for (j = 0; j < MEMTEST_DATA_RETRIES + 1; ++j) {
			rdata = array[i];
			if (rdata == seed_32) {
				ok_at = j;
				break;
			}
		}
		if (ok_at > 0)
			printf("@%p: Redeemed at %d. attempt\n", addr + i, ok_at + 1);

		if(rdata != seed_32) {
			errors++;
			if (config != NULL && config->on_error != NULL) {
				// call the handler, if non-zero status is returned finish now
				if (config->on_error((unsigned long) (addr + i), rdata, seed_32, config->arg) != 0)
					return errors;
			}
#ifdef MEMTEST_DATA_DEBUG
			if (MEMTEST_DEBUG_MAX_ERRORS < 0 || errors <= MEMTEST_DEBUG_MAX_ERRORS)
				printf("memtest_data error @ %p: 0x%08x vs 0x%08x\n", addr + i, rdata, seed_32);
#endif
		}
		if (i%0x8000 == 0 && progress)
			print_progress("   Read:", (unsigned long)addr, 4*i);
	}
	if (progress) {
		print_progress("   Read:", (unsigned long)addr, 4*i);
		printf("\n");
	}

    unsigned long halflen = size / 2;
    unsigned long count = halflen / sizeof(ul);
    ulv *bufa = (ulv *) array;
    ulv *bufb = (ulv *) ((size_t) array + halflen);

	for (i=0;;i++) {
		if (!tests[i].name) break;
		printf("  %-20s: ", tests[i].name);
		if (!tests[i].fp(bufa, bufb, count)) {
			printf("ok\n");
		} else {
			errors++;
		}
		fflush(stdout);
	}
	printf("\n");
	fflush(stdout);

	return errors;
}

void memspeed(unsigned int *addr, unsigned long size, bool read_only, bool random)
{
	volatile unsigned long *array = (unsigned long *)addr;
	int i;
	unsigned int seed_32 = 0;
	uint32_t start, end;
	unsigned long write_speed = 0;
	unsigned long read_speed;
	__attribute__((unused)) unsigned long data;
	const unsigned int sz = sizeof(unsigned long);
	int burst_size = 4;
	volatile unsigned long *ptr, *ptr_max = (volatile unsigned long *)(((char *)array) + size - sz*burst_size);


	printf("Memspeed at %p (", addr);
	if (random)
		printf("Random, ");
	else
		printf("Sequential, ");
	print_size(size);
	printf(")...\n");

	/* Init timer */
	timer0_en_write(0);
	timer0_reload_write(0);
	timer0_load_write(0xffffffff);
	timer0_en_write(1);

	/* Measure Write speed */
	if (!read_only) {
		timer0_update_value_write(1);
		start = timer0_value_read();

		ptr = array;
		do{
			ptr[0] = -1ul;
			ptr[1] = -1ul;
			ptr[2] = -1ul;
			ptr[3] = -1ul;
			ptr += burst_size;
		} while(ptr <= ptr_max);

		timer0_update_value_write(1);
		end = timer0_value_read();
		uint64_t numerator   = ((uint64_t)size)*((uint64_t)CONFIG_CLOCK_FREQUENCY);
		uint64_t denominator = ((uint64_t)start - (uint64_t)end);
		write_speed = numerator/denominator;
		printf("  Write speed: ");
		print_speed(write_speed);
		printf("\n");
	}

	/* flush caches */
	flush_cpu_dcache();
	flush_l2_cache();

	/* Measure Read speed */
	timer0_en_write(1);
	timer0_update_value_write(1);
	start = timer0_value_read();

	int num = size/sz;

	if (random) {
		for (i = 0; i < size/sz; i++) {
			seed_32 = seed_to_data_32(seed_32, i);
			data = array[seed_32 % num];
		}
	} else {
		ptr = array;
		do{
			data = ptr[0];
			data = ptr[1];
			data = ptr[2];
			data = ptr[3];
			ptr += burst_size;
		} while(ptr <= ptr_max);
	}

	timer0_update_value_write(1);
	end = timer0_value_read();
	uint64_t numerator   = ((uint64_t)size)*((uint64_t)CONFIG_CLOCK_FREQUENCY);
	uint64_t denominator = ((uint64_t)start - (uint64_t)end);
	read_speed = numerator/denominator;
	printf("   Read speed: ");
	print_speed(read_speed);
	printf("\n");
}

int memtest(unsigned int *addr, unsigned long maxsize)
{
	int bus_errors, data_errors, addr_errors;
	unsigned long bus_size  = MEMTEST_BUS_SIZE < maxsize ? MEMTEST_BUS_SIZE : maxsize;
	unsigned long addr_size = MEMTEST_ADDR_SIZE < maxsize ? MEMTEST_ADDR_SIZE : maxsize;
	unsigned long data_size = maxsize;

	printf("Memtest at %p (", addr);
	print_size(data_size);
	printf(")...\n");

#ifdef CSR_CTRL_BASE
	if (memtest_access(addr))
		return 0;
#endif

	bus_errors  = memtest_bus(addr, bus_size);
	addr_errors = memtest_addr(addr, addr_size, MEMTEST_ADDR_RANDOM);
	data_errors = memtest_data(addr, data_size, MEMTEST_DATA_RANDOM, NULL);

	if(bus_errors + addr_errors + data_errors != 0) {
		printf("  bus errors:  %d/%ld\n", bus_errors,  2*bus_size/4);
		printf("  addr errors: %d/%ld\n", addr_errors, addr_size/4);
		printf("  data errors: %d/%ld\n", data_errors, data_size/4);
		printf("Memtest KO\n");
		return 0;
	}
	printf("Memtest OK\n");
	return 1;
}
