/*******************************************************************************
 Copyright (c) 2009-2018, Intel Corporation

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

     * Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
     * Neither the name of Intel Corporation nor the names of its contributors
       may be used to endorse or promote products derived from this software
       without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************/

/**
 * Implementation of CRC computation methods
 */
#include <x86intrin.h>

#include "types.h"

/**
 * Global data
 *
 */

/**
 * Flag indicating availability of PCLMULQDQ instruction
 * Only valid after running CRCInit() function.
 */
static int pclmulqdq_available = 0;

static __m128i crc_xmm_be_le_swap128;

DECLARE_ALIGNED(static const uint8_t crc_xmm_shift_tab[48], 16) = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

#include <cpuid.h>

#include "crc.h"
#include "crc_wimax.h"
#include "crcext.h"

/**
 * Common macros
 */

/**
 * Common use local data
 */

/**
 * Common use function prototypes
 */

/**
 * ========================
 *
 * 32-bit LUT METHOD
 *
 * ========================
 */

/**
 * @brief Initializes look-up-table (LUT) for given 32 bit polynomial
 *
 * @param poly CRC polynomial
 * @param lut pointer to 256 x 32bits look-up-table to be initialized
 */
static void crc32_init_lut(const uint32_t poly, uint32_t *lut) {
    uint_fast32_t i, j;

    if (lut == NULL) return;

    for (i = 0; i < 256; i++) {
        uint_fast32_t crc = (i << 24);

        for (j = 0; j < 8; j++)
            if (crc & 0x80000000L)
                crc = (crc << 1) ^ poly;
            else
                crc <<= 1;

        lut[i] = crc;
    }
}

/**
 * ===================================================================
 *
 * CRC initialization
 *
 * ===================================================================
 */

/**
 * @brief Initializes CRC module.
 * @note It is mandatory to run it before using any of CRC API's.
 */
void BALBOA_NS(CRCInit)(void) {
    static int is_initialized = 0;
    uint32_t reax = 0, rebx = 0, recx = 0, redx = 0;

    if (is_initialized) return;

    /**
     * Check support for SSE4.2 & PCLMULQDQ
     */
    __cpuid(1, reax, rebx, recx, redx);

    if ((recx & bit_SSE4_2) && (recx & bit_PCLMUL)) pclmulqdq_available = 1;

    /**
     * Init BE <-> LE swap pattern for XMM registers
     */
    crc_xmm_be_le_swap128 = _mm_setr_epi32(0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203);

    /**
     * Initialize CRC functions
     */
    WiMAXCrcInit();
    is_initialized = 1;
}

// The WiMax-specific stuff.

/**
 * Local data
 *
 */
static uint32_t wimax_crc32_lut[256];
static DECLARE_ALIGNED(struct crc_pclmulqdq_ctx wimax_crc32_pclmulqdq, 16) = {
    0xe8a45605, /**< k1 */
    0xc5b9cd4c, /**< k2 */
    0x490d678d, /**< k3 */
    0x4d101df,  /**< q */
    0x4c11db7,  /**< p */
    0ULL        /**< res */
};

/**
 * Implementation
 *
 */

/**
 * @brief Initializes data structures for WiMAX OFDMA crc32 calculations.
 *
 */
static void WiMAXCrcInit(void) {
    crc32_init_lut(WIMAX_OFDMA_CRC32_POLYNOMIAL, wimax_crc32_lut);
}

/**
 * @brief Calculates WiMAX OFDMA CRC32 using LUT method
 *
 * @param data pointer to data block to calculate CRC for
 * @param data_len size of data block
 *
 * @return New CRC value
 */
uint32_t BALBOA_NS(compute_the_crc_lut)(uint32_t start, const uint8_t *data, uint32_t data_len) {
    return crc32_calc_lut(data, data_len, start, wimax_crc32_lut);
}

/**
 * @brief Calculates WiMAX OFDMA CRC32
 *
 * @param data pointer to data block to calculate CRC for
 * @param data_len size of data block
 *
 * @return New CRC value
 */
uint32_t BALBOA_NS(compute_the_crc)(uint32_t start, const uint8_t *data, uint32_t data_len) {
    return crc32_calc_pclmulqdq(data, data_len, start, &wimax_crc32_pclmulqdq);
}
