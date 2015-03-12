/*------------------------------------------------------------------------
 / OCB Version 3 Reference Code (Unoptimized C)   Last modified 12-JUN-2013
 /-------------------------------------------------------------------------
 / Copyright (c) 2013 Ted Krovetz.
 /
 / Permission to use, copy, modify, and/or distribute this software for any
 / purpose with or without fee is hereby granted, provided that the above
 / copyright notice and this permission notice appear in all copies.
 /
 / THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 / WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 / MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 / ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 / WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 / ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 / OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 /
 / Phillip Rogaway holds patents relevant to OCB. See the following for
 / his free patent grant: http://www.cs.ucdavis.edu/~rogaway/ocb/grant.htm
 /
 / Comments are welcome: Ted Krovetz <ted@krovetz.net>
 /------------------------------------------------------------------------- */

/* http://web.cs.ucdavis.edu/~rogaway/ocb/news/code/ocb_ref.c
 *
 * This is a quick and dirty port of OCB for NRF51 series device
 *
 *                                 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ocb.h"
#include "nrf_soc.h"
#include "tiny-AES128-C/aes.h"
#define KEYBYTES   (128/8)
#define NONCEBYTES (96/8)
#define TAGBYTES   (128/8)

#if !(KEYBYTES==16 || KEYBYTES==24 || KEYBYTES==32) ||  \
     (NONCEBYTES > 15 || NONCEBYTES < 0) ||             \
     (TAGBYTES > 16 || TAGBYTES < 1)
#error -- KEYBYTES, NONCEBYTES, or TAGBYTES is an illegal value
#endif
#define BLOCK_SIZE 16
typedef uint8_t block[BLOCK_SIZE];

typedef uint8_t AES_KEY[SOC_ECB_KEY_LENGTH];


//decryption uses sotware AES hence it is much slower
static inline void  AES_decrypt(block in, block out, uint8_t* aes_key){
	 AES128_ECB_decrypt(in, aes_key, out);
}

// we need to create a struct for the nrf sd_ecb encryption
static inline void AES_encrypt(block in, block out, uint8_t* aes_key) {
	nrf_ecb_hal_data_t datain = { .key = { 0, }, .cleartext = { 0, }, .ciphertext =
			{ 0, } };
	memcpy(datain.key, aes_key, KEYBYTES);
	memcpy(datain.cleartext, in, BLOCK_SIZE);
	sd_ecb_block_encrypt(&datain);
	memcpy(out, datain.ciphertext, BLOCK_SIZE);
}

/* ------------------------------------------------------------------------- */

static void xor_block(block d, block s1, block s2) {
	unsigned i;
	for (i = 0; i < 16; i++)
		d[i] = s1[i] ^ s2[i];
}

/* ------------------------------------------------------------------------- */

static void double_block(block d, block s) {
	unsigned i;
	uint8_t tmp = s[0];
	for (i = 0; i < 15; i++)
		d[i] = (s[i] << 1) | (s[i + 1] >> 7);
	d[15] = (s[15] << 1) ^ ((tmp >> 7) * 135);
}

/* ------------------------------------------------------------------------- */

static void calc_L_i(block l, block ldollar, unsigned i) {
	double_block(l, ldollar); /* l is now L_0               */
	for (; (i & 1) == 0; i >>= 1)
		double_block(l, l); /* double for each trailing 0 */
}

/* ------------------------------------------------------------------------- */

static void hash(block result, uint8_t *k, uint8_t *a, unsigned abytes) {
	block lstar, ldollar, offset, sum, tmp;
	unsigned i;

	/* Key-dependent variables */

	/* L_* = ENCIPHER(K, zeros(128)) */
	//AES_set_encrypt_key(k, KEYBYTES*8, &aes_key);
	memset(tmp, 0, 16);
	AES_encrypt(tmp, lstar, k);

	/* L_$ = double(L_*) */
	double_block(ldollar, lstar);

	/* Process any whole blocks */

	/* Sum_0 = zeros(128) */
	memset(sum, 0, 16);
	/* Offset_0 = zeros(128) */
	memset(offset, 0, 16);
	for (i = 1; i <= abytes / 16; i++, a = a + 16) {
		/* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
		calc_L_i(tmp, ldollar, i);
		xor_block(offset, offset, tmp);
		/* Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i) */
		xor_block(tmp, offset, a);
		AES_encrypt(tmp, tmp, k);
		xor_block(sum, sum, tmp);
	}

	/* Process any final partial block; compute final hash value */

	abytes = abytes % 16; /* Bytes in final block */
	if (abytes > 0) {
		/* Offset_* = Offset_m xor L_* */
		xor_block(offset, offset, lstar);
		/* tmp = (A_* || 1 || zeros(127-bitlen(A_*))) xor Offset_* */
		memset(tmp, 0, 16);
		memcpy(tmp, a, abytes);
		tmp[abytes] = 0x80;
		xor_block(tmp, offset, tmp);
		/* Sum = Sum_m xor ENCIPHER(K, tmp) */
		AES_encrypt(tmp, tmp, k);
		xor_block(sum, tmp, sum);
	}

	memcpy(result, sum, 16);
}

/* ------------------------------------------------------------------------- */

int ocb_crypt(uint8_t *out, uint8_t *k, uint8_t *n, uint8_t *a,
		unsigned abytes, uint8_t *in, unsigned inbytes, int encrypting) {
//    AES_KEY aes_encrypt_key;
	block lstar, ldollar, sum, offset, ktop, pad, nonce, tag, tmp;
	uint8_t stretch[24];
	unsigned bottom, byteshift, bitshift, i;

    if ( ! encrypting ) {
         if (inbytes < TAGBYTES) return -1;
         inbytes -= TAGBYTES;
    }

	/* L_* = ENCIPHER(K, zeros(128)) */
	memset(tmp, 0, 16);
	AES_encrypt(tmp, lstar, k);

	/* L_$ = double(L_*) */
	double_block(ldollar, lstar);

	/* Nonce-dependent and per-encryption variables */

	/* Nonce = zeros(127-bitlen(N)) || 1 || N */
	memset(nonce, 0, 16);
	memcpy(&nonce[16 - NONCEBYTES], n, NONCEBYTES);
	nonce[0] = (uint8_t) (((TAGBYTES * 8) % 128) << 1);
	nonce[16 - NONCEBYTES - 1] |= 0x01;
	/* bottom = str2num(Nonce[123..128]) */
	bottom = nonce[15] & 0x3F;
	/* Ktop = ENCIPHER(K, Nonce[1..122] || zeros(6)) */
	nonce[15] &= 0xC0;
	AES_encrypt(nonce, ktop, k);
	/* Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72]) */
	memcpy(stretch, ktop, 16);
	memcpy(tmp, &ktop[1], 8);
	xor_block(tmp, tmp, ktop);
	memcpy(&stretch[16], tmp, 8);
	/* Offset_0 = Stretch[1+bottom..128+bottom] */
	byteshift = bottom / 8;
	bitshift = bottom % 8;
	if (bitshift != 0)
		for (i = 0; i < 16; i++)
			offset[i] = (stretch[i + byteshift] << bitshift)
					| (stretch[i + byteshift + 1] >> (8 - bitshift));
	else
		for (i = 0; i < 16; i++)
			offset[i] = stretch[i + byteshift];
	/* Checksum_0 = zeros(128) */
	memset(sum, 0, 16);

	/* Process any whole blocks */

	for (i = 1; i <= inbytes / 16; i++, in = in + 16, out = out + 16) {
		/* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
		calc_L_i(tmp, ldollar, i);
		xor_block(offset, offset, tmp);

		xor_block(tmp, offset, in);
        if (encrypting) {
            /* P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i) */
        	AES_encrypt(tmp, tmp, k);
            xor_block(out, offset, tmp);
            /* Checksum_i = Checksum_{i-1} xor P_i */
            xor_block(sum, in, sum);
        } else {
            /* P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i) */
            AES_decrypt(tmp, tmp, k);
            xor_block(out, offset, tmp);
            /* Checksum_i = Checksum_{i-1} xor P_i */
            xor_block(sum, out, sum);
        }

	}

	/* Process any final partial block and compute raw tag */

	inbytes = inbytes % 16; /* Bytes in final block */
	if (inbytes > 0) {
		/* Offset_* = Offset_m xor L_* */
		xor_block(offset, offset, lstar);
		/* Pad = ENCIPHER(K, Offset_*) */
		AES_encrypt(offset, pad, k);

        if (encrypting) {
            /* Checksum_* = Checksum_m xor (P_* || 1 || zeros(127-bitlen(P_*))) */
            memset(tmp, 0, 16);
            memcpy(tmp, in, inbytes);
            tmp[inbytes] = 0x80;
            xor_block(sum, tmp, sum);
            /* C_* = P_* xor Pad[1..bitlen(P_*)] */
            xor_block(pad, tmp, pad);
            memcpy(out, pad, inbytes);
            out = out + inbytes;
        } else {
            /* P_* = C_* xor Pad[1..bitlen(C_*)] */
            memcpy(tmp, pad, 16);
            memcpy(tmp, in, inbytes);
            xor_block(tmp, pad, tmp);
            tmp[inbytes] = 0x80;     /* tmp == P_* || 1 || zeros(127-bitlen(P_*)) */
            memcpy(out, tmp, inbytes);
            /* Checksum_* = Checksum_m xor (P_* || 1 || zeros(127-bitlen(P_*))) */
            xor_block(sum, tmp, sum);
            in = in + inbytes;
        }
	}
	/* Tag = ENCIPHER(K, Checksum xor Offset xor L_$) xor HASH(K,A) */
	xor_block(tmp, sum, offset);
	xor_block(tmp, tmp, ldollar);
	AES_encrypt(tmp, tag, k);
	hash(tmp, k, a, abytes);
	xor_block(tag, tmp, tag);

    if (encrypting) {
        memcpy(out, tag, TAGBYTES);
        return 0;
    } else
        return (memcmp(in,tag,TAGBYTES) ? -1 : 0);     /* Check for validity */

}

void ocb_encrypt(uint8_t *c, uint8_t *k, uint8_t *n,
                 uint8_t *a, unsigned abytes,
                 uint8_t *p, unsigned pbytes) {
     ocb_crypt(c, k, n, a, abytes, p, pbytes, OCB_ENCRYPT);
}

/* ------------------------------------------------------------------------- */

int ocb_decrypt(uint8_t *p, uint8_t *k, uint8_t *n,
                uint8_t *a, unsigned abytes,
                uint8_t *c, unsigned cbytes) {
    return ocb_crypt(p, k, n, a, abytes, c, cbytes, OCB_DECRYPT);
}



