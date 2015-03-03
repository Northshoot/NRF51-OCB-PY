/*
 * ocb.h
 *
 *  Created on: Mar 3, 2015
 *      Author: lauril
 */

#ifndef OCB_H_
#define OCB_H_

#include <stdint.h>
#include <stdbool.h>

#define OCB_ENCRYPT 1
#define OCB_DECRYPT 0

#define KEYBYTES   (128/8)
#define NONCEBYTES (96/8)
#define TAGBYTES   (128/8)


#if !(KEYBYTES==16 || KEYBYTES==24 || KEYBYTES==32) ||  \
     (NONCEBYTES > 15 || NONCEBYTES < 0) ||             \
     (TAGBYTES > 16 || TAGBYTES < 1)
#error -- KEYBYTES, NONCEBYTES, or TAGBYTES is an illegal value
#endif

/* ------------------------------------------------------------------------- */
void ocb_encrypt(uint8_t *c, uint8_t *k, uint8_t *n,
		uint8_t *a, uint8_t abytes,
		uint8_t *p, uint8_t pbytes);

/* ------------------------------------------------------------------------- */

int ocb_decrypt(uint8_t *p, uint8_t *k, uint8_t *n,
		uint8_t *a, uint8_t abytes,
		uint8_t *c, uint8_t cbytes) ;

/* ------------------------------------------------------------------------- */
bool ocb_init(const uint8_t * key) ;


#endif /* OCB_H_ */
