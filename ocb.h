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


void ocb_encrypt(unsigned char *c, unsigned char *k, unsigned char *n,
                 unsigned char *a, unsigned abytes,
                 unsigned char *p, unsigned pbytes);

/* ------------------------------------------------------------------------- */

int ocb_decrypt(unsigned char *p, unsigned char *k, unsigned char *n,
                unsigned char *a, unsigned abytes,
                unsigned char *c, unsigned cbytes) ;

bool ocb_init(const uint8_t * key) ;


#endif /* OCB_H_ */
