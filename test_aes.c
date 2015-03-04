/*
 * test_aes.c
 *
 *  Created on: Mar 3, 2015
 *      Author: lauril
 */

#include <string.h>
#include <stdlib.h>
#include <openssl/aes.h>

#define KEYBYTES   (128/8)
#define NONCEBYTES (96/8)
#define TAGBYTES   (128/8)
typedef unsigned char block[16];

int main(void){
	 AES_KEY AESkey;
	 uint8_t MBlock[16] = {2,};
	 uint8_t MBlock2[16];
	 uint8_t CBlock[16];
	 uint8_t  keyArray[KEYBYTES] = {'A','A','A','A','A','A','A','A','A','A','A','A','A','A','A','A'};
	  int i;

	  /*
	   * Key contains the actual 128-bit AES key. AESkey is a data structure
	   * holding a transformed version of the key, for efficiency.
	   */


	  AES_set_encrypt_key((const unsigned char *) keyArray, 128, &AESkey);


	  AES_encrypt((const unsigned char *) MBlock, CBlock, (const AES_KEY *) &AESkey);

	  for (i=0; i<16; i++)
	    printf("%X", CBlock[i]/16), printf("%X", CBlock[i]%16);
	  printf("\n");

	  /*
	   * We need to set AESkey appropriately before inverting AES.
	   * Note that the underlying key Key is the same; just the data structure
	   * AESkey is changing (for reasons of efficiency).
	   */
	  AES_set_decrypt_key((const unsigned char *) keyArray, 128, &AESkey);

	  AES_decrypt((const unsigned char *) CBlock, MBlock2, (const AES_KEY *) &AESkey);

	  for (i=0; i<16; i++)
	    printf("%X", MBlock2[i]/16), printf("%X", MBlock2[i]%16);
	  printf("\n");
}


