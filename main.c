/*
 * main.c
 *
 *  Created on: Mar 2, 2015
 *      Author: lauril
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "nrf_delay.h"
#include "nrf_gpio.h"
#include "boards.h"
#include <stdio.h>
#include "nrf.h"
#include "nrf_temp.h"
#include "app_uart.h"
#include "app_error.h"
#include "app_gpiote.h"
#include "bsp.h"
#include "nrf_ecb.h"
#include "ocb.h"

#define UART_TX_BUF_SIZE 256                                                          /**< UART TX buffer size. */
#define UART_RX_BUF_SIZE 1
#define AES_ECB_BUFF_SIZE 20*64

const uint8_t leds_list[LEDS_NUMBER] = LEDS_LIST;


void uart_error_handle(app_uart_evt_t * p_event)
{
    if (p_event->evt_type == APP_UART_COMMUNICATION_ERROR)
    {
        APP_ERROR_HANDLER(p_event->data.error_communication);
    }
    else if (p_event->evt_type == APP_UART_FIFO_ERROR)
    {
        APP_ERROR_HANDLER(p_event->data.error_code);
    }
}

void print_hex_memory(void *mem, int len) {
  int i;
  uint8_t *p = (uint8_t *)mem;
  for (i=0;i<len;i++) {
    printf("0x%02x ", p[i]);
  }
  printf("\n");
}


int main(void)
{

//    int32_t volatile temp;
    uint32_t err_code;
    // Configure LED-pins as outputs.
    LEDS_CONFIGURE(LEDS_MASK);
    nrf_temp_init();


    APP_GPIOTE_INIT(1);
    const app_uart_comm_params_t comm_params =
     {
         RX_PIN_NUMBER,
         TX_PIN_NUMBER,
         RTS_PIN_NUMBER,
         CTS_PIN_NUMBER,
         APP_UART_FLOW_CONTROL_ENABLED,
         false,
         UART_BAUDRATE_BAUDRATE_Baud38400
     };

    APP_UART_FIFO_INIT(&comm_params,
                    UART_RX_BUF_SIZE,
                    UART_TX_BUF_SIZE,
                    uart_error_handle,
                    APP_IRQ_PRIORITY_LOW,
                    err_code);

    APP_ERROR_CHECK(err_code);
    printf("Booted \n");

    unsigned char zeroes[128] = {0,};
    unsigned char plainData[16] = {2,2,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
    unsigned char nonce[16] = {0,};
    //unsigned char p[128] = {0,};
    unsigned char final[16];
    unsigned char *c;
    unsigned i, next;

    uint8_t  keyArray[KEYBYTES] = {'A','A','A','A','A','A','A','A','A','A','A','A','A','A','A','A'};
    uint8_t *aesKey = (uint8_t *)keyArray;
    bool init = ocb_init(aesKey);
    if(!init) return 0;
    printf("AES init Successfull \n");

    printf("KEY in hex \n");
	  for (i=0; i<16; i++)
	    printf("%X", keyArray[i]/16), printf("%X", keyArray[i]%16);
	  printf("\n");

	  printf("data in hex \n");
	  for (i=0; i<16; i++)
	    printf("%X", plainData[i]/16), printf("%X", plainData[i]%16);
	  printf("\n");
	  printf("header in hex \n");
	  for (i=0; i<16; i++)
	    printf("%X", zeroes[i]/16), printf("%X", zeroes[i]%16);
	  printf("\n");


    /* Encrypt and output RFC vector */
    c = (uint8_t *) malloc(16*8+32);
    next = 0;
    for (i=0; i<128; i++) {
        nonce[11] = i;
        ocb_encrypt(c+next, aesKey, nonce, zeroes, i, plainData, i);
        next = next + i + TAGBYTES;
        ocb_encrypt(c+next, aesKey, nonce, zeroes, 0, plainData, i);
        next = next + i + TAGBYTES;
        ocb_encrypt(c+next, aesKey, nonce, zeroes, i, plainData, 0);
        next = next + TAGBYTES;
    }
    nonce[11] = 0;
    for (i=0; i<16; i++)
   	    printf("%X", nonce[i]/16), printf("%X", nonce[i]%16);
   	  printf("\n");
    ocb_encrypt(final, zeroes, nonce, c, next, zeroes, 0);
    if (NONCEBYTES == 12) {
        printf("AEAD_AES_%d_OCB_TAGLEN%d Output: ", KEYBYTES*8, TAGBYTES*8);
        for (i=0; i<TAGBYTES; i++) printf("%02X", final[i]); printf("\n");
    }

//    /* Decrypt and test for all zeros and authenticity */
//    result = ocb_decrypt(p, zeroes, nonce, c, next, final, TAGBYTES);
//    if (result) { printf("FAIL\n"); return 0; }
//    next = 0;
//    for (i=0; i<128; i++) {
//        nonce[11] = i;
//        result = ocb_decrypt(p, aesKey, nonce, zeroes, i, c+next, i+TAGBYTES);
//        if (result || memcmp(p,plainData,i)) { printf("FAIL\n"); return 0; }
//        next = next + i + TAGBYTES;
//        result = ocb_decrypt(p, aesKey, nonce, zeroes, 0, c+next, i+TAGBYTES);
//        if (result || memcmp(p,plainData,i)) { printf("FAIL\n"); return 0; }
//        next = next + i + TAGBYTES;
//        result = ocb_decrypt(p, aesKey, nonce, zeroes, i, c+next, TAGBYTES);
//        if (result || memcmp(p,plainData,i)) { printf("FAIL\n"); return 0; }
//        next = next + TAGBYTES;
//    }
//    print_hex_memory(p, 20);
    return 0;

}


