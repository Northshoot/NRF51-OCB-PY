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
#include "nrf_soc.h"
#include "nrf_sdm.h"
#include "softdevice_handler.h"
#include "nrf51.h"
#include "nrf_error.h"


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
    SOFTDEVICE_HANDLER_INIT(NRF_CLOCK_LFCLKSRC_XTAL_20_PPM, false);
    int i;
    nrf_ecb_init();
    uint8_t spam[16] ={0,};
    nrf_ecb_hal_data_t  datain = {
				.key={'A','A','A','A','A','A','A','A','A','A','A','A','A','A','A','A'},
				.cleartext={2,2,1,1,1,1,1,1,1,1,1,1,1,1,1,1},
				.ciphertext={0,}
	};
    sd_ecb_block_encrypt(&datain);
    printf("key: \n");
    for (i=0; i<16; i++) printf("%02X", datain.key[i]); printf("\n");

    printf("plain: \n");
    for (i=0; i<16; i++) printf("%02X", datain.cleartext[i]); printf("\n");

	bool r = sd_ecb_block_encrypt(&datain);
	printf("Encrypt: %d\n",r);
	for (i=0; i<16; i++) printf("%02X", datain.ciphertext[i]); printf("\n");

	memcpy(datain.cleartext, datain.ciphertext, sizeof datain.ciphertext);
	printf("datain.cleartext: \n");
	for (i=0; i<16; i++) printf("%02X", datain.cleartext[i]); printf("\n");
	memcpy(datain.ciphertext, spam, sizeof spam);
	r= sd_ecb_block_encrypt(&datain);
	printf("Decrypt: %d\n", r);
	for (i=0; i<16; i++) printf("%02X", datain.ciphertext[i]); printf("\n");

	        spam[w] ^= keyStream();
	return 0;
}


