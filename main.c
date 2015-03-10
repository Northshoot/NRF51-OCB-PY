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
#include <inttypes.h>

#include "nrf_delay.h"
#include "nrf_gpio.h"
#include "boards.h"
#include <stdio.h>
#include "nrf.h"
#include "nrf_temp.h"
#include "app_uart.h"
#include "app_error.h"
#include "app_gpiote.h"
#include "app_timer.h"
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
#define PLAIN_SIZE 32
#define APP_TIMER_PRESCALER                  0                                          /**< Value of the RTC1 PRESCALER register. */
#define APP_TIMER_MAX_TIMERS                 3                                          /**< Maximum number of simultaneously created timers. */
#define APP_TIMER_OP_QUEUE_SIZE              4                                          /**< Size of timer operation queues. */

const uint8_t leds_list[LEDS_NUMBER] = LEDS_LIST;

void uart_error_handle(app_uart_evt_t * p_event) {
	if (p_event->evt_type == APP_UART_COMMUNICATION_ERROR) {
		APP_ERROR_HANDLER(p_event->data.error_communication);
	} else if (p_event->evt_type == APP_UART_FIFO_ERROR) {
		APP_ERROR_HANDLER(p_event->data.error_code);
	}
}

void print_hex_memory(void *mem, int len) {
	int i;
	uint8_t *p = (uint8_t *) mem;
	for (i = 0; i < len; i++) {
		printf("0x%02x ", p[i]);
	}
	printf("\n");
}
static app_timer_id_t m_battery_timer_id;
#define BATTERY_LEVEL_MEAS_INTERVAL          APP_TIMER_TICKS(200000, APP_TIMER_PRESCALER)

static void timer_handler(void * p_context) {
	static uint32_t ticks;
	uint32_t err = app_timer_cnt_get(&ticks);
	APP_ERROR_CHECK(err);
	printf("Ticks %" PRIu32 " \n", ticks);
}
int main(void) {

//    int32_t volatile temp;
	uint32_t err_code;
	// Configure LED-pins as outputs.
	LEDS_CONFIGURE(LEDS_MASK);
	nrf_temp_init();

	APP_GPIOTE_INIT(1);
	const app_uart_comm_params_t comm_params = { RX_PIN_NUMBER, TX_PIN_NUMBER,
			RTS_PIN_NUMBER, CTS_PIN_NUMBER, APP_UART_FLOW_CONTROL_ENABLED,
			false,
			UART_BAUDRATE_BAUDRATE_Baud38400 };

	APP_UART_FIFO_INIT(&comm_params,
	UART_RX_BUF_SIZE,
	UART_TX_BUF_SIZE, uart_error_handle, APP_IRQ_PRIORITY_LOW, err_code);

	APP_ERROR_CHECK(err_code);
	printf("Booted \n");
	SOFTDEVICE_HANDLER_INIT(NRF_CLOCK_LFCLKSRC_XTAL_20_PPM, false);
	// Initialize timer module.
	APP_TIMER_INIT(APP_TIMER_PRESCALER, APP_TIMER_MAX_TIMERS,
			APP_TIMER_OP_QUEUE_SIZE, false);
	// Create timers.
	err_code = app_timer_create(&m_battery_timer_id, APP_TIMER_MODE_REPEATED,
			timer_handler);

	// Start application timers.
	err_code = app_timer_start(m_battery_timer_id, BATTERY_LEVEL_MEAS_INTERVAL,
			NULL);
	APP_ERROR_CHECK(err_code);
	static uint32_t s_ticks;
	static uint32_t e_ticks;
	static uint32_t r_ticks;
	uint32_t err = 0;

	uint8_t text[PLAIN_SIZE] = { 0, };
	uint8_t zeroes[PLAIN_SIZE] = { 0, };
	uint8_t nonce[16] = { 0, };

	uint8_t keyArray[KEYBYTES] = { 0, };
//	uint8_t chiper_ref[PLAIN_SIZE + TAGBYTES] = { 1, 112, 133, 71, 186, 214,
//			151, 107, 185, 18, 31, 46, 66, 122, 167, 95, 103, 114, 82, 134, 2,
//			55, 253, 137, 244, 10, 229, 108, 14, 64, 247, 220 };
	uint8_t *c;
	unsigned i;
//    for(i=0;i<PLAIN_SIZE;i++) {
//    	text[i]=i;
//    }

	ocb_init((uint8_t *) &keyArray);
	/* Encrypt and output RFC vector */
	c = malloc(PLAIN_SIZE + TAGBYTES);
	err = app_timer_cnt_get(&s_ticks);
	APP_ERROR_CHECK(err);
	ocb_encrypt(c, keyArray, nonce, zeroes, PLAIN_SIZE, text, PLAIN_SIZE);
	err = app_timer_cnt_get(&e_ticks);
	APP_ERROR_CHECK(err);
	err = app_timer_cnt_diff_compute(e_ticks, s_ticks, &r_ticks);
	APP_ERROR_CHECK(err);
//    if ( ! memcmp(&c,chiper_ref,PLAIN_SIZE+TAGBYTES)) { printf("FAIL\n"); } else {printf("PASS\n");}
	printf("\nTook %.3f microseconds to OCB %d size byte datablock \n\n",
			(float) r_ticks / 32.0, PLAIN_SIZE);

	printf("Chipper: \n");
	for (i = 0; i < (PLAIN_SIZE + TAGBYTES); i++)
		printf("%u,", (unsigned int) *(c + i));
	printf("\n");


	free(c);
	// Enter main loop.

	return 0;

}

