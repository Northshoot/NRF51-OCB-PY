/*
 * main.c
 *
 *  Created on: Mar 2, 2015
 *      Author: lauril
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "nrf_delay.h"
#include "nrf_gpio.h"
#include "boards.h"
#include "nrf.h"
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
#include "tiny-AES128-C/aes.h"

#define UART_TX_BUF_SIZE 512                                                          /**< UART TX buffer size. */
#define UART_RX_BUF_SIZE 1

#define APP_TIMER_PRESCALER                  0                                          /**< Value of the RTC1 PRESCALER register. */
#define APP_TIMER_MAX_TIMERS                 3                                          /**< Maximum number of simultaneously created timers. */
#define APP_TIMER_OP_QUEUE_SIZE              4                                          /**< Size of timer operation queues. */
#define ECB 1 // used for software AES

void uart_error_handle(app_uart_evt_t * p_event) {
	if (p_event->evt_type == APP_UART_COMMUNICATION_ERROR) {
		APP_ERROR_HANDLER(p_event->data.error_communication);
	} else if (p_event->evt_type == APP_UART_FIFO_ERROR) {
		APP_ERROR_HANDLER(p_event->data.error_code);
	}
}

static app_timer_id_t m_timer;
#define BATTERY_LEVEL_MEAS_INTERVAL          APP_TIMER_TICKS(10000, APP_TIMER_PRESCALER)




#define PLAIN_SIZE 256
static void testOCB(){
	static uint32_t s_ticks;
	static uint32_t e_ticks;
	static uint32_t r_ticks;
	uint32_t err = 0;

	uint8_t text[PLAIN_SIZE] = { 0, };
	uint8_t p[PLAIN_SIZE] = { 1, };
	uint8_t zeroes[PLAIN_SIZE] = { 0, };
	uint8_t nonce[16] = { 0, };

	uint8_t keyArray[KEYBYTES] = { 0, };
	uint8_t *c;
	//unsigned i;
	/* Encrypt and output RFC vector */
	c = malloc(PLAIN_SIZE + TAGBYTES);
	/// ----- encrypt
	err = app_timer_cnt_get(&s_ticks);
	APP_ERROR_CHECK(err);
	ocb_encrypt(c, keyArray, nonce, zeroes, PLAIN_SIZE, text, PLAIN_SIZE);
	err = app_timer_cnt_get(&e_ticks);
	APP_ERROR_CHECK(err);
	err = app_timer_cnt_diff_compute(e_ticks, s_ticks, &r_ticks);
	APP_ERROR_CHECK(err);
	printf("Took %.3f microseconds to encrypt OCB %d size byte datablock \n\n",
			(float) r_ticks / 32.0, PLAIN_SIZE);

//	printf("Chipper: \n");
//	for (i = 0; i < (PLAIN_SIZE + TAGBYTES); i++)
//		printf("%d, ", (unsigned int) *(c + i));
//	printf("\n");

	/// ----- decrypt
	err = app_timer_cnt_get(&s_ticks);
	APP_ERROR_CHECK(err);
	ocb_decrypt(p, keyArray, nonce, zeroes, PLAIN_SIZE, c, PLAIN_SIZE);
	err = app_timer_cnt_get(&e_ticks);
	APP_ERROR_CHECK(err);
	err = app_timer_cnt_diff_compute(e_ticks, s_ticks, &r_ticks);
	APP_ERROR_CHECK(err);
	printf("Took %.3f microseconds to decrypt OCB %d size byte datablock \n\n",
			(float) r_ticks / 32.0, PLAIN_SIZE);

//	printf("cleartext: \n");
//	for (i = 0; i < PLAIN_SIZE; i++)
//		printf("%d, ", (unsigned int) p[i]);
//	printf("\n");
	printf("\n");
	free(c);
}


static void timer_handler(void * p_context) {
	testOCB();
}

static void init(){
	uint32_t err_code;
	APP_GPIOTE_INIT(1);
	const app_uart_comm_params_t comm_params = { RX_PIN_NUMBER, TX_PIN_NUMBER,
			RTS_PIN_NUMBER, CTS_PIN_NUMBER, APP_UART_FLOW_CONTROL_ENABLED,
			false,
			UART_BAUDRATE_BAUDRATE_Baud38400 };

	APP_UART_FIFO_INIT(&comm_params,
	UART_RX_BUF_SIZE,
	UART_TX_BUF_SIZE, uart_error_handle, APP_IRQ_PRIORITY_LOW, err_code);

	APP_ERROR_CHECK(err_code);

	SOFTDEVICE_HANDLER_INIT(NRF_CLOCK_LFCLKSRC_XTAL_20_PPM, false);
	// Initialize timer module.
	APP_TIMER_INIT(APP_TIMER_PRESCALER, APP_TIMER_MAX_TIMERS,
			APP_TIMER_OP_QUEUE_SIZE, false);
	// Create timers.
	err_code = app_timer_create(&m_timer, APP_TIMER_MODE_REPEATED,
			timer_handler);

	// Start application timers.
	err_code = app_timer_start(m_timer, BATTERY_LEVEL_MEAS_INTERVAL,
			NULL);
	APP_ERROR_CHECK(err_code);
}

int main(void) {
	init();
	nrf_ecb_init();
	testOCB(); //will get executed by timer
	//testAES();
	return 0;

}

