/*
 *  Simple DTLS server demonstration program
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf printf
#define mbedtls_fprintf fprintf
#define mbedtls_time_t time_t
#define mbedtls_exit exit
#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE
#endif

/* Uncomment out the following line to default to IPv4 and disable IPv6 */
//#define FORCE_IPV4

#ifdef FORCE_IPV4
#define BIND_IP "0.0.0.0" /* Forces IPv4 */
#else
#define BIND_IP "::"
#endif

#if defined(_WIN32)
#include <windows.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#define READ_TIMEOUT_MS 10000 /* 5 seconds */
#define DEBUG_LEVEL 0

static void my_debug(void *ctx, int level,
                     const char *file, int line,
                     const char *str)
{
  ((void)level);

  mbedtls_fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
  fflush((FILE *)ctx);
}

int main(void)
{
  int ret, len;
  mbedtls_net_context listen_fd, client_fd;
  unsigned char buf[1024];
  const char *pers = "dtls_server";
  unsigned char client_ip[16] = {0};
  size_t cliip_len;
  mbedtls_ssl_cookie_ctx cookie_ctx;

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_timing_delay_context timer;
#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_context cache;
#endif

  mbedtls_net_init(&listen_fd);
  mbedtls_net_init(&client_fd);
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);
  mbedtls_ssl_cookie_init(&cookie_ctx);
#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_init(&cache);
#endif
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

#if defined(MBEDTLS_DEBUG_C)
  mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

  printf("\nStarting server:\n");
  printf("- Loading client key...");
  fflush(stdout);

  const unsigned char psk_key[16] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  size_t psk_len = sizeof(psk_key);
  const char psk_id[] = "Client_identity";

  if ((ret = mbedtls_ssl_conf_psk(&conf, psk_key, psk_len,
                                  (const unsigned char *)psk_id,
                                  strlen(psk_id))) != 0)
  {
    mbedtls_printf("  mbedtls_ssl_conf_psk returned %d\n\n", ret);
  }

  printf(" ok\n");

  printf("- Bind on udp/*/4433 ...");
  fflush(stdout);

  if ((ret = mbedtls_net_bind(&listen_fd, BIND_IP, "4433", MBEDTLS_NET_PROTO_UDP)) != 0)
  {
    printf(" failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
    goto exit;
  }
  printf(" ok\n");

  printf("- Seeding the random number generator...");
  fflush(stdout);

  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                   (const unsigned char *)pers,
                                   strlen(pers))) != 0)
  {
    printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
    goto exit;
  }
  printf(" ok\n");

  printf("- Setting up the DTLS data...");
  fflush(stdout);

  if ((ret = mbedtls_ssl_config_defaults(&conf,
                                         MBEDTLS_SSL_IS_SERVER,
                                         MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
  {
    mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
    goto exit;
  }

  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
  mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_conf_session_cache(&conf, &cache,
                                 mbedtls_ssl_cache_get,
                                 mbedtls_ssl_cache_set);
#endif

  if ((ret = mbedtls_ssl_cookie_setup(&cookie_ctx,
                                      mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
  {
    printf(" failed\n  ! mbedtls_ssl_cookie_setup returned %d\n\n", ret);
    goto exit;
  }

  mbedtls_ssl_conf_dtls_cookies(&conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check,
                                &cookie_ctx);

  if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
  {
    printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
    goto exit;
  }

  mbedtls_ssl_set_timer_cb(&ssl, &timer, mbedtls_timing_set_delay,
                           mbedtls_timing_get_delay);

  printf(" ok\n");

reset:
#ifdef MBEDTLS_ERROR_C
  if (ret != 0)
  {
    char error_buf[100];
    mbedtls_strerror(ret, error_buf, 100);
    printf("Last error was: %d - %s\n\n", ret, error_buf);
  }
#endif

  mbedtls_net_free(&client_fd);

  mbedtls_ssl_session_reset(&ssl);

  printf("- Waiting for a remote connection ...");
  fflush(stdout);

  if ((ret = mbedtls_net_accept(&listen_fd, &client_fd,
                                client_ip, sizeof(client_ip), &cliip_len)) != 0)
  {
    printf(" failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
    goto exit;
  }

  /* For HelloVerifyRequest cookies */
  if ((ret = mbedtls_ssl_set_client_transport_id(&ssl,
                                                 client_ip, cliip_len)) != 0)
  {
    printf(" failed\n  ! "
           "mbedtls_ssl_set_client_transport_id() returned -0x%x\n\n",
           (unsigned int)-ret);
    goto exit;
  }

  mbedtls_ssl_set_bio(&ssl, &client_fd,
                      mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

  printf(" ok\n");

  printf("- Performing the DTLS handshake...");
  fflush(stdout);

  // do
  //   ret = mbedtls_ssl_handshake(&ssl);
  // while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
  //        ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  // if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED)
  // {
  //   printf(" hello verification requested\n");
  //   ret = 0;
  //   goto reset;
  // }
  // else if (ret != 0)
  // {
  //   printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", (unsigned int)-ret);
  //   goto reset;
  // }
  printf(" ok\n");

  printf("- Read from client:");
  fflush(stdout);

read:
  len = sizeof(buf) - 1;
  memset(buf, 0, sizeof(buf));

  do
    ret = mbedtls_ssl_read(&ssl, buf, len);
  while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
         ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  if (ret <= 0)
  {
    switch (ret)
    {
    case MBEDTLS_ERR_SSL_TIMEOUT:
      printf("- Timeout\n\n");
      goto reset;

    case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
      printf("- Connection was closed gracefully\n");
      ret = 0;
      goto reset;

    default:
      printf(" mbedtls_ssl_read returned -0x%x\n\n", (unsigned int)-ret);
      goto reset;
    }
  }

  len = ret;
  printf(" %d bytes read\n\n%s\n\n", len, buf);

  printf("- Write to client:");
  fflush(stdout);

  const unsigned char message[14] = "Hello Client!";
  len = sizeof(message) - 1;

  do
    ret = mbedtls_ssl_write(&ssl, message, len);
  while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
         ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  if (ret < 0)
  {
    printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
    goto exit;
  }

  len = ret;
  printf(" %d bytes written\n", len);

  goto read;

exit:

#ifdef MBEDTLS_ERROR_C
  if (ret != 0)
  {
    char error_buf[100];
    mbedtls_strerror(ret, error_buf, 100);
    printf("Last error was: %d - %s\n\n", ret, error_buf);
  }
#endif

  mbedtls_net_free(&client_fd);
  mbedtls_net_free(&listen_fd);

  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_config_free(&conf);
  mbedtls_ssl_cookie_free(&cookie_ctx);
#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_free(&cache);
#endif
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);

#if defined(_WIN32)
  printf("  Press Enter to exit this program.\n");
  fflush(stdout);
  getchar();
#endif

  /* Shell can not handle large exit numbers -> 1 for errors */
  if (ret < 0)
    ret = 1;

  mbedtls_exit(ret);
}
