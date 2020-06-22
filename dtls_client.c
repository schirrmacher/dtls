/*
 *  Simple DTLS client demonstration program
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
#define mbedtls_exit exit
#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE
#endif

#include <string.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "mbedtls/timing.h"

/* Uncomment out the following line to default to IPv4 and disable IPv6 */
//#define FORCE_IPV4

#define SERVER_PORT "4433"
#define SERVER_NAME "localhost"

#ifdef FORCE_IPV4
#define SERVER_ADDR "127.0.0.1" /* Forces IPv4 */
#else
#define SERVER_ADDR "::1"
#endif

#define READ_TIMEOUT_MS 1000
#define MAX_RETRY 5

#define DEBUG_LEVEL 0

static void my_debug(void *ctx, int level,
                     const char *file, int line,
                     const char *str)
{
    ((void)level);

    mbedtls_fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE *)ctx);
}

int main(int argc, char *argv[])
{
    int ret, len;
    mbedtls_net_context server_fd;
    uint32_t flags;
    unsigned char buf[1024];
    const char *pers = "dtls_client";
    int retry_left = MAX_RETRY;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt clientcert;
    mbedtls_pk_context pkey;
    mbedtls_timing_delay_context timer;

    ((void)argc);
    ((void)argv);

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    /*
     * 0. Initialize the RNG and the session data
     */
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&clientcert);
    mbedtls_pk_init(&pkey);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    printf("\nStarting client:\n");
    mbedtls_printf("- Seeding the random number generator...");
    fflush(stdout);
    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers,
                                     strlen(pers))) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    mbedtls_printf("- Loading the CA root certificate ...");
    fflush(stdout);

    const char *cafile = "pki/ca.pem";
    if ((ret = mbedtls_x509_crt_parse_file(&cacert, cafile)) != 0)
    {
        mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", (unsigned int)-ret);
        goto exit;
    }

    printf("\n- Loading the client cert. and key...");
    fflush(stdout);

    const char *clientfile = "pki/client.pem";
    if ((ret = mbedtls_x509_crt_parse_file(&clientcert, clientfile)) != 0)
    {
        printf(" failed\n  !  mbedtls_x509_crt_parse_file returned %d\n\n", ret);
        goto exit;
    }

    const char *clientkeyfile = "pki/client-key.pem";
    if ((ret = mbedtls_pk_parse_keyfile(&pkey, clientkeyfile, NULL)))
    {
        printf(" failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok (%d skipped)\n", ret);

    mbedtls_printf("- Connecting to udp/%s/%s...", SERVER_NAME, SERVER_PORT);
    fflush(stdout);

    if ((ret = mbedtls_net_connect(&server_fd, SERVER_ADDR,
                                   SERVER_PORT, MBEDTLS_NET_PROTO_UDP)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    mbedtls_printf("- Setting up the DTLS structure...");
    fflush(stdout);

    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    const int ciphersuites[] = {
        MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0};

    const mbedtls_ecp_group_id curves[] = {
        MBEDTLS_ECP_DP_SECP256R1,
        MBEDTLS_ECP_DP_NONE};

    mbedtls_ssl_conf_ciphersuites(&conf, ciphersuites);
    mbedtls_ssl_conf_curves(&conf, curves);

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    if ((ret = mbedtls_ssl_conf_own_cert(&conf, &clientcert, &pkey)) != 0)
    {
        printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_set_hostname(&ssl, SERVER_NAME)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &server_fd,
                        mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

    mbedtls_ssl_set_timer_cb(&ssl, &timer, mbedtls_timing_set_delay,
                             mbedtls_timing_get_delay);

    mbedtls_printf(" ok\n");

    mbedtls_printf("- Performing the DTLS handshake...");
    fflush(stdout);

    do
        ret = mbedtls_ssl_handshake(&ssl);
    while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", (unsigned int)-ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    mbedtls_printf("- Verifying peer X.509 certificate...");

    if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0)
    {
        char vrfy_buf[512];

        mbedtls_printf(" failed\n");

        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

        mbedtls_printf("%s\n", vrfy_buf);
    }
    else
        mbedtls_printf(" ok\n");

send_request:
    mbedtls_printf("- Write to server:");
    fflush(stdout);

    const unsigned char message[14] = "Hello Server!";
    len = sizeof(message) - 1;

    do
        ret = mbedtls_ssl_write(&ssl, message, len);
    while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret < 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
        goto exit;
    }

    len = ret;
    mbedtls_printf(" %d bytes written\n", len);

    mbedtls_printf("- Read from server:");
    fflush(stdout);

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
            mbedtls_printf(" timeout\n\n");
            if (retry_left-- > 0)
                goto send_request;
            goto exit;

        case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
            mbedtls_printf(" connection was closed gracefully\n");
            ret = 0;
            goto close_notify;

        default:
            mbedtls_printf(" mbedtls_ssl_read returned -0x%x\n\n", (unsigned int)-ret);
            goto exit;
        }
    }

    len = ret;
    mbedtls_printf(" %d bytes read\n\n%s\n\n", len, buf);

close_notify:
    mbedtls_printf("- Closing the connection...");

    do
        ret = mbedtls_ssl_close_notify(&ssl);
    while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret < 0)
    {
        printf(" failed\n  ! mbedtls_ssl_close_notify returned %d\n\n", ret);
    }
    else
    {
        mbedtls_printf(" done\n");
    }

    ret = 0;

exit:

#ifdef MBEDTLS_ERROR_C
    if (ret != 0)
    {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    mbedtls_net_free(&server_fd);

    mbedtls_x509_crt_free(&cacert);
    mbedtls_x509_crt_free(&clientcert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

#if defined(_WIN32)
    mbedtls_printf("  + Press Enter to exit this program.\n");
    fflush(stdout);
    getchar();
#endif

    /* Shell can not handle large exit numbers -> 1 for errors */
    if (ret < 0)
        ret = 1;

    mbedtls_exit(ret);
}