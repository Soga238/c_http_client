/****************************************************************************
 * Copyright (c) [2019] [core.zhang@outlook.com]                            *
 * [C http] is licensed under Mulan PSL v2.                                 *
 * You can use this software according to the terms and conditions of       *
 * the Mulan PSL v2.                                                        *
 * You may obtain a copy of Mulan PSL v2 at:                                *
 *          http://license.coscl.org.cn/MulanPSL2                           *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF     *
 * ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO        *
 * NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.       *
 * See the Mulan PSL v2 for more details.                                   *
 *                                                                          *
 ***************************************************************************/
/* Includes --------------------------------------------------------*/
#include "./platform_config.h"
#include "./platform_net.h"
#include "./platform_ssl.h"

/* Global variables ------------------------------------------------*/
/* Private typedef -------------------------------------------------*/
/* Private define --------------------------------------------------*/
#if defined(_WIN32)
#include <WinSock2.h>
#   if defined(_WIN32_WCE)
#       pragma comment( lib, "ws2.lib")
#   else
#       pragma comment( lib, "ws2_32.lib")
#   endif
#endif

#if HTTPS_USE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#elif (HTTPS_USE_WOLFSSL)
#include "./3rdparty/wolfSSL/wolfssl/openssl/ssl.h"
#include "./3rdparty/wolfSSL/wolfssl/openssl/err.h"
#elif HTTPS_USE_KRYPTON
#include "./3rdparty/krypton//krypton.h"
#endif

/* Private macro ---------------------------------------------------*/
/* Private variables -----------------------------------------------*/
/* Private function prototypes -------------------------------------*/
/* Private functions -----------------------------------------------*/

#if defined(FT_SUPPORT_HTTPS)

int platform_ssl_env_setup(void)
{
#if defined(_WIN32)
    {
        WORD version = MAKEWORD(2, 2);
        WSADATA data;
        WSAStartup(version, &data);
    }
#endif

#if (HTTPS_USE_OPENSSL)
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
#elif (HTTPS_USE_MBEDTLS)

#endif

#if (HTTPS_USE_OPENSSL) || (HTTPS_USE_KRYPTON)
    SSL_library_init();
#endif
    return 0;
}

int platform_ssl_env_exit(void)
{
#if defined(_WIN32)
    {
        WSACleanup();
    }
#endif
    return 0;
}

//static void *ssl_ctx_init(const char *cert, const char *key)
//{
//    return NULL;
//}

static void *ssl_ctx_new(void)
{
    return SSL_CTX_new(SSLv23_client_method());
}

static void ssl_ctx_free(void *ctx)
{
    SSL_CTX_free(ctx);
}

static void *ssl_new(void *ctx, int sock)
{
    void *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    return ssl;
}

static void ssl_free(void *ssl)
{
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

int platform_ssl_connect(platform_ssl_t *wrapper)
{
    void *ssl, *ctx;

    if (NULL == wrapper->ssl) {
        ctx = ssl_ctx_new();
        if (NULL == ctx) {
            printf("ssl_ctx_new failed!");
            return -1;
        }

        ssl = ssl_new(ctx, wrapper->net_ctx.fd);
        if (NULL == ssl) {
            printf("ssl_new failed!");
            ssl_ctx_free(ctx);
            wrapper->ctx = NULL;
            return -1;
        }

        wrapper->ssl = ssl;
        wrapper->ctx = ctx;
    }

    if (0 < SSL_connect(wrapper->ssl)) {
        return 0;
    }

    return -1;
}

int platform_ssl_read(platform_ssl_t *wrapper, void *buf, size_t count)
{
    return SSL_read(wrapper->ssl, buf, count);
}

int platform_ssl_write(platform_ssl_t *wrapper, const void *buf, size_t count)
{
    return SSL_write(wrapper->ssl, buf, count);
}

void platform_ssl_destroy(platform_ssl_t *wrapper)
{
    if (NULL != wrapper) {
        ssl_ctx_free(wrapper->ctx);
        ssl_free(wrapper->ssl);
    }
}

#endif

/*************************** End of file ****************************/
