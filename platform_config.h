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
#ifndef HTTPCLIENT_PLATFORM_CONFIG_H
#define HTTPCLIENT_PLATFORM_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes --------------------------------------------------------*/
/* Global variables ------------------------------------------------*/
/* Global typedef --------------------------------------------------*/
/* Global define ---------------------------------------------------*/
#define CONFIG_HOST_MAX_SIZE    64           // host buf max size
#define CONFIG_BODY_MAX_SIZE    4096         // body buf max size

//#define HTTPS_USE_OPENSSL       1
#define HTTPS_USE_KRYPTON       1
//#define HTTPS_USE_WOLFSSL       1
//#define HTTPS_USE_MBEDTLS       1

#if (HTTPS_USE_OPENSSL) || (HTTPS_USE_KRYPTON) || \
    (HTTPS_USE_MBEDTLS) || (HTTPS_USE_WOLFSSL)

#if  (HTTPS_USE_OPENSSL + HTTPS_USE_KRYPTON + HTTPS_USE_WOLFSSL + HTTPS_USE_MBEDTLS) > 1
#error "Duplicate SSL definition"
#endif
#define FT_SUPPORT_HTTPS
#endif

/* Global macro ----------------------------------------------------*/
/* Global variables ------------------------------------------------*/
/* Global function prototypes --------------------------------------*/

#ifdef __cplusplus
}
#endif

#endif

/*************************** End of file ****************************/
