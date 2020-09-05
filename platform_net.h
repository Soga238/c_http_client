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
#ifndef HTTPCLIENT_PLATFORM_NET_SOCKET_H
#define HTTPCLIENT_PLATFORM_NET_SOCKET_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes --------------------------------------------------------*/
#include "./platform_data_types.h"

/* Global variables ------------------------------------------------*/
/* Global typedef --------------------------------------------------*/
/* Global define ---------------------------------------------------*/
#define PLATFORM_PROTOCOL_TCP       1
//#define PLATFORM_PROTOCOL_UDP       2

#define PLATFORM_NET_POLL_READ      (1ul << 0)    /*! Used in platform_net_poll to check for pending data. */
#define PLATFORM_NET_POLL_WRITE     (1ul << 1)    /*! Used in platform_net_poll to check if write possible. */
//#define PLATFORM_NET_POLL_ERROR     (1 << 2)

/* Global macro ----------------------------------------------------*/
/* Global variables ------------------------------------------------*/
/* Global function prototypes --------------------------------------*/

extern int  platform_net_env_setup(void);

extern void platform_net_env_exit(void);

extern int  platform_net_connect(platform_net_ctx_t *ctx, const char *host, const char *port, int proto);

extern int  platform_net_recv(void *ctx, void *buf, size_t n, int flags);

extern int  platform_net_send(void *ctx, const void *buf, size_t n, int flags);

extern void platform_net_close(void *ctx);

extern int  platform_net_poll(platform_net_ctx_t *ctx, int rw, unsigned int timeout);

#ifdef __cplusplus
}
#endif
#endif

/*************************** End of file ****************************/
