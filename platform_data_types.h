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

#ifndef HTTPCLIENT_PLATFORM_DATA_TYPES_H
#define HTTPCLIENT_PLATFORM_DATA_TYPES_H
#ifdef __cplusplus
extern "C" {
#endif

/* Includes --------------------------------------------------------*/
#include "platform_config.h"

/* Global variables ------------------------------------------------*/
/* Global typedef --------------------------------------------------*/
#define PLATFORM_ERR_NET_MAP(XX)                    \
  XX(-101,  SOCKET_FAILED ,     SOCKET_FAILED)      \
  XX(-102,  UNKNOWN_HOST,       UNKNOWN_HOST)       \
  XX(-103,  SEND_FAILED,        SEND_FAILED)        \
  XX(-104,  RECV_FAILED,        RECV_FAILED)        \
  XX(-105,  POLL_FAILED,        POLL_FAILED)        \
  XX(-106,  INVALID_CONTEXT ,   INVALID_CONTEXT)    \
  XX(-107,  CONNECT_FAILED,     CONNECT_FAILED)     \
  XX(-108,  CONN_RESET,         CONN_RESET)         \
  XX(-109,  BUFFER_TOO_SMALL,   BUFFER_TOO_SMALL)   \
  XX(-110,  BIND_FAILED,        BIND_FAILED)        \
  XX(-111,  BAD_INPUT_DATA,     BAD_INPUT_DATA)     \
  XX(-112,  ACCEPT_FAILED,      ACCEPT_FAILED)      \

enum platform_net_error {
#define XX(num, name, string) PLATFORM_ERR_NET_##name = (num),
    PLATFORM_ERR_NET_MAP(XX)
#undef XX
};

/*!  Wrapper type for sockets. */
typedef struct platform_net_ctx platform_net_ctx_t;
struct platform_net_ctx {
    int fd;
};

/*!  Wrapper type for ssl */
typedef struct platform_ssl platform_ssl_t;
struct platform_ssl {
    platform_net_ctx_t net_ctx;
    void *ssl;
    void *ctx;
};

/* Global define ---------------------------------------------------*/
#if defined(_WIN32)
#   ifndef USE_WINDOWS_API
#       define USE_WINDOWS_API
#   endif
#endif

/* Standard wrappers */
#ifndef HTTP_CUSTOM_STRING
#   include <string.h>

#   ifndef M_STRLEN
#       define M_STRLEN(s1)             strlen((s1))
#   endif
#   ifndef M_STRCHR
#       define M_STRCHR(s, c)           strchr((s),(c))
#   endif
#   ifndef M_STRNCMP
#       define M_STRNCMP(s1, s2, n)     strncmp((s1),(s2),(n))
#   endif
#   ifndef M_STRNCPY
#       define M_STRNCPY(s1, s2, n)     strncpy((s1),(s2),(n))
#   endif
#   ifndef M_MEMCPY
#       define M_MEMCPY(d, s, l)        memcpy((d),(s),(l))
#   endif
#   ifndef M_MEMSET
#       define M_MEMSET(b, c, l)        memset((b),(c),(l))
#   endif
#   ifndef M_STRICMP
#       ifndef USE_WINDOWS_API
#           define M_STRICMP            strcasecmp
#       else
#           define M_STRICMP            _stricmp
#       endif
#   endif
#   ifndef M_STRNICMP
#       ifndef USE_WINDOWS_API
#           define M_STRNICMP           strncasecmp
#       else
#           define M_STRNICMP           _strnicmp
#       endif
#   endif
#   ifndef M_STRDUP
#       ifndef USE_WINDOWS_API
#           define M_STRDUP             strdup
#       else
#           define M_STRDUP             _strdup
#       endif
#   endif
#endif

#ifndef HTTP_CUSTOM_STDLIB
#   include <stdio.h>

#   ifndef M_SNPRINTF
#       ifndef USE_WINDOWS_API
#           define M_SNPRINTF           snprintf
#       else
#           define M_SNPRINTF           _snprintf
#       endif
#   endif
#   ifndef M_SPRINTF
#       define M_SPRINTF                sprintf
#   endif
#endif

#ifndef HTTP_CUSTOM_STDLIB
#   include <stdlib.h>

#   ifndef M_STRTOL
#       define M_STRTOL(s, e, b)        strtol((s), (e), (b))
#   endif
#endif

#ifndef HTTP_CUSTOM_MALLOC
#   ifndef M_HTTP_MALLOC
#       define M_HTTP_MALLOC(s)         malloc((s))
#   endif
#   ifndef M_HTTP_FREE
#       define M_HTTP_FREE(p)           do {void* xp = (p); if((xp)) free((xp));} while(0)
#   endif
#   ifndef M_HTTP_CALLOC
#       define M_HTTP_CALLOC(n, s)      calloc((n), (s))
#   endif
#   ifndef M_HTTP_REALLOC
#       define M_HTTP_REALLOC(p, n)     realloc((p), (n))
#   endif
#endif

#ifndef HTTP_CUSTOM_ASSERT
#   define NDEBUG
#       include <assert.h>
#   undef  NDEBUG

#   ifndef M_HTTP_ASSERT
#       define M_HTTP_ASSERT(...)       assert(__VA_ARGS__)
#   endif
#endif

/* printf */
#ifndef HTTP_CUSTOM_PRINT
#   ifndef LINE_END
#       define LINE_END    "\n"
#   endif
#   ifndef HTTP_PRINTF
#       include "stdio.h"
#       define HTTP_PRINTF(...)     printf(__VA_ARGS__)
#   endif
#   undef LINE_END
#endif

#define HTTP_API

/* Global macro ----------------------------------------------------*/
/* Global variables ------------------------------------------------*/
/* Global function prototypes --------------------------------------*/

#ifdef __cplusplus
}
#endif
#endif

/*************************** End of file ****************************/
