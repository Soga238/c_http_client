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
#include "./platform_net.h"

/* Global variables ------------------------------------------------*/
/* Private typedef -------------------------------------------------*/
/* Private define --------------------------------------------------*/
#if defined(_WIN32)

#include <WinSock2.h>
#include <WS2tcpip.h>

#if defined(_WIN32_WCE)
#pragma comment( lib, "ws2.lib")
#else
#pragma comment( lib, "ws2_32.lib")
#endif

#define IS_EINTR(__ERR) ((__ERR) == WSAEINTR )
#define close(fd)       closesocket(fd)

#else

#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "errno.h"
#include "signal.h"

#define IS_EINTR(__ERR)  ((__ERR) == EINTR)
#endif

#if defined(_MSC_VER)
#define MSVC_INT_CAST   (int)
#else
#define MSVC_INT_CAST
#endif
/* Private macro ---------------------------------------------------*/
/* Private variables -----------------------------------------------*/
/* Private function prototypes -------------------------------------*/
/* Private functions -----------------------------------------------*/

int platform_net_env_setup(void)
{
#if defined(_WIN32)
    {
        WORD version = MAKEWORD(2, 2);
        WSADATA data;
        if (0 != WSAStartup(version, &data)) {
            return -1;
        }
    }
#endif
    return 0;
}

void platform_net_env_exit(void)
{
#if defined(_WIN32)
    {
        WSACleanup();
    }
#endif
}

/**
 *      socket 连接函数，返回0表示连接成功
 * */
#if defined(_WIN32)

int platform_net_connect(platform_net_ctx_t *ctx, const char *host,
                         const char *port, int proto)
{
    int ret;
    struct addrinfo hints, *addr_list, *cur;
    struct sockaddr_in sock_addr;

    HTTP_PRINTF("host: %s\r\n", host);
    HTTP_PRINTF("port: %d\r\n", (int) port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;

    if (getaddrinfo(host, NULL, &hints, &addr_list) != 0) {
        HTTP_PRINTF("get addr info failed!\n");
        return PLATFORM_ERR_NET_UNKNOWN_HOST;
    }

    ret = PLATFORM_ERR_NET_UNKNOWN_HOST;
    for (cur = addr_list; cur != NULL; cur = cur->ai_next) {
        if (cur->ai_family == AF_INET) {
            break;
        }
    }

    if (NULL == cur || cur->ai_family != AF_INET) {
        goto __exit;
    }

    sock_addr.sin_port = htons(port);
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr = ((struct sockaddr_in *) cur->ai_addr)->sin_addr;

    ctx->fd = (int) socket(sock_addr.sin_family, SOCK_STREAM, 0);
    if (ctx->fd < 0) {
        ret = PLATFORM_ERR_NET_SOCKET_FAILED;
        goto __exit;
    }

    ret = connect(ctx->fd, (struct sockaddr *) &sock_addr, sizeof(sock_addr));
    if (ret == 0) {
        HTTP_PRINTF("connect ok\n");
    } else {
        HTTP_PRINTF("connect failed\n");
        close(ctx->fd);
        ctx->fd = -1;
        ret = PLATFORM_ERR_NET_CONNECT_FAILED;
    }

    __exit:
    freeaddrinfo(addr_list);
    return ret;
}

#else
int platform_net_connect(platform_net_ctx_t *ctx, const char *host, const char *port, int proto)
{
    HTTP_PRINTF("host: %s\r\n", host);
    HTTP_PRINTF("port: %d\r\n", (int)port);

    struct sockaddr_in sin;
    if (host[0] >= '0' && host[0] <= '9') {
        sin.sin_addr.s_addr = (unsigned long) inet_addr(host);
    } else {
        struct hostent *he = gethostbyname(host);
        if (he == NULL || he->h_addrtype != AF_INET) {
            return PLATFORM_ERR_NET_UNKNOWN_HOST;
        }
        sin.sin_addr = *((struct in_addr *) he->h_addr_list[0]);
    }

    if (sin.sin_addr.s_addr == INADDR_NONE) {
        return PLATFORM_ERR_NET_UNKNOWN_HOST;
    }

    sin.sin_port = htons(port);
    sin.sin_family = AF_INET;

    ctx->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ctx->fd <= 0) {
        return PLATFORM_ERR_NET_SOCKET_FAILED;
    }

    struct linger linger;
    linger.l_onoff = 1;
    linger.l_linger = 0;
    setsockopt(ctx->fd, SOL_SOCKET, SO_LINGER, (const char *) &linger, sizeof(linger));

    if (connect(ctx->fd, (struct sockaddr *) &sin, sizeof(sin)) == 0) {
        HTTP_PRINTF("connect succ!\r\n");
        return 0;
    }

    return PLATFORM_ERR_NET_CONNECT_FAILED;
}
#endif

int platform_net_recv(void *ctx, void *buf, size_t n, int flags)
{
    int fd = ((platform_net_ctx_t *) ctx)->fd;
    return recv(fd, buf, n, flags);
}

int platform_net_send(void *ctx, const void *buf, size_t n, int flags)
{
    int fd = ((platform_net_ctx_t *) ctx)->fd;
    return send(fd, buf, n, flags);
}

void platform_net_close(void *ctx)
{
    platform_net_ctx_t *_ctx = (platform_net_ctx_t *) ctx;
    close(_ctx->fd);
    _ctx->fd = -1;
}

int platform_net_poll(platform_net_ctx_t *ctx, int rw, unsigned int timeout)
{
    int ret;
    struct timeval tv;

    fd_set read_fds;
    fd_set write_fds;

    int fd = ctx->fd;

    if (fd < 0) {
        return PLATFORM_ERR_NET_INVALID_CONTEXT;
    }

    FD_ZERO(&read_fds);
    if (rw & PLATFORM_NET_POLL_READ) {
        rw &= ~PLATFORM_NET_POLL_READ;
        FD_SET(fd, &read_fds);
    }

    FD_ZERO(&write_fds);
    if (rw & PLATFORM_NET_POLL_WRITE) {
        rw &= ~PLATFORM_NET_POLL_WRITE;
        FD_SET(fd, &write_fds);
    }

    if (rw != 0) {
        return PLATFORM_ERR_NET_BAD_INPUT_DATA;
    }

    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    do {
        ret = select(fd + 1, &read_fds, &write_fds, NULL,
                     timeout == (unsigned int) -1 ? NULL : &tv);
    } while (IS_EINTR(ret));

    if (ret < 0) {
        return PLATFORM_ERR_NET_POLL_FAILED;
    }

    ret = 0;
    if (FD_ISSET(fd, &read_fds)) {
        ret |= PLATFORM_NET_POLL_READ;
    }
    if (FD_ISSET(fd, &write_fds)) {
        ret |= PLATFORM_NET_POLL_WRITE;
    }

    return ret;
}

/*************************** End of file ****************************/
