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

#ifndef C_HTTP_H
#define C_HTTP_H

/* Includes --------------------------------------------------------*/
#include "platform_config.h"
#include "platform_data_types.h"

/* Global variables ------------------------------------------------*/
/* Global typedef --------------------------------------------------*/
typedef enum http_request_method_e {
    M_GET = 0,
    M_POST,
} http_request_method_e;

/*! https://github.com/prettymuchbryce/http-status-codes */
#define HTTP_STATUS_CODE_MAP(XX)                \
  XX(200,  OK ,                 "OK")           \
  XX(400,  BAD_REQUEST,         "Bad Request")  \
  XX(404,  NOT_FOUND,           "Not Found")    \
  XX(502,  BAD_GATEWAY,         "Bad Gateway")  \

enum http_status_code {
#define XX(num, name, string) HTTP_STATUS_CODE_##name = (num),
    HTTP_STATUS_CODE_MAP(XX)
#undef XX
};

enum http_error_e {
    ERR_OK = 0,

    ERR_INVALID_PARAM = -1,
    ERR_OPEN_FILE = -2,
    ERR_OUT_MEMORY = -3,
    ERR_NO_RESOURCE = -4,
    ERR_UNSUPPORT = -5,
    ERR_PARSE_REP = -6,
    ERR_BAD_RESPONSE = -7,

    ERR_URL_INVALID = -11,
    ERR_URL_INVALID_HOST = -13,

    ERR_SOCKET_CONNECT = -24,
    ERR_SOCKET_WRITE = -25,
    ERR_SOCKET_READ = -26,

#if defined(FT_SUPPORT_HTTPS)
    ERR_SSL_CREATE_CTX,
    ERR_SSL_CREATE_SSL,
    ERR_SSL_SET_FD,
    ERR_SSL_CONNECT,
    ERR_SSL_WRITE,
    ERR_SSL_READ
#endif

};

enum proto_type_e {
    PROTO_HTTP = 0, PROTO_HTTPS
};

typedef struct http_client_t uc_http_client_t;

typedef int(*uc_http_recv_cb_t)
    (void *http, const char *data, int size, int total, void *user);

struct http_client_t {
    FILE *pf;

    char *filename;
    char *body;
    char *redirect_url;
    char *header_field;
    char *header_value;

    unsigned short header_field_size;
    unsigned short header_value_size;
    unsigned long body_len;
    unsigned long content_length;

    void *ctx;
    uc_http_recv_cb_t recv_cb;

    enum http_request_method_e method;
    enum proto_type_e proto_type;

#if defined(FT_SUPPORT_HTTPS)
    platform_ssl_t ssl_wrapper;
#endif
    platform_net_ctx_t net_ctx;

    int error_code;
    unsigned short status_code;
    char parser_state;

    unsigned char cancel : 1;
    unsigned char exit : 1;
    unsigned char download : 1;
    unsigned char redirect : 1;
};

/* Global define ---------------------------------------------------*/
/* Global macro ----------------------------------------------------*/
/* Global variables ------------------------------------------------*/
/* Global function prototypes --------------------------------------*/

/**
 *  \brief: 设置http运行环境，根据硬件平台选择使用
 *  \retval:
 */
HTTP_API int uc_http_env_setup(void);

/**
 *  \brief: 退出http运行环境，根据硬件平台选择使用
 *  \retval:
 */
HTTP_API int uc_http_env_exit(void);

/**
 *  \brief: 生成一个 uc_http_client_t 对象
 *  \retval: uc_http_client_t 结构体指针
 */
HTTP_API uc_http_client_t *uc_http_new(void);

/**
 *  \brief: 释放一个 uc_http_client_t 对象
 *  \retval:
 */
HTTP_API void uc_http_destroy(uc_http_client_t *http);

/**
 *  \brief: 完成一次http请求，并把应答写入指定的文件中，若文件不存在则创建文件
 *  \param[in]: http     指向 uc_http_client_t 类型的结构体指针
 *  \param[in]: url      服务器域名或者ip地址
 *  \param[in]: filename 文件保存路径
 *  \retval: 错误码
 */
HTTP_API int uc_http_sync_download_file(uc_http_client_t *http,
                                        const char *url,
                                        const char *filename);

/**
 *  \brief: 完成一次http请求，保存应答内容到内存数组中
 *  \param[in]: http     指向 uc_http_client_t 类型的结构体指针
 *  \param[in]: url      服务器域名或者ip地址
 *  \retval: 内存数组地址
 */
HTTP_API const char *uc_http_sync_get(uc_http_client_t *http,
                                      const char *url);

/**
 *  \brief: 完成一次http请求，并把应答写入指定的文件中，若文件不存在则创建文件
 *  \param[in]: http     指向 uc_http_client_t 类型的结构体指针
 *  \param[in]: url      服务器域名或者ip地址
 *  \param[in]: filename 文件保存路径
 *  \retval:
 */
HTTP_API void uc_http_set_recv_cb(uc_http_client_t *http,
                                  uc_http_recv_cb_t cb,
                                  void *user_ctx);

#endif

/*************************** End of file ****************************/
