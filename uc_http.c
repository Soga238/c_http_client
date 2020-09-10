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
#include "./3rdparty/http_parser/http_parser.h"
#include "./platform_ssl.h"
#include "./platform_net.h"
#include "./uc_http.h"

/* Global variables ------------------------------------------------*/
/* Private typedef -------------------------------------------------*/
typedef struct {
    struct http_parser_url *parser;
    const char *url;
    const char *body;
    int body_len;
    const char *user_header;
    int user_header_len;
} request_info_t;

typedef enum {
    STATE_ON_INIT,
    STATE_ON_FILED,
    STATE_ON_VALUE,
    STATE_ON_BODY,
} parser_state_t;

/* Private define --------------------------------------------------*/
#define HTTP_PORT               80
#define HTTPS_PORT              443

#define USER_AGENT_STR          "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20100101 Firefox/29.0\r\n"
#define CONNECT_STR             "Connection: close\r\n"
#define ACCEPT_STR              "Accept: */*\r\n"
#define CONTENT_LENGTH_STR      "Content-Length"
#define CRLF                    "\r\n"

#define DEFAULT_HEADER          USER_AGENT_STR""CONNECT_STR""ACCEPT_STR

/* Private macro ---------------------------------------------------*/
#define IS_BIT_SET(__DATA, __MASK)  ((unsigned)(__DATA) & (1UL << (unsigned)(__MASK)))
#define CHECK_RW(RET)               do {if ((RET) <= 0) { return http->error_code = ERR_SOCKET_WRITE; }} while(0)
// #define UNUSED_PARAM(__PARAM)       (void)(__PARAM)
#define FREE_MEMBER(__P)            do { if(__P)  {M_HTTP_FREE(__P); (__P) = NULL; }} while(0)

/* Private variables -----------------------------------------------*/
/* Private function prototypes -------------------------------------*/
static int parser_field_value(uc_http_client_t *http);

/* Private functions -----------------------------------------------*/
/**
 *  \brief: 与远端服务器建立 tcp 连接
 *  \param[in]: http 指向 uc_http_client_t 类型的结构体指针
 *  \param[in]: url 服务器域名或者ip地址
 *  \param[in]: u   指向 http_parser_url 类型的结构体指针,
 *                  http parser 对 url 结构体解析后的信息存放在该结构体中
 *  \retval:    ERR_OK
 *              ERR_URL_INVALID_HOST
 *              ERR_SOCKET_CONNECT
 */
static int http_connect_host(uc_http_client_t *http,
                             const char *url,
                             struct http_parser_url *u)
{
    int port;
    int rc = ERR_OK;
    char host[CONFIG_HOST_MAX_SIZE + 1];

    if (IS_BIT_SET(u->field_set, UF_PORT)) {
        port = (int) M_STRTOL(url + u->field_data[UF_PORT].off, NULL, 10);
    } else {
        if (M_STRNICMP("https", url + u->field_data[UF_SCHEMA].off, 5) == 0) {
#if defined(FT_SUPPORT_HTTPS)
            port = HTTPS_PORT;
            http->proto_type = PROTO_HTTPS;
#else
            M_HTTP_ASSERT(!"not support https");
            return ERR_UNSUPPORT;
#endif
        } else if (M_STRNICMP("http", url + u->field_data[UF_SCHEMA].off, 4)
            == 0) {
            port = HTTP_PORT;
            http->proto_type = PROTO_HTTP;
        } else {
            return ERR_URL_INVALID_HOST;
        }
    }

    M_MEMCPY(host, url + u->field_data[UF_HOST].off,
             u->field_data[UF_HOST].len);
    host[u->field_data[UF_HOST].len] = 0;

    if (0 != platform_net_connect(&http->net_ctx, host, port,
                                  PLATFORM_PROTOCOL_TCP)) {
        rc = ERR_SOCKET_CONNECT;
        HTTP_PRINTF("connect failed!\r\n");
        return rc;
    }

    if (PROTO_HTTPS == http->proto_type) {
#if defined(FT_SUPPORT_HTTPS)
        http->ssl_wrapper.net_ctx.fd = http->net_ctx.fd;
        if (0 != platform_ssl_connect(&http->ssl_wrapper)) {
            rc = ERR_SOCKET_CONNECT;
            HTTP_PRINTF("ssl connect failed!\r\n");
        }
#endif
    }

    return rc;
}

/**
 *  \brief: http数据读写接口函数
 *  \param[in]: http 指向 uc_http_client_t 类型的结构体指针
 *  \param[in]: data 数据存放所在数组的头指针
 *  \param[in]: len  数据长度
 *  \param[in]: read 1 表示读取 0 表示写入
 *  \retval:    -1 读写操作异常
 *              n 读取或写入的数据长度
 */
static int http_read_write(uc_http_client_t *http, const char *data,
                           int len, int read)
{
    int n = 0, r;

    while ((n < len) && (!http->exit)) {
        if (http->proto_type == PROTO_HTTPS) {
#if defined(FT_SUPPORT_HTTPS)
            r = read ? \
            platform_ssl_read(&http->ssl_wrapper, (char *) data + n, len - n) :
            platform_ssl_write(&http->ssl_wrapper, data + n, len - n);
#else
            M_HTTP_ASSERT(!"not support https");
            r = -1;
#endif
        } else {
            r = read ? \
            platform_net_recv(&http->net_ctx, (char *) data + n, len - n, 0) : \
            platform_net_send(&http->net_ctx, data + n, len - n, 0);
        }

        if (r > 0) {
            n += r;
        } else if (0 == r) {
            return n;
        } else {
            return -1;
        }
    }

    return len;
}

/**
 *  \brief: 发送固定内容的 http 请求包
 *  \param[in]: http 指向 uc_http_client_t 类型的结构体指针
 *  \param[in]: ctx 用户数据
 *  \retval:   ERR_OK
 *             ERR_SOCKET_WRITE
 */
static int http_send_request(uc_http_client_t *http,
                             const char *url,
                             struct http_parser_url *parser,
                             uc_http_user_ctx *ctx)
{
    const char *offset;
    int len;

    if (http->method == M_GET) {
        CHECK_RW(http_read_write(http, "GET ", 4, 0));
    } else if (http->method == M_POST) {
        CHECK_RW(http_read_write(http, "POST ", 5, 0));
    } else if (http->method == M_PUT) {
        CHECK_RW(http_read_write(http, "PUT ", 4, 0));
    }

    if (IS_BIT_SET(parser->field_set, UF_PATH)) {
        offset = url + parser->field_data[UF_PATH].off;
        len = parser->field_data[UF_PATH].len;
        CHECK_RW(http_read_write(http, offset, len, 0));
    } else {
        CHECK_RW(http_read_write(http, "/", 1, 0));
    }

    if (IS_BIT_SET(parser->field_set, UF_QUERY)) {
        CHECK_RW(http_read_write(http, "?", 1, 0));
        offset = url + parser->field_data[UF_QUERY].off;
        len = parser->field_data[UF_QUERY].len;
        CHECK_RW(http_read_write(http, offset, len, 0));
    }

    CHECK_RW(http_read_write(http, " HTTP/1.1\r\nHost: ", 17, 0));

    offset = url + parser->field_data[UF_HOST].off;
    len = parser->field_data[UF_HOST].len;
    CHECK_RW(http_read_write(http, offset, len, 0));

    offset = CRLF DEFAULT_HEADER;
    len = 2 + sizeof(DEFAULT_HEADER) - 1; /*! 0 占用尾部空间 */
    CHECK_RW(http_read_write(http, offset, len, 0));
    // CHECK_RW(http_read_write(http, CRLF, 2, 0));

    if (NULL == ctx) {
        CHECK_RW(http_read_write(http, CRLF, 2, 0));
        return ERR_OK;
    }

    if (ctx->header && (ctx->header_len > 0)) {
        CHECK_RW(
            http_read_write(http, ctx->header, ctx->header_len, 0)
        );
    }

    if (ctx->body && (ctx->body_len > 0)) {
        char len_data[32];
        len = M_SNPRINTF(len_data, 32, "%s: %d\r\n", CONTENT_LENGTH_STR, ctx->body_len);
        CHECK_RW(http_read_write(http, len_data, len, 0));
        CHECK_RW(http_read_write(http, CRLF, 2, 0));
        CHECK_RW(http_read_write(http, ctx->body, ctx->body_len, 0));
    } else {
        CHECK_RW(http_read_write(http, CRLF, 2, 0));
    }

    return ERR_OK;
}

/**
 *  \brief: 保存http parser解析http应答包过程中的header和value字符串
 *  \param[in, out]: used       动态申请的内存空间指针，保存字符串
 *  \param[in, out]: used_size  已使用的内存空间长度
 *  \param[in]:      at         字符串偏移指针
 *  \param[in]:      length     字符串长度
 *  \retval:   ERR_OK
 *             ERR_SOCKET_WRITE
 */
static int save_field_value(char **used,
                            unsigned short *used_size,
                            const char *at,
                            size_t length)
{
#define MAXIMUM_SAVE_SIZE 127
    char *new = *used;
    unsigned short new_size = *used_size;

    if (*used == NULL) {
        /*! Initially give a larger memory space, reduce the number of malloc */
        new_size = length > MAXIMUM_SAVE_SIZE ? length : MAXIMUM_SAVE_SIZE;
        new = (char *) M_HTTP_CALLOC(1, new_size + 1);
        if (new == NULL) {
            return -1;
        }
    } else if (length > *used_size) {
        new_size = length;
        new = (char *) M_HTTP_REALLOC(*used, new_size + 1);
        if (new == NULL) {
            return -1;
        }
    }

    *used = new;
    *used_size = new_size;
    M_MEMCPY(*used, at, length);
    (*used)[length] = '\0';

    return 0;
}

/**
 *  \brief: 根据已保存的header和value内容, 保存用户关心的内容
 *  \param[in]: http    指向 uc_http_client_t 类型的结构体指针
 *  \retval:    0
 *             -1
 */
static int parser_field_value(uc_http_client_t *http)
{
    if (http->header_field_size == 0 ||
        http->header_value_size == 0) {
        return -1;
    }

    // Location: xxx
    if (M_STRICMP(http->header_field, "Location") == 0) {
        FREE_MEMBER(http->redirect_url);
        http->redirect_url = M_STRDUP(http->header_value);
        http->redirect = 1;
        return -1;
    } else if (M_STRICMP(http->header_field, CONTENT_LENGTH_STR) == 0) {
        // Content-Length: xxx
        http->content_length = M_STRTOL(http->header_value, NULL, 10);
    } else {
        /* extract other header field value */
    }

    return 0;
}

/**
 *  \brief: http parser 模块解析http header时的回调函数，在回调函数中保存
 *          header字符串
 *  \param[in]: parser 指向 http_parser_url 类型的结构体指针
 *  \param[in]: at     字符串偏移指针
 *  \param[in]: length 字符串长度
 *  \retval:    0
 *             -1
 */
static int on_header_field_cb(http_parser *parser, const char *at,
                              size_t length)
{
    uc_http_client_t *http = (uc_http_client_t *) parser->data;

    // HTTP_PRINTF("Header field: %.*s\n", (int) length, at);

    http->parser_state = STATE_ON_FILED;
    return save_field_value(&http->header_field, &http->header_field_size,
                            at, length);
}

/**
 *  \brief: http parser 模块解析http value时的回调函数，在回调函数中保存
 *          value字符串。并根据已保存的header和value内容, 保存用户关心的内容
 *  \param[in]: parser 指向 http_parser_url 类型的结构体指针
 *  \param[in]: at     字符串偏移指针
 *  \param[in]: length 字符串长度
 *  \retval:    0
 *             -1
 */
static int on_header_value_cb(http_parser *parser, const char *at,
                              size_t length)
{
    uc_http_client_t *http = (uc_http_client_t *) parser->data;
    int rc;

    // HTTP_PRINTF("Header value: %.*s\n", (int) length, at);

    http->parser_state = STATE_ON_VALUE;
    rc = save_field_value(&http->header_value, &http->header_value_size,
                          at, length);
    if (rc == 0) {
        rc = parser_field_value(http);
    }

    return rc;
}

/**
 *  \brief: http parser 模块解析 http 状态码回调函数
 *          注意：存在chunk字段时，并没有正常解析http状态码
 *  \param[in]: parser 指向 http_parser_url 类型的结构体指针
 *  \param[in]: at     字符串偏移指针
 *  \param[in]: length 字符串长度
 *  \retval:    0
 *             -1
 */
// static int on_status_cb(http_parser *parser, const char *at, size_t length)
// {
//     UNUSED_PARAM(at);
//     UNUSED_PARAM(length);
//     ft_http_client_t *http = (ft_http_client_t *) parser->data;
//
//     HTTP_PRINTF("Status value: %.*s\n", (int) length, at);
//     http->status_code = (unsigned short) parser->status_code;
//
//     return 0;
// }

/**
 *  \brief: http parser 模块解析 header: value 完毕回调函数
 *  \param[in]: parser 指向 http_parser_url 类型的结构体指针
 *  \param[in]: at     字符串偏移指针
 *  \param[in]: length 字符串长度
 *  \retval:    0
 */
static int on_headers_complete_cb(http_parser *parser)
{
    uc_http_client_t *http = (uc_http_client_t *) parser->data;

    FREE_MEMBER(http->header_field);
    FREE_MEMBER(http->header_value);
    http->header_field_size = http->header_value_size = 0;

    return 0;
}

// static int on_chunk_header_cb(http_parser *parser)
// {
//     UNUSED_PARAM(parser);
//     // HTTP_PRINTF("chunked header [%lld]\n", parser->content_length);
//     return 0;
// }
//
// static int on_chunk_complete_cb(http_parser *parser)
// {
//     UNUSED_PARAM(parser);
//     // HTTP_PRINTF("chunked complete [%lld]\n", parser->content_length);
//     return 0;
// }

/**
 *  \brief: http parser 模块解析 body 内容回调函数，下载文件到指定目录中
 *  \param[in]: parser 指向 http_parser_url 类型的结构体指针
 *  \param[in]: at     字符串偏移指针
 *  \param[in]: length 字符串长度
 *  \retval:    0
 */
static int on_download_cb(http_parser *parser, const char *at,
                               size_t length)
{
    uc_http_client_t *http = (uc_http_client_t *) parser->data;

    HTTP_PRINTF("File: %.*s\n", (int) parser->content_length, at);

    http->parser_state = STATE_ON_BODY;

    if (http->pf == NULL) {
#if defined(USE_WINDOWS_API)
        fopen_s(&http->pf, http->filename, "wb");
#else
        http->pf = fopen(http->filename, "wb");
#endif
        if (http->pf != NULL) {
            HTTP_PRINTF("open file %s success\n ", http->filename);
        } else {
            HTTP_PRINTF("open file %s failed\n", http->filename);
            http->error_code = ERR_OPEN_FILE;
            http->exit = 1;
        }
    }

    if (http->pf != NULL) {
        fwrite(at, 1, length, http->pf);
        if (http->recv_cb) {
            http->recv_cb(http, at, length, (int) http->content_length,
                          http->ctx);
        }
    }

    return 0;
}

/**
 *  \brief: http parser 模块解析 body 内容回调函数，将body内容保存到动态申请
 *          的内存数组中
 *  \param[in]: parser 指向 http_parser_url 类型的结构体指针
 *  \param[in]: at     字符串偏移指针
 *  \param[in]: length 字符串长度
 *  \retval:    0
 *              -1
 */
static int on_body_cb(http_parser *parser, const char *at, size_t length)
{
    uc_http_client_t *http = (uc_http_client_t *) parser->data;
    char *new;

    http->parser_state = STATE_ON_BODY;

    if (http->body == NULL) {
        if (http->content_length > 0) {
            http->body = (char *) M_HTTP_CALLOC(1, http->content_length + 1);
        } else {
            http->body = (char *) M_HTTP_CALLOC(1, length + 1);
        }
    } else {
        // TODO：
        if (http->content_length <= 0) {
            new = (char *) M_HTTP_REALLOC(http->body,
                                          http->body_len + length + 1);
            if (NULL != new) {
                http->body = new;
            } else {
                return -1;
            }
        }
    }

    if (http->body != NULL) {
        M_MEMCPY(http->body + http->body_len, at, length);
        http->body_len += length;
    }

    return 0;
}

/**
 *  \brief: 处理远端服务器回应的数据
 *  \param[in]: http    指向 uc_http_client_t 类型的结构体指针
 *  \retval:    ERR_OK
 *              ERR_PARSE_REP
 *              ERR_NO_RESOURCE
 */
static int http_wait_response(uc_http_client_t *http)
{
    int rc = ERR_OK, read;
    http_parser_settings setting;
    http_parser parser;

    M_MEMSET(&setting, 0, sizeof(setting));

    setting.on_header_field = on_header_field_cb;
    setting.on_header_value = on_header_value_cb;
    setting.on_headers_complete = on_headers_complete_cb;
    setting.on_body = http->download ? on_download_cb : on_body_cb;
    http_parser_init(&parser, HTTP_RESPONSE);

    http->parser_state = STATE_ON_INIT;
    parser.data = http; // http对象会传递给回调函数

    char *buf = M_HTTP_CALLOC(1, CONFIG_BODY_MAX_SIZE);
    if (NULL == buf) {
        return http->error_code = ERR_NO_RESOURCE;
    }

    do {
        read = http_read_write(http, buf, CONFIG_BODY_MAX_SIZE - 1, 1);
        if (read > 0) {
            // HTTP_PRINTF("%s", buf);
            http_parser_execute(&parser, &setting, buf, read);
            if (HPE_OK == HTTP_PARSER_ERRNO(&parser)) {
                if (http->redirect) {
                    HTTP_PRINTF("no support redirect");
                    break;
                }
            } else {
                http->exit = 1;
                http->error_code = ERR_PARSE_REP;
                break;
            }
        }
    } while (read && !http->exit && !http->cancel);

    M_HTTP_FREE(buf);
    if (http->download && http->pf) {
        fclose(http->pf);
        http->pf = NULL;
    }

    if (http->cancel || http->exit) {
        /*! Abnormal ending */
        return http->error_code;
    } else {
        http->status_code = parser.status_code;
        if (http->status_code != HTTP_STATUS_CODE_OK) {
            rc = ERR_BAD_RESPONSE;
        }
    }

    return http->error_code = rc;
}

/**
 *  \brief: 完成一次http的请求过程
 *  \param[in]: http    指向 uc_http_client_t 类型的结构体指针
 *  \param[in]: url     服务器域名或者ip地址
 *  \param[in]: ctx     用户传递的结构体指针，保存了用户指定发送的header和body内容
 *  \retval:    ERR_OK
 *              ERR_PARSE_REP
 *              ERR_NO_RESOURCE
 */
static int sync_request(uc_http_client_t *http,
                        const char *url,
                        uc_http_user_ctx *ctx)
{
    int r;
    struct http_parser_url parser;

    if (0 != http_parser_parse_url(url, M_STRLEN(url), 0, &parser)) {
        return (http->error_code = ERR_URL_INVALID);
    }

    r = http_connect_host(http, url, &parser);
    if (ERR_OK != r) {
        return (http->error_code = r);
    }

    r = http_send_request(http, url, &parser, ctx);
    if (ERR_OK != r) {
        return (http->error_code = r);
    }

    r = http_wait_response(http);
    if (ERR_OK != r) {
        return (http->error_code = r);
    }

    return r;
}

/**
 *  \brief: 设置http接收数据时的回调函数，可以在该回调函数中对
 *  \param[in]: http     指向 uc_http_client_t 类型的结构体指针
 *  \param[in]: cb       回调函数指针
 *  \param[in]: user_ctx 用户数据指针
 *  \retval:
 */
HTTP_API void uc_http_set_recv_cb(uc_http_client_t *http, uc_http_recv_cb_t cb,
                                  void *user_ctx)
{
    if (NULL != http) {
        http->recv_cb = cb;
        http->ctx = user_ctx;
    }
}

/**
 *  \brief: 完成一次http请求，并把应答写入指定的文件中，若文件不存在则创建文件
 *  \param[in]: http     指向 uc_http_client_t 类型的结构体指针
 *  \param[in]: url      服务器域名或者ip地址
 *  \param[in]: filename 文件保存路径
 *  \retval:
 */
HTTP_API int uc_http_sync_download_file(uc_http_client_t *http, const char *url,
                                        const char *filename)
{
    if ((http == NULL) || filename == NULL) {
        return ERR_INVALID_PARAM;
    }

    http->method = M_GET;
    http->download = 1;
    http->cancel = http->exit = http->redirect = 0;
    http->pf = NULL;

    FREE_MEMBER(http->filename);
    http->filename = M_STRDUP(filename);
    if (http->filename == NULL) {
        return http->error_code = ERR_OUT_MEMORY;
    }

    if (sync_request(http, url, NULL) == ERR_OK) {
        return ERR_OK;
    }

    return http->error_code;
}

/**
 *  \brief: 完成一次http GET请求，保存应答内容到内存数组中
 *  \param[in]: http     指向 uc_http_client_t 类型的结构体指针
 *  \param[in]: url      服务器域名或者ip地址
 *  \retval: 内存数组地址
 */
HTTP_API const char *uc_http_sync_get(uc_http_client_t *http,
                                      const char *url)
{
    if (http == NULL) {
        return NULL;
    }

    http->method = M_GET;
    http->download = http->cancel = http->exit = http->redirect = 0;

    if (sync_request(http, url, NULL) == ERR_OK) {
        return http->body;
    }

    return NULL;
}

/**
 *  \brief: 完成一次http POST请求，保存应答内容到内存数组中
 *  \param[in]: http  指向 uc_http_client_t 类型的结构体指针
 *  \param[in]: url   服务器域名或者ip地址
 *  \param[in]: ctx   用户传递的结构体指针，保存了用户指定发送的 header 和 body 内容
 *                    程序默认发送 User-Agent, Connection, Accept 字段
 *  \retval: 内存数组地址
 */
HTTP_API const char *uc_http_sync_post(uc_http_client_t *http,
                                       const char *url,
                                       uc_http_user_ctx *ctx)
{
    if (http == NULL) {
        return NULL;
    }

    http->method = M_POST;
    http->download = http->cancel = http->exit = http->redirect = 0;

    if (sync_request(http, url, ctx) == ERR_OK) {
        return http->body;
    }

    return NULL;
}

/**
 *  \brief: 完成一次http PUT请求，保存应答内容到内存数组中
 *  \param[in]: http  指向 uc_http_client_t 类型的结构体指针
 *  \param[in]: url   服务器域名或者ip地址
 *  \param[in]: ctx   用户传递的结构体指针，保存了用户指定发送的 header 和 body 内容
 *                    程序默认发送 User-Agent, Connection, Accept 字段
 *  \retval: 内存数组地址
 */
HTTP_API const char *uc_http_sync_put(uc_http_client_t *http,
                                      const char *url,
                                      uc_http_user_ctx *ctx)
{
    if (http == NULL) {
        return NULL;
    }

    http->method = M_PUT;
    http->download = http->cancel = http->exit = http->redirect = 0;

    if (sync_request(http, url, ctx) == ERR_OK) {
        return http->body;
    }

    return NULL;
}

/**
 *  \brief: 获取http状态码
 *  \param[in]: http     指向 uc_http_client_t 类型的结构体指针
 *  \retval: http状态码
 */
HTTP_API int ft_http_get_status_code(uc_http_client_t *http)
{
    return http != NULL ? http->status_code : ERR_INVALID_PARAM;
}

/**
 *  \brief: 设置http运行环境，根据硬件平台选择使用
 *  \retval:
 */
HTTP_API int uc_http_env_setup(void)
{
    platform_net_env_setup();
#if defined(FT_SUPPORT_HTTPS)
    platform_ssl_env_setup();
#endif
    return 0;
}

/**
 *  \brief: 退出http运行环境，根据硬件平台选择使用
 *  \retval:
 */
HTTP_API int uc_http_env_exit(void)
{
    platform_net_env_exit();
#if defined(FT_SUPPORT_HTTPS)
    platform_ssl_env_exit();
#endif
    return 0;
}

/**
 *  \brief: 生成一个 uc_http_client_t 对象
 *  \retval: uc_http_client_t 结构体指针
 */
HTTP_API uc_http_client_t *uc_http_new(void)
{
    uc_http_client_t *http;

    http = (uc_http_client_t *) M_HTTP_CALLOC(1, sizeof(uc_http_client_t));

    return http;
}

/**
 *  \brief: 释放一个 uc_http_client_t 对象
 *  \retval:
 */
HTTP_API void uc_http_destroy(uc_http_client_t *http)
{
    if (http != NULL) {
        FREE_MEMBER(http->body);
        FREE_MEMBER(http->header_field);
        FREE_MEMBER(http->header_value);
        FREE_MEMBER(http->redirect_url);
        FREE_MEMBER(http->filename);

        platform_net_close(&http->net_ctx);
        M_MEMSET(&http->net_ctx, 0, sizeof(platform_net_ctx_t));

#if defined(FT_SUPPORT_HTTPS)
        platform_ssl_destroy(&http->ssl_wrapper);
        M_MEMSET(&http->ssl_wrapper, 0, sizeof(platform_ssl_t));
#endif

        FREE_MEMBER(http);
    }
}

/*************************** End of file ****************************/
