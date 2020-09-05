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
#ifndef HTTPCLIENT_PLATFORM_SSL_H
#define HTTPCLIENT_PLATFORM_SSL_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes --------------------------------------------------------*/
#include "./platform_data_types.h"

/* Global variables ------------------------------------------------*/
/* Global typedef --------------------------------------------------*/
/* Global define ---------------------------------------------------*/
/* Global macro ----------------------------------------------------*/
/* Global variables ------------------------------------------------*/
/* Global function prototypes --------------------------------------*/

extern int   platform_ssl_env_setup(void);

extern int   platform_ssl_env_exit(void);

extern int   platform_ssl_connect(platform_ssl_t *wrapper);

extern int   platform_ssl_read(platform_ssl_t *wrapper, void *buf, size_t count);

extern int   platform_ssl_write(platform_ssl_t *wrapper, const void *buf, size_t count);

extern void  platform_ssl_destroy(platform_ssl_t *wrapper);

#ifdef __cplusplus
}
#endif
#endif

/*************************** End of file ****************************/
