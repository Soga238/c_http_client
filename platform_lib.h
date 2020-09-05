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
#ifndef CORE_PLATFORM_LIB_H
#define CORE_PLATFORM_LIB_H
#ifdef __cplusplus
extern "C" {
#endif

/* Includes --------------------------------------------------------*/
/* Global variables ------------------------------------------------*/
/* Global typedef --------------------------------------------------*/
/* Global define ---------------------------------------------------*/
/* Global macro ----------------------------------------------------*/
/* Global variables ------------------------------------------------*/
/* Global function prototypes --------------------------------------*/

extern char *platform_strdup(const char *src);

extern void  platform_free(void *p);

extern void *platform_malloc(unsigned int size);

extern void *platform_realloc(void *p, unsigned int size);

extern void *platform_calloc(unsigned int n, unsigned int size);

#ifdef __cplusplus
}
#endif
#endif

/*************************** End of file ****************************/
