cmake_minimum_required(VERSION 2.8)
project(httpclient2)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        uc_http.c
        uc_http.h
        3rdparty/http_parser/http_parser.c
        3rdparty/http_parser/http_parser.h
        main.c
        platform_ssl.c
        platform_net.c
        platform_config.h
        platform_data_types.h
        platform_lib.c
        platform_lib.h

        3rdparty/krypton/krypton.c
        3rdparty/krypton/krypton.h

        http_test.c
        )

#add_subdirectory(3rdparty/krypton)
#include_directories(3rdparty/wolfSSL/wolfssl/openssl)
#include_directories(3rdparty/wolfSSL/wolfssl/openssl)

#include_directories(/usr/include/openssl)
add_executable(httpclient3 ${SOURCE_FILES})

#if (HTTPS_USE_OPENSSL)
#target_link_libraries(httpclient /lib64/libssl.so /lib64/libcrypto.so)
#endif (HTTPS_USE_OPENSSL)
