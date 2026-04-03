# SSLPlugin - requires OpenSSL

if(NOT TARGET OpenSSL::SSL)
    message(STATUS "SSLPlugin requires OpenSSL, skipping")
    return()
endif()

add_3proxy_plugin(SSLPlugin
    SOURCES
        ssl_plugin.c
        my_ssl.c
    LIBRARIES
        OpenSSL::SSL
        OpenSSL::Crypto
    COMPILE_DEFINITIONS
        WITH_SSL
)
