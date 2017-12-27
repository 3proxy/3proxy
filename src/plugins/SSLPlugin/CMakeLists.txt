
set(SSL_PLUGIN_SOURCES ssl_plugin.c my_ssl.c)

add_library(SSLPlugin SHARED ${SSL_PLUGIN_SOURCES})

target_include_directories (SSLPlugin PRIVATE ${CMAKE_SOURCE_DIR}/include)
set_target_properties(SSLPlugin PROPERTIES PREFIX "")

find_library(LEBEAY_LIBRARY
    NAMES libeay32 libeay32mt
    HINTS "${CMAKE_SOURCE_DIR}/lib"
)
find_library(SSLEAY_LIBRARY
    NAMES ssleay32 ssleay32mt
    HINTS "${CMAKE_SOURCE_DIR}/lib"
)

target_link_libraries (SSLPlugin PRIVATE
  ws2_32.lib
  ${SSLEAY_LIBRARY}
  ${LEBEAY_LIBRARY})

