set(SSL_PLUGIN_SOURCES ssl_plugin.c my_ssl.c)

add_library(SSLPlugin SHARED ${SSL_PLUGIN_SOURCES})

target_include_directories (SSLPlugin PRIVATE ${CMAKE_SOURCE_DIR}/include)
set_target_properties(SSLPlugin PROPERTIES PREFIX "")

if (WIN32)
  target_link_libraries (SSLPlugin PRIVATE ws2_32.lib)
endif (WIN32)

find_library(LIBEAY_LIBRARY
  NAMES crypto libeay32 libeay32mt
  HINTS "${CMAKE_SOURCE_DIR}/lib"
)

find_library(SSLEAY_LIBRARY
  NAMES libssl ssleay32 ssleay32mt
  HINTS "${CMAKE_SOURCE_DIR}/lib"
)

target_link_libraries (SSLPlugin PRIVATE ${LIBEAY_LIBRARY} ${SSLEAY_LIBRARY})

