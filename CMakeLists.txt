cmake_minimum_required (VERSION 3.0)
project (3proxy)

set_property(GLOBAL PROPERTY COMPILE_DEFINITIONS_DEBUG "DEBUG")

option (3PROXY_USE_IPV6 "Compile 3proxy with IPv6 support" OFF)
option (3PROXY_PLUGIN_FILE "Build FilePlugin" ON)
option (3PROXY_PLUGIN_LR "Build LstFRipper plugin" OFF)
option (3PROXY_PLUGIN_LDAP "Build LDAP plugin" OFF)
option (3PROXY_PLUGIN_PAM "Build PAM plugin" OFF)
option (3PROXY_PLUGIN_PCRE "Build PCRE plugin" ON)
option (3PROXY_PLUGIN_SSL "Build SSL plugin" ON)
option (3PROXY_PLUGIN_STRINGS "Build strings plugin" ON)
option (3PROXY_PLUGIN_TRANSPARENT "Build transparent proxy plugin" OFF)
option (3PROXY_PLUGIN_U2C "Build UTF8 to CP1251 conversion plugin" ON)
option (3PROXY_PLUGIN_TRAFFIC "Build trafic counter plugin" ON)
option (3PROXY_PLUGIN_WINAUTH "Build Windows authentication plugin" ON)

if(NOT WIN32)
  set (3PROXY_PLUGIN_TRAFFIC OFF)
  set (3PROXY_PLUGIN_WINAUTH OFF)
endif(NOT WIN32)

set (CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set (CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

file(MAKE_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

# Add Windows resources file
if (WIN32)
  set (3PROXY_RESOURCES ${CMAKE_SOURCE_DIR}/3proxy.rc)
else (WIN32)
  set (3PROXY_RESOURCES "")
endif (WIN32)

set (SOURCE_DIR ${CMAKE_SOURCE_DIR}/src)

set (3PROXY_SOURCES
  ${SOURCE_DIR}/3proxy.c
  ${SOURCE_DIR}/proxymain.c
  ${SOURCE_DIR}/proxy.c
  ${SOURCE_DIR}/pop3p.c
  ${SOURCE_DIR}/smtpp.c
  ${SOURCE_DIR}/ftppr.c
  ${SOURCE_DIR}/socks.c
  ${SOURCE_DIR}/tcppm.c
  ${SOURCE_DIR}/icqpr.c
  ${SOURCE_DIR}/udppm.c
  ${SOURCE_DIR}/sockmap.c
  ${SOURCE_DIR}/sockgetchar.c
  ${SOURCE_DIR}/myalloc.c
  ${SOURCE_DIR}/common.c
  ${SOURCE_DIR}/auth.c
  ${SOURCE_DIR}/conf.c
  ${SOURCE_DIR}/datatypes.c
  ${SOURCE_DIR}/libs/md4.c
  ${SOURCE_DIR}/libs/md5.c
  ${SOURCE_DIR}/mycrypt.c
  ${SOURCE_DIR}/base64.c
  ${SOURCE_DIR}/ftp.c
  ${SOURCE_DIR}/libs/smbdes.c
  ${SOURCE_DIR}/ntlm.c
  ${SOURCE_DIR}/stringtable.c
  ${SOURCE_DIR}/webadmin.c
  ${SOURCE_DIR}/dnspr.c
  ${SOURCE_DIR}/plugins.c
  )

set(DIGHOSTS_SOURCES
  ${SOURCE_DIR}/common.c
  ${SOURCE_DIR}/dighosts.c
  ${SOURCE_DIR}/myalloc.c
  )

set(MYCRYPT_SOURCES
  ${SOURCE_DIR}/libs/md4.c
  ${SOURCE_DIR}/libs/md5.c
  ${SOURCE_DIR}/mycrypt.c
  ${SOURCE_DIR}/base64.c
  )

set(CMAKE_FIND_LIBRARY_PREFIXES "")

if (WIN32)
  if (MSVC)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".lib")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /nodefaultlib:msvcrt,msvcrtd")
  else (MSVC)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".lib" ".dll" ".dll.a" ".a")
  endif (MSVC)
else(WIN32)
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".so" ".a")
endif(WIN32)

add_executable (3proxy
  ${3PROXY_RESOURCES};
  ${3PROXY_SOURCES})

target_compile_definitions(3proxy PRIVATE WINDOWS WITH_STD_MALLOC _WIN32 _CONSOLE _MBCS MODULEMAINFUNC=mainfunc)

add_executable(dighosts ${DIGHOSTS_SOURCES})
target_compile_definitions(dighosts PRIVATE WINDOWS WITH_STD_MALLOC _CONSOLE _MBCS)

add_executable(mycrypt ${MYCRYPT_SOURCES})
target_compile_definitions(mycrypt PRIVATE WITHMAIN)

if (WIN32)
  target_link_libraries(3proxy PRIVATE ws2_32 odbc32 gdi32)
  target_link_libraries(dighosts PRIVATE ws2_32 odbc32 gdi32)
endif(WIN32)

if (NOT 3PROXY_USE_IPV6)
  target_compile_definitions(3proxy PRIVATE NOIPV6)
  target_compile_definitions(dighosts PRIVATE NOIPV6)
endif (NOT 3PROXY_USE_IPV6)

add_subdirectory (src/plugins)

