#
# 3proxy CMake build system
#

cmake_minimum_required(VERSION 3.16)

# Read version from RELEASE file
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/RELEASE" PROJECT_VERSION LIMIT_COUNT 1)

project(3proxy
    VERSION ${PROJECT_VERSION}
    LANGUAGES C
    DESCRIPTION "3proxy - tiny free proxy server"
)

# Include GNUInstallDirs for standard installation directories
include(GNUInstallDirs)

# Add cmake module path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Detect compiler
if(CMAKE_C_COMPILER_ID STREQUAL "Clang" OR CMAKE_C_COMPILER_ID STREQUAL "AppleClang")
    set(COMPILER_IS_CLANG TRUE)
    if(WIN32 AND CMAKE_C_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
        set(COMPILER_IS_CLANG_CL TRUE)
    else()
        set(COMPILER_IS_CLANG_CL FALSE)
    endif()
else()
    set(COMPILER_IS_CLANG FALSE)
    set(COMPILER_IS_CLANG_CL FALSE)
endif()

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(COMPILER_IS_GCC TRUE)
else()
    set(COMPILER_IS_GCC FALSE)
endif()

if(MSVC AND NOT COMPILER_IS_CLANG_CL)
    set(COMPILER_IS_MSVC TRUE)
else()
    set(COMPILER_IS_MSVC FALSE)
endif()

# Options
option(3PROXY_BUILD_SHARED "Build shared libraries for plugins" ON)
option(3PROXY_USE_OPENSSL "Enable TLS/SSL support (requires OpenSSL)" ON)
option(3PROXY_USE_PCRE2 "Enable PCRE2 regex filtering" ON)
option(3PROXY_USE_PAM "Enable PAM/PamAuth" ON)
option(3PROXY_USE_ODBC "Enable ODBC support (Unix only, always ON on Windows)" OFF)
option(3PROXY_USE_SPLICE "Use Linux splice() for zero-copy (Linux only)" ON)
option(3PROXY_USE_POLL "Use poll() instead of select() (Unix only)" ON)
option(3PROXY_USE_WSAPOLL "Use WSAPoll instead of select() (Windows only)" ON)
option(3PROXY_USE_NETFILTER "Enable Linux netfilter support (Linux only)" ON)
option(3PROXY_USE_UNIX_SOCKETS "Enable Unix domain socket support (Unix only)" ON)

if(NOT WIN32 AND NOT APPLE)
    option(3PROXY_STATIC_LINK "Statically link libraries using -Wl,-Bstatic (Linux/Unix only)" OFF)
endif()

# Binary name prefix for standalone modules and crypt (default: 3proxy_)
# For crypt: if prefix is empty, "my" is used instead (→ mycrypt)
set(3PROXY_BINARY_PREFIX "3proxy_" CACHE STRING "Prefix for standalone module and crypt binary names")

# Standalone module build options (ON by default)
option(3PROXY_BUILD_NONE   "Do not build standalone binaries"   OFF)
option(3PROXY_BUILD_PROXY  "Build standalone proxy binary"  ON)
option(3PROXY_BUILD_SOCKS  "Build standalone socks binary"  ON)
option(3PROXY_BUILD_POP3P  "Build standalone pop3p binary"  ON)
option(3PROXY_BUILD_SMTPP  "Build standalone smtpp binary"  ON)
option(3PROXY_BUILD_FTPPR  "Build standalone ftppr binary"  ON)
option(3PROXY_BUILD_TCPPM  "Build standalone tcppm binary"  ON)
option(3PROXY_BUILD_UDPPM  "Build standalone udppm binary"  ON)
option(3PROXY_BUILD_TLSPR  "Build standalone tlspr binary"  ON)

if(3PROXY_BUILD_NONE)
    foreach(_M PROXY SOCKS POP3P SMTPP FTPPR TCPPM UDPPM TLSPR)
        set(3PROXY_BUILD_${_M} OFF)
    endforeach()
endif()

# Output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Find threads library (cross-platform pthread equivalent)
find_package(Threads REQUIRED)

# Set default build type if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Platform-independent position independent code for shared libraries
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Platform detection and configuration
if(WIN32)
    # Windows-specific configuration
    add_compile_definitions(
        WIN32
        _WIN32
        _MBCS
        _CONSOLE
    )

    if(COMPILER_IS_MSVC)
        # MSVC-specific settings
        add_compile_definitions(
            MSVC
        )
        # Use static runtime library
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        # MSVC compiler options
        add_compile_options(
            /W3           # Warning level 3
            /GS           # Buffer security check
            /GA           # Optimize for Windows applications
            /GF           # Enable string pooling
        )
        # Optimization flags per build type
        set(CMAKE_C_FLAGS_RELEASE "/O2")

    elseif(COMPILER_IS_CLANG_CL)
        # clang-cl (Clang with MSVC frontend)
        add_compile_definitions(
            MSVC
        )
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        add_compile_options(
            -W3
            -fno-strict-aliasing
        )

    elseif(COMPILER_IS_CLANG OR COMPILER_IS_GCC)
        # Clang or GCC on Windows (MinGW-like)
        add_compile_definitions(WITH_STD_MALLOC)
        add_compile_options(-fno-strict-aliasing)

    elseif(WATCOM)
        # OpenWatcom-specific flags
        add_compile_definitions(
            WATCOM
            MSVC
            NOIPV6
            NODEBUG
            NORADIUS
        )
    endif()

    # Windows libraries
    set(WINDOWS_LIBS ws2_32 advapi32 user32 kernel32 gdi32 crypt32)

    # Windows plugins (always built)
    set(DEFAULT_PLUGINS
        utf8tocp1251
        WindowsAuthentication
        TrafficPlugin
        StringsPlugin
        FilePlugin
    )

elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # Linux-specific configuration
    add_compile_definitions(
        _GNU_SOURCE
        GETHOSTBYNAME_R
        _THREAD_SAFE
        _REENTRANT
    )

    if(COMPILER_IS_CLANG OR COMPILER_IS_GCC)
        # Clang/GCC on Linux
        add_compile_options(-fno-strict-aliasing)
    endif()

    if(3PROXY_USE_SPLICE)
        add_compile_definitions(WITHSPLICE)
    endif()

    if(3PROXY_USE_NETFILTER)
        add_compile_definitions(WITH_NETFILTER)
    endif()

    if(3PROXY_USE_UNIX_SOCKETS)
        add_compile_definitions(WITH_UN)
    endif()

    set(DEFAULT_PLUGINS
        StringsPlugin
        TrafficPlugin
        TransparentPlugin
        FilePlugin
    )

elseif(CMAKE_SYSTEM_NAME MATCHES "FreeBSD|Darwin|OpenBSD|NetBSD")
    # BSD/macOS-specific configuration
    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        # macOS-specific
        add_compile_definitions(_DARWIN_UNLIMITED_SELECT)
    endif()

    if(COMPILER_IS_CLANG OR COMPILER_IS_GCC)
        add_compile_options(-fno-strict-aliasing)
    endif()

    if(3PROXY_USE_UNIX_SOCKETS)
        add_compile_definitions(WITH_UN)
    endif()

    set(DEFAULT_PLUGINS
        StringsPlugin
        TrafficPlugin
        TransparentPlugin
        FilePlugin
    )

else()
    # Generic Unix configuration
    if(COMPILER_IS_CLANG OR COMPILER_IS_GCC)
        add_compile_options(-fno-strict-aliasing)
    endif()

    if(3PROXY_USE_UNIX_SOCKETS)
        add_compile_definitions(WITH_UN)
    endif()

    set(DEFAULT_PLUGINS
        StringsPlugin
        TrafficPlugin
        TransparentPlugin
        FilePlugin
    )
endif()

# Common definitions
if(WIN32)
    # Windows: use WSAPOLL
    if(3PROXY_USE_WSAPOLL)
        add_compile_definitions(WITH_WSAPOLL)
    else()
        add_compile_definitions(FD_SETSIZE=4096)
    endif()
else()
    # Unix: use poll
    if(3PROXY_USE_POLL)
        add_compile_definitions(WITH_POLL)
    else()
        add_compile_definitions(FD_SETSIZE=4096)
    endif()
endif()

# Find dependencies

# OpenSSL
set(OPENSSL_FOUND FALSE)
if(3PROXY_USE_OPENSSL)
    find_package(OpenSSL REQUIRED)
    if(OpenSSL_FOUND)
        set(OPENSSL_FOUND TRUE)
        add_compile_definitions(WITH_SSL)
        message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
    endif()
else()
    message(STATUS "OpenSSL disabled by user request")
endif()

# PCRE2
set(PCRE2_FOUND FALSE)
if(3PROXY_USE_PCRE2)
    find_package(PCRE2 QUIET)
    if(PCRE2_FOUND)
        add_compile_definitions(WITH_PCRE)
        message(STATUS "PCRE2 found: ${PCRE2_VERSION}")
    else()
        message(STATUS "PCRE2 not found, PCRE support will not be built")
    endif()
endif()

# PAM (Unix only)
set(PAM_FOUND FALSE)
if(3PROXY_USE_PAM AND NOT WIN32)
    find_package(PAM QUIET)
    if(PAM_FOUND)
        message(STATUS "PAM found")
    else()
        message(STATUS "PAM not found, PamAuth will not be built")
    endif()
endif()

# ODBC (always enabled on Windows)
set(ODBC_FOUND FALSE)
if(WIN32 OR 3PROXY_USE_ODBC)
    find_package(ODBC QUIET)
    if(ODBC_FOUND)
        message(STATUS "ODBC found")
    else()
        message(STATUS "ODBC not found, building without ODBC support")
    endif()
endif()

# Define WITH_ODBC when ODBC is available
if(ODBC_FOUND)
    add_compile_definitions(WITH_ODBC)
endif()

# Set NORADIUS if OpenSSL is not available (RADIUS requires MD5 from OpenSSL)
if(NOT OPENSSL_FOUND)
    add_compile_definitions(NORADIUS)
endif()

# Source files for 3proxy core
set(3PROXY_CORE_SOURCES
    src/3proxy.c
    src/auth.c
    src/acl.c
    src/limiter.c
    src/redirect.c
    src/authradius.c
    src/hash.c
    src/hashtables.c
    src/resolve.c
    src/sql.c
    src/conf.c
    src/datatypes.c
    src/plugins.c
    src/stringtable.c
)

# BLAKE2 source for 3proxy_crypt
set(MD_SOURCES
    src/libs/blake2b-ref.c
)

# ============================================================================
# Object libraries for common sources (shared between executables)
# ============================================================================

# Common object library (sockmap, sockgetchar, common, log)
add_library(common_obj OBJECT
    src/sockmap.c
    src/sockgetchar.c
    src/common.c
    src/log.c
)
target_include_directories(common_obj PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# base64 object library
add_library(base64_obj OBJECT src/base64.c)
target_include_directories(base64_obj PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# mdhash object library (MD4/MD5: CAPI on Windows, OpenSSL EVP elsewhere)
add_library(mdhash_obj OBJECT src/mdhash.c)
target_include_directories(mdhash_obj PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
if(WIN32)
    # CAPI lives in advapi32 (already in WINDOWS_LIBS); no extra include needed.
else()
    if(OpenSSL_FOUND)
        target_include_directories(mdhash_obj PRIVATE ${OPENSSL_INCLUDE_DIR})
        target_compile_definitions(mdhash_obj PRIVATE WITH_SSL)
    endif()
endif()

# ============================================================================
# Object libraries for 3proxy (compiled WITHOUT WITHMAIN)
# These are used by the main 3proxy executable
# ============================================================================

# Server modules object library (without WITHMAIN, without UDP)
add_library(srv_modules OBJECT
    src/proxy.c
    src/pop3p.c
    src/smtpp.c
    src/ftppr.c
    src/tcppm.c
    src/tlspr.c
    src/auto.c
    src/socks.c
    src/webadmin.c
    src/dnspr.c
)

target_include_directories(srv_modules PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
# UDP port mapper server module (without WITHMAIN)
add_library(srvudppm_obj OBJECT src/udppm.c)
target_include_directories(srvudppm_obj PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# UDP socket relay (used by 3proxy, socks, udppm)
add_library(udpsockmap_obj OBJECT src/udpsockmap.c)
target_include_directories(udpsockmap_obj PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# mainfunc object (proxymain.c compiled with MODULEMAINFUNC=mainfunc for 3proxy)
add_library(mainfunc OBJECT src/proxymain.c)
target_include_directories(mainfunc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(mainfunc PRIVATE MODULEMAINFUNC=mainfunc)

# ftp object (used only by 3proxy and ftppr)
add_library(ftp_obj OBJECT src/ftp.c)
target_include_directories(ftp_obj PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# 3proxy_crypt object for 3proxy (without WITHMAIN)
add_library(3proxy_crypt_obj OBJECT src/3proxy_crypt.c)
target_include_directories(3proxy_crypt_obj PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
if(OpenSSL_FOUND)
    target_include_directories(3proxy_crypt_obj PRIVATE ${OPENSSL_INCLUDE_DIR})
endif()

# ============================================================================
# Main 3proxy executable
# Uses srv_* object files (without WITHMAIN)
# ============================================================================

add_executable(3proxy
    ${3PROXY_CORE_SOURCES}
    $<TARGET_OBJECTS:srv_modules>
    $<TARGET_OBJECTS:srvudppm_obj>
    $<TARGET_OBJECTS:mainfunc>
    $<TARGET_OBJECTS:common_obj>
    $<TARGET_OBJECTS:udpsockmap_obj>
    $<TARGET_OBJECTS:base64_obj>
    $<TARGET_OBJECTS:mdhash_obj>
    $<TARGET_OBJECTS:ftp_obj>
    $<TARGET_OBJECTS:3proxy_crypt_obj>
)
target_sources(3proxy PRIVATE ${MD_SOURCES})

if(OpenSSL_FOUND)
    target_sources(3proxy PRIVATE src/ssllib.c src/ssl.c)
endif()

if(PCRE2_FOUND)
    target_sources(3proxy PRIVATE src/pcre.c)
endif()

target_include_directories(3proxy PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/libs
)
if(OpenSSL_FOUND)
    target_include_directories(3proxy PRIVATE ${OPENSSL_INCLUDE_DIR})
endif()
if(PCRE2_FOUND)
    target_include_directories(3proxy PRIVATE ${PCRE2_INCLUDE_DIRS})
endif()

target_link_libraries(3proxy PRIVATE Threads::Threads)

if(ODBC_FOUND)
    if(TARGET ODBC::ODBC)
        target_link_libraries(3proxy PRIVATE ODBC::ODBC)
    else()
        target_link_libraries(3proxy PRIVATE ${ODBC_LIBRARIES})
    endif()
endif()

# OpenSSL linking
if(OpenSSL_FOUND)
    if(3PROXY_STATIC_LINK)
        # Will be linked statically below (if static libraries are found)
    else()
        target_link_libraries(3proxy PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
endif()

# PCRE2 linking
if(PCRE2_FOUND)
    if(3PROXY_STATIC_LINK)
        # Will be linked statically below (if static libraries are found)
    elseif(TARGET PCRE2::PCRE2)
        target_link_libraries(3proxy PRIVATE PCRE2::PCRE2)
    else()
        target_link_libraries(3proxy PRIVATE ${PCRE2_LIBRARIES})
    endif()
endif()

# Static linking of OpenSSL and PCRE2 (when option is enabled)
if(3PROXY_STATIC_LINK AND (OpenSSL_FOUND OR PCRE2_FOUND))
    set(_saved_cmake_find_library_suffixes ${CMAKE_FIND_LIBRARY_SUFFIXES})
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")

    set(_static_libs "")

    if(OpenSSL_FOUND)
        find_library(_ssl_static_lib ssl)
        find_library(_crypto_static_lib crypto)
        if(_ssl_static_lib AND _crypto_static_lib)
            list(APPEND _static_libs ${_ssl_static_lib} ${_crypto_static_lib})
        endif()
    endif()

    if(PCRE2_FOUND)
        find_library(_pcre2_static_lib NAMES pcre2-8)
        if(_pcre2_static_lib)
            list(APPEND _static_libs ${_pcre2_static_lib})
        endif()
    endif()

    set(CMAKE_FIND_LIBRARY_SUFFIXES ${_saved_cmake_find_library_suffixes})

    if(_static_libs)
        target_link_libraries(3proxy PRIVATE -Wl,-Bstatic ${_static_libs} -Wl,-Bdynamic)
        message(STATUS "Static linking enabled for OpenSSL/PCRE2")
    else()
        message(WARNING "3PROXY_STATIC_LINK is ON but static libraries not found, falling back to dynamic")
        if(OpenSSL_FOUND)
            target_link_libraries(3proxy PRIVATE OpenSSL::SSL OpenSSL::Crypto)
        endif()
        if(PCRE2_FOUND)
            if(TARGET PCRE2::PCRE2)
                target_link_libraries(3proxy PRIVATE PCRE2::PCRE2)
            else()
                target_link_libraries(3proxy PRIVATE ${PCRE2_LIBRARIES})
            endif()
        endif()
    endif()
endif()

if(WIN32)
    target_link_libraries(3proxy PRIVATE ${WINDOWS_LIBS})
    if(COMPILER_IS_MSVC AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/3proxy.rc)
        target_sources(3proxy PRIVATE 3proxy.rc)
    endif()
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(3proxy PRIVATE dl)
endif()

# Build 3proxy_crypt utility
add_executable(3proxy_crypt
    src/3proxy_crypt.c
    $<TARGET_OBJECTS:base64_obj>
    $<TARGET_OBJECTS:mdhash_obj>
)
target_sources(3proxy_crypt PRIVATE ${MD_SOURCES})
target_compile_definitions(3proxy_crypt PRIVATE WITHMAIN)
target_include_directories(3proxy_crypt PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/libs
)
if(OpenSSL_FOUND)
    target_include_directories(3proxy_crypt PRIVATE ${OPENSSL_INCLUDE_DIR})
endif()
target_link_libraries(3proxy_crypt PRIVATE Threads::Threads)
if(OpenSSL_FOUND)
    if(3PROXY_STATIC_LINK)
        set(_saved_cmake_find_library_suffixes ${CMAKE_FIND_LIBRARY_SUFFIXES})
        set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
        find_library(_ssl_static_lib ssl)
        find_library(_crypto_static_lib crypto)
        set(CMAKE_FIND_LIBRARY_SUFFIXES ${_saved_cmake_find_library_suffixes})
        if(_ssl_static_lib AND _crypto_static_lib)
            target_link_libraries(3proxy_crypt PRIVATE -Wl,-Bstatic ${_ssl_static_lib} ${_crypto_static_lib} -Wl,-Bdynamic)
            message(STATUS "3proxy_crypt: static OpenSSL")
        else()
            message(WARNING "3PROXY_STATIC_LINK is ON but static OpenSSL not found, using dynamic")
            target_link_libraries(3proxy_crypt PRIVATE OpenSSL::SSL OpenSSL::Crypto)
        endif()
    else()
        target_link_libraries(3proxy_crypt PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
endif()
if("${3PROXY_BINARY_PREFIX}" STREQUAL "")
    set_target_properties(3proxy_crypt PROPERTIES OUTPUT_NAME "mycrypt")
else()
    set_target_properties(3proxy_crypt PROPERTIES OUTPUT_NAME "${3PROXY_BINARY_PREFIX}crypt")
endif()

# Build standalone proxy executables
foreach(PROXY_NAME proxy socks pop3p smtpp ftppr tcppm udppm tlspr)
    string(TOUPPER "${PROXY_NAME}" _MODULE_OPT)
    if(NOT 3PROXY_BUILD_${_MODULE_OPT})
        continue()
    endif()

    if(PROXY_NAME STREQUAL "ftppr" OR PROXY_NAME STREQUAL "proxy")
        # ftppr and proxy use ftp_obj
        add_executable(${PROXY_NAME}
            src/${PROXY_NAME}.c
            $<TARGET_OBJECTS:common_obj>
            $<TARGET_OBJECTS:ftp_obj>
        )
    else()
        add_executable(${PROXY_NAME}
            src/${PROXY_NAME}.c
            $<TARGET_OBJECTS:common_obj>
        )
    endif()

    set_target_properties(${PROXY_NAME} PROPERTIES
        OUTPUT_NAME "${3PROXY_BINARY_PREFIX}${PROXY_NAME}"
    )

    target_include_directories(${PROXY_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )

    target_compile_definitions(${PROXY_NAME} PRIVATE
        WITHMAIN
        NOPORTMAP
    )

    if(NOT PROXY_NAME STREQUAL "udppm")
        target_compile_definitions(${PROXY_NAME} PRIVATE NOUDPMAIN)
    endif()

    target_link_libraries(${PROXY_NAME} PRIVATE Threads::Threads)

    if(PROXY_NAME STREQUAL "proxy")
        target_compile_definitions(${PROXY_NAME} PRIVATE ANONYMOUS)
    endif()

    if(PROXY_NAME STREQUAL "tcppm" OR PROXY_NAME STREQUAL "udppm" OR PROXY_NAME STREQUAL "tlspr")
        target_compile_definitions(${PROXY_NAME} PRIVATE PORTMAP)
    endif()

    if(WIN32)
        target_link_libraries(${PROXY_NAME} PRIVATE ${WINDOWS_LIBS})
    endif()

    if(PROXY_NAME STREQUAL "proxy" OR PROXY_NAME STREQUAL "smtpp")
        target_sources(${PROXY_NAME} PRIVATE $<TARGET_OBJECTS:base64_obj>)
    endif()

    if(PROXY_NAME STREQUAL "udppm")
        target_sources(${PROXY_NAME} PRIVATE src/hash.c)
    endif()

    if(PROXY_NAME STREQUAL "socks" OR PROXY_NAME STREQUAL "udppm")
        target_sources(${PROXY_NAME} PRIVATE src/udpsockmap.c)
    endif()
endforeach()

# Plugin output directory
set(PLUGIN_OUTPUT_DIR ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
if(WIN32)
    set(PLUGIN_SUFFIX ".dll")
else()
    set(PLUGIN_SUFFIX ".ld.so")
endif()

# Include plugin definitions
include(cmake/plugins.cmake)

# Build plugins
foreach(PLUGIN ${DEFAULT_PLUGINS})
    add_subdirectory(src/plugins/${PLUGIN})
endforeach()

if(PAM_FOUND)
    add_subdirectory(src/plugins/PamAuth)
endif()

# Build full list of plugins to be built
set(ALL_PLUGINS ${DEFAULT_PLUGINS})
if(PAM_FOUND)
    list(APPEND ALL_PLUGINS PamAuth)
endif()

# Installation rules
install(TARGETS 3proxy 3proxy_crypt
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

foreach(PROXY_NAME proxy socks pop3p smtpp ftppr tcppm udppm tlspr)
    string(TOUPPER "${PROXY_NAME}" _MODULE_OPT)
    if(3PROXY_BUILD_${_MODULE_OPT})
        install(TARGETS ${PROXY_NAME}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )
    endif()
endforeach()

# Install plugins
# Use install(DIRECTORY ... FILES_MATCHING) so the glob resolves at install
# time, after plugin targets have been built. A configure-time file(GLOB)
# would run before any plugin exists and install nothing.
if(WIN32)
    install(DIRECTORY ${PLUGIN_OUTPUT_DIR}/
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        FILES_MATCHING PATTERN "*${PLUGIN_SUFFIX}"
    )
else()
    install(DIRECTORY ${PLUGIN_OUTPUT_DIR}/
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/3proxy
        FILES_MATCHING PATTERN "*${PLUGIN_SUFFIX}"
    )
endif()

# Install configuration files
if(NOT WIN32)
    set(CRYPT_PREFIX "${3PROXY_BINARY_PREFIX}")
    set(3PROXY_CONFDIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}/3proxy/conf")
    set(3PROXY_COUNTERDIR "/opt/3proxy")
    install(DIRECTORY DESTINATION /opt/3proxy)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/scripts/3proxy.cfg.in
        ${CMAKE_CURRENT_BINARY_DIR}/3proxy.cfg
        @ONLY
    )
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/3proxy.cfg DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/3proxy)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/scripts/add3proxyuser.sh.in
        ${CMAKE_CURRENT_BINARY_DIR}/add3proxyuser
        @ONLY
    )
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/add3proxyuser
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
    )
endif()

# Install service files (systemd, launchd, init.d, or rc.d)
if(NOT WIN32)
    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        # macOS - install launchd plist
        configure_file(
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts/org.3proxy.3proxy.plist.in
            ${CMAKE_CURRENT_BINARY_DIR}/org.3proxy.3proxy.plist
            @ONLY
        )
        install(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.3proxy.3proxy.plist
            DESTINATION /Library/LaunchDaemons
        )

        message(STATUS "  launchd: YES (/Library/LaunchDaemons)")
    elseif(CMAKE_SYSTEM_NAME MATCHES "FreeBSD|OpenBSD|NetBSD")
        # BSD - install rc.d script
        set(RCD_DIR "/usr/local/etc/rc.d")

        configure_file(
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts/rc.d/3proxy.in
            ${CMAKE_CURRENT_BINARY_DIR}/3proxy.rc
            @ONLY
        )
        install(FILES ${CMAKE_CURRENT_BINARY_DIR}/3proxy.rc
            DESTINATION ${RCD_DIR}
            RENAME 3proxy
            PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
        )

        message(STATUS "  rc.d: YES (${RCD_DIR})")
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        # Linux - check for systemd
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(SYSTEMD QUIET systemd)
        endif()

        if(SYSTEMD_FOUND)
            # systemd is available - install systemd service
            # Get systemd unit directory
            pkg_get_variable(SYSTEMD_UNIT_DIR systemd systemdsystemunitdir)
            if(NOT SYSTEMD_UNIT_DIR)
                # Fallback to common location
                set(SYSTEMD_UNIT_DIR "/lib/systemd/system")
            endif()

            # Configure and install systemd service file
            configure_file(
                ${CMAKE_CURRENT_SOURCE_DIR}/scripts/3proxy.service.in
                ${CMAKE_CURRENT_BINARY_DIR}/3proxy.service
                @ONLY
            )
            install(FILES ${CMAKE_CURRENT_BINARY_DIR}/3proxy.service
                DESTINATION ${SYSTEMD_UNIT_DIR}
            )

            message(STATUS "  systemd: YES (${SYSTEMD_UNIT_DIR})")
        else()
            # No systemd - install init.d script
            configure_file(
                ${CMAKE_CURRENT_SOURCE_DIR}/scripts/init.d/3proxy.in
                ${CMAKE_CURRENT_BINARY_DIR}/3proxy.init
                @ONLY
            )
            install(FILES ${CMAKE_CURRENT_BINARY_DIR}/3proxy.init
                DESTINATION /etc/init.d
                RENAME 3proxy
                PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
            )

            message(STATUS "  systemd: NO (using init.d)")
        endif()
    else()
        # Other Unix - install init.d script
        configure_file(
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts/init.d/3proxy.in
            ${CMAKE_CURRENT_BINARY_DIR}/3proxy.init
            @ONLY
        )
        install(FILES ${CMAKE_CURRENT_BINARY_DIR}/3proxy.init
            DESTINATION /etc/init.d
            RENAME 3proxy
            PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
        )

        message(STATUS "  init.d: YES (/etc/init.d)")
    endif()

    # Run postinstall only for direct installs (no DESTDIR)
    install(CODE "
        if(\"\$ENV{DESTDIR}\" STREQUAL \"\")
            execute_process(
                COMMAND ${CMAKE_COMMAND} -E env sh ${CMAKE_CURRENT_SOURCE_DIR}/scripts/postinstall.sh ${CMAKE_INSTALL_PREFIX}
                RESULT_VARIABLE POSTINSTALL_RESULT
            )
        endif()
    ")
endif()

# Install man pages
if(NOT WIN32)
    # Config man page (section 5) — no prefix
    file(GLOB MAN5_FILES "${CMAKE_CURRENT_SOURCE_DIR}/man/*.5")
    install(FILES ${MAN5_FILES} DESTINATION ${CMAKE_INSTALL_MANDIR}/man5)
    # Main 3proxy man page — no prefix
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/man/3proxy.8"
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man8
    )
    # 3proxy_crypt man page — no prefix (already has 3proxy_)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/man/3proxy_crypt.8")
        install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/man/3proxy_crypt.8"
            DESTINATION ${CMAKE_INSTALL_MANDIR}/man8
        )
    endif()
    # Module man pages — installed with binary prefix only if module is built
    foreach(_MAN proxy socks pop3p smtpp ftppr tcppm udppm tlspr)
        string(TOUPPER "${_MAN}" _MODULE_OPT)
        if(3PROXY_BUILD_${_MODULE_OPT})
            set(_MAN_SRC "${CMAKE_CURRENT_SOURCE_DIR}/man/${_MAN}.8")
            if(EXISTS "${_MAN_SRC}")
                install(FILES "${_MAN_SRC}"
                    DESTINATION ${CMAKE_INSTALL_MANDIR}/man8
                    RENAME "${3PROXY_BINARY_PREFIX}${_MAN}.8"
                )
            endif()
        endif()
    endforeach()
endif()

# Summary
message(STATUS "")
message(STATUS "3proxy configuration summary:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "  Compiler: ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "")
message(STATUS "  Options:")
message(STATUS "    BUILD_SHARED:    ${3PROXY_BUILD_SHARED}")
message(STATUS "    USE_OPENSSL:     ${3PROXY_USE_OPENSSL}")
message(STATUS "    USE_PCRE2:       ${3PROXY_USE_PCRE2}")
message(STATUS "    USE_PAM:         ${3PROXY_USE_PAM}")
message(STATUS "    USE_ODBC:        ${3PROXY_USE_ODBC}")
message(STATUS "    USE_POLL:        ${3PROXY_USE_POLL}")
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(STATUS "    USE_SPLICE:      ${3PROXY_USE_SPLICE}")
    message(STATUS "    USE_NETFILTER:   ${3PROXY_USE_NETFILTER}")
endif()
if(NOT WIN32 AND NOT APPLE)
    message(STATUS "    STATIC_LINK:     ${3PROXY_STATIC_LINK}")
endif()
if(WIN32)
    message(STATUS "    USE_WSAPOLL:     ${3PROXY_USE_WSAPOLL}")
endif()
message(STATUS "")
message(STATUS "  Libraries found:")
message(STATUS "    OpenSSL: ${OPENSSL_FOUND}")
message(STATUS "    PCRE2:   ${PCRE2_FOUND}")
message(STATUS "    PAM:     ${PAM_FOUND}")
message(STATUS "    ODBC:    ${ODBC_FOUND}")
message(STATUS "")
message(STATUS "  Plugins to build: ${ALL_PLUGINS}")
message(STATUS "")
message(STATUS "  Standalone modules:")
message(STATUS "    Binary prefix:   \"${3PROXY_BINARY_PREFIX}\"")
foreach(_M proxy socks pop3p smtpp ftppr tcppm udppm tlspr)
    string(TOUPPER "${_M}" _MO)
    message(STATUS "    BUILD_${_MO}: ${3PROXY_BUILD_${_MO}}")
endforeach()
message(STATUS "")
