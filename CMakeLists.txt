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
option(3PROXY_USE_OPENSSL "Enable OpenSSL/SSLPlugin" ON)
option(3PROXY_USE_PCRE2 "Enable PCRE2/PCREPlugin" ON)
option(3PROXY_USE_PAM "Enable PAM/PamAuth" ON)
option(3PROXY_USE_ODBC "Enable ODBC support (Unix only, always ON on Windows)" OFF)
option(3PROXY_USE_SPLICE "Use Linux splice() for zero-copy (Linux only)" ON)
option(3PROXY_USE_POLL "Use poll() instead of select() (Unix only)" ON)
option(3PROXY_USE_WSAPOLL "Use WSAPoll instead of select() (Windows only)" ON)
option(3PROXY_USE_NETFILTER "Enable Linux netfilter support (Linux only)" ON)

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
            WITH_SSL
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
            WITH_SSL
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

    set(DEFAULT_PLUGINS
        StringsPlugin
        TrafficPlugin
        TransparentPlugin
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

    set(DEFAULT_PLUGINS
        StringsPlugin
        TrafficPlugin
        TransparentPlugin
    )

else()
    # Generic Unix configuration
    if(COMPILER_IS_CLANG OR COMPILER_IS_GCC)
        add_compile_options(-fno-strict-aliasing)
    endif()

    set(DEFAULT_PLUGINS
        StringsPlugin
        TrafficPlugin
        TransparentPlugin
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
    find_package(OpenSSL QUIET)
    if(OpenSSL_FOUND)
        set(OPENSSL_FOUND TRUE)
        add_compile_definitions(WITH_SSL)
        message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
    else()
        message(STATUS "OpenSSL not found, SSLPlugin will not be built")
    endif()
endif()

# PCRE2
set(PCRE2_FOUND FALSE)
if(3PROXY_USE_PCRE2)
    find_package(PCRE2 QUIET)
    if(PCRE2_FOUND)
        message(STATUS "PCRE2 found: ${PCRE2_VERSION}")
    else()
        message(STATUS "PCRE2 not found, PCREPlugin will not be built")
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

# Set NOODBC if ODBC is not found
if(NOT ODBC_FOUND)
    add_compile_definitions(NOODBC)
endif()

# Source files for 3proxy core
set(3PROXY_CORE_SOURCES
    src/3proxy.c
    src/auth.c
    src/authradius.c
    src/conf.c
    src/datatypes.c
    src/plugins.c
    src/stringtable.c
)

# MD4/MD5 sources for mycrypt
set(MD_SOURCES
    src/libs/md4.c
    src/libs/md5.c
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

# ============================================================================
# Object libraries for 3proxy (compiled WITHOUT WITHMAIN)
# These are used by the main 3proxy executable
# ============================================================================

# Server modules object library (without WITHMAIN)
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
    src/udppm.c
    src/dnspr.c
)

target_include_directories(srv_modules PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# mainfunc object (proxymain.c compiled with MODULEMAINFUNC=mainfunc for 3proxy)
add_library(mainfunc OBJECT src/proxymain.c)
target_include_directories(mainfunc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(mainfunc PRIVATE MODULEMAINFUNC=mainfunc)

# ftp object (used only by 3proxy and ftppr)
add_library(ftp_obj OBJECT src/ftp.c)
target_include_directories(ftp_obj PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# mycrypt object for 3proxy (without WITHMAIN)
add_library(mycrypt_obj OBJECT src/mycrypt.c)
target_include_directories(mycrypt_obj PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# ============================================================================
# Main 3proxy executable
# Uses srv_* object files (without WITHMAIN)
# ============================================================================

add_executable(3proxy
    ${3PROXY_CORE_SOURCES}
    ${MD_SOURCES}
    $<TARGET_OBJECTS:srv_modules>
    $<TARGET_OBJECTS:mainfunc>
    $<TARGET_OBJECTS:common_obj>
    $<TARGET_OBJECTS:base64_obj>
    $<TARGET_OBJECTS:ftp_obj>
    $<TARGET_OBJECTS:mycrypt_obj>
)

target_include_directories(3proxy PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/libs
)

target_link_libraries(3proxy PRIVATE Threads::Threads)

if(ODBC_FOUND)
    if(TARGET ODBC::ODBC)
        target_link_libraries(3proxy PRIVATE ODBC::ODBC)
    else()
        target_link_libraries(3proxy PRIVATE ${ODBC_LIBRARIES})
    endif()
endif()

if(WIN32)
    target_link_libraries(3proxy PRIVATE ${WINDOWS_LIBS})
    if(OpenSSL_FOUND)
        target_link_libraries(3proxy PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
    if(COMPILER_IS_MSVC AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/3proxy.rc)
        target_sources(3proxy PRIVATE 3proxy.rc)
    endif()
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(3proxy PRIVATE dl)
    if(OpenSSL_FOUND)
        target_link_libraries(3proxy PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
endif()

# Build mycrypt utility
add_executable(mycrypt
    src/mycrypt.c
    ${MD_SOURCES}
    $<TARGET_OBJECTS:base64_obj>
)
target_compile_definitions(mycrypt PRIVATE WITHMAIN)
target_include_directories(mycrypt PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/libs
)
target_link_libraries(mycrypt PRIVATE Threads::Threads)

# Build standalone proxy executables
foreach(PROXY_NAME proxy socks pop3p smtpp ftppr tcppm udppm tlspr)
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

    target_include_directories(${PROXY_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )

    target_compile_definitions(${PROXY_NAME} PRIVATE
        WITHMAIN
        NOPORTMAP
    )

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

if(OPENSSL_FOUND)
    add_subdirectory(src/plugins/SSLPlugin)
endif()

if(PCRE2_FOUND)
    add_subdirectory(src/plugins/PCREPlugin)
endif()

if(PAM_FOUND)
    add_subdirectory(src/plugins/PamAuth)
endif()

# Build full list of plugins to be built
set(ALL_PLUGINS ${DEFAULT_PLUGINS})
if(OPENSSL_FOUND)
    list(APPEND ALL_PLUGINS SSLPlugin)
endif()
if(PCRE2_FOUND)
    list(APPEND ALL_PLUGINS PCREPlugin)
endif()
if(PAM_FOUND)
    list(APPEND ALL_PLUGINS PamAuth)
endif()

# Installation rules
install(TARGETS 3proxy mycrypt proxy socks pop3p smtpp ftppr tcppm udppm tlspr
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install plugins
if(WIN32)
    install(FILES
        ${PLUGIN_OUTPUT_DIR}/utf8tocp1251${PLUGIN_SUFFIX}
        ${PLUGIN_OUTPUT_DIR}/WindowsAuthentication${PLUGIN_SUFFIX}
        ${PLUGIN_OUTPUT_DIR}/TrafficPlugin${PLUGIN_SUFFIX}
        ${PLUGIN_OUTPUT_DIR}/StringsPlugin${PLUGIN_SUFFIX}
        DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
else()
    install(FILES
        ${PLUGIN_OUTPUT_DIR}/StringsPlugin${PLUGIN_SUFFIX}
        ${PLUGIN_OUTPUT_DIR}/TrafficPlugin${PLUGIN_SUFFIX}
        ${PLUGIN_OUTPUT_DIR}/TransparentPlugin${PLUGIN_SUFFIX}
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/3proxy
    )
endif()

# Install configuration files
if(NOT WIN32)
    install(FILES scripts/3proxy.cfg DESTINATION /etc/3proxy)
    install(FILES scripts/add3proxyuser.sh DESTINATION ${CMAKE_INSTALL_BINDIR})
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

            # Install tmpfiles.d configuration for runtime directory
            configure_file(
                ${CMAKE_CURRENT_SOURCE_DIR}/scripts/3proxy.tmpfiles.in
                ${CMAKE_CURRENT_BINARY_DIR}/3proxy.conf
                @ONLY
            )
            install(FILES ${CMAKE_CURRENT_BINARY_DIR}/3proxy.conf
                DESTINATION /usr/lib/tmpfiles.d
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

    # Create proxy user and group during installation
    install(FILES scripts/postinstall.sh
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
    )
    install(CODE "
        execute_process(
            COMMAND ${CMAKE_INSTALL_FULL_BINDIR}/postinstall.sh
            RESULT_VARIABLE POSTINSTALL_RESULT
        )
    ")
endif()

# Install man pages
if(NOT WIN32)
    file(GLOB MAN3_FILES "${CMAKE_CURRENT_SOURCE_DIR}/man/*.3")
    file(GLOB MAN8_FILES "${CMAKE_CURRENT_SOURCE_DIR}/man/*.8")
    install(FILES ${MAN3_FILES} DESTINATION ${CMAKE_INSTALL_MANDIR}/man3)
    install(FILES ${MAN8_FILES} DESTINATION ${CMAKE_INSTALL_MANDIR}/man8)
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
