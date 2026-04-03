# FindPCRE2.cmake
#
# Find the PCRE2 library
#
# This module defines:
#  PCRE2_FOUND - whether the PCRE2 library was found
#  PCRE2_INCLUDE_DIRS - the PCRE2 include directories
#  PCRE2_LIBRARIES - the PCRE2 libraries
#  PCRE2_VERSION - the PCRE2 version

# Try pkg-config first
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PC_PCRE2 QUIET libpcre2-8)
endif()

# Find include directory
find_path(PCRE2_INCLUDE_DIR
    NAMES pcre2.h
    HINTS
        ${PC_PCRE2_INCLUDE_DIRS}
        /usr/include
        /usr/local/include
    PATH_SUFFIXES
        pcre2
)

# Find library
find_library(PCRE2_LIBRARY
    NAMES pcre2-8 pcre2-8d pcre2
    HINTS
        ${PC_PCRE2_LIBRARY_DIRS}
        /usr/lib
        /usr/local/lib
)

# Extract version from header
if(PCRE2_INCLUDE_DIR AND EXISTS "${PCRE2_INCLUDE_DIR}/pcre2.h")
    file(STRINGS "${PCRE2_INCLUDE_DIR}/pcre2.h" PCRE2_VERSION_MAJOR_LINE
        REGEX "^#define[ \t]+PCRE2_MAJOR[ \t]+[0-9]+")
    file(STRINGS "${PCRE2_INCLUDE_DIR}/pcre2.h" PCRE2_VERSION_MINOR_LINE
        REGEX "^#define[ \t]+PCRE2_MINOR[ \t]+[0-9]+")
    string(REGEX REPLACE "^#define[ \t]+PCRE2_MAJOR[ \t]+([0-9]+)" "\\1"
        PCRE2_VERSION_MAJOR "${PCRE2_VERSION_MAJOR_LINE}")
    string(REGEX REPLACE "^#define[ \t]+PCRE2_MINOR[ \t]+([0-9]+)" "\\1"
        PCRE2_VERSION_MINOR "${PCRE2_VERSION_MINOR_LINE}")
    set(PCRE2_VERSION "${PCRE2_VERSION_MAJOR}.${PCRE2_VERSION_MINOR}")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCRE2
    REQUIRED_VARS PCRE2_LIBRARY PCRE2_INCLUDE_DIR
    VERSION_VAR PCRE2_VERSION
)

if(PCRE2_FOUND)
    set(PCRE2_LIBRARIES ${PCRE2_LIBRARY})
    set(PCRE2_INCLUDE_DIRS ${PCRE2_INCLUDE_DIR})

    if(NOT TARGET PCRE2::PCRE2)
        add_library(PCRE2::PCRE2 UNKNOWN IMPORTED)
        set_target_properties(PCRE2::PCRE2 PROPERTIES
            IMPORTED_LOCATION "${PCRE2_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${PCRE2_INCLUDE_DIR}"
        )
    endif()
endif()

mark_as_advanced(PCRE2_INCLUDE_DIR PCRE2_LIBRARY)
