# FindODBC.cmake
#
# Find the ODBC library
#
# This module defines:
#  ODBC_FOUND - whether the ODBC library was found
#  ODBC_INCLUDE_DIRS - the ODBC include directories
#  ODBC_LIBRARIES - the ODBC libraries

# Try pkg-config first
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PC_ODBC QUIET odbc)
endif()

# Find include directory
find_path(ODBC_INCLUDE_DIR
    NAMES sql.h
    HINTS
        ${PC_ODBC_INCLUDE_DIRS}
        /usr/include
        /usr/local/include
)

# Find library
if(WIN32)
    # On Windows, ODBC is typically available as odbc32
    find_library(ODBC_LIBRARY
        NAMES odbc32
        HINTS
            ${PC_ODBC_LIBRARY_DIRS}
    )
else()
    # On Unix, look for odbc
    find_library(ODBC_LIBRARY
        NAMES odbc iodbc
        HINTS
            ${PC_ODBC_LIBRARY_DIRS}
            /usr/lib
            /usr/local/lib
            /usr/lib/x86_64-linux-gnu
    )
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ODBC
    REQUIRED_VARS ODBC_LIBRARY ODBC_INCLUDE_DIR
)

if(ODBC_FOUND)
    set(ODBC_LIBRARIES ${ODBC_LIBRARY})
    set(ODBC_INCLUDE_DIRS ${ODBC_INCLUDE_DIR})

    if(NOT TARGET ODBC::ODBC)
        add_library(ODBC::ODBC UNKNOWN IMPORTED)
        set_target_properties(ODBC::ODBC PROPERTIES
            IMPORTED_LOCATION "${ODBC_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${ODBC_INCLUDE_DIR}"
        )
    endif()
endif()

mark_as_advanced(ODBC_INCLUDE_DIR ODBC_LIBRARY)
