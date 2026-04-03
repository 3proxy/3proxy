# FindPAM.cmake
#
# Find the PAM library
#
# This module defines:
#  PAM_FOUND - whether the PAM library was found
#  PAM_INCLUDE_DIRS - the PAM include directories
#  PAM_LIBRARIES - the PAM libraries

# Find include directory
find_path(PAM_INCLUDE_DIR
    NAMES security/pam_appl.h pam/pam_appl.h
    HINTS
        /usr/include
        /usr/local/include
)

# Find library
find_library(PAM_LIBRARY
    NAMES pam
    HINTS
        /usr/lib
        /usr/local/lib
        /usr/lib/x86_64-linux-gnu
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PAM
    REQUIRED_VARS PAM_LIBRARY PAM_INCLUDE_DIR
)

if(PAM_FOUND)
    set(PAM_LIBRARIES ${PAM_LIBRARY})
    set(PAM_INCLUDE_DIRS ${PAM_INCLUDE_DIR})

    if(NOT TARGET PAM::PAM)
        add_library(PAM::PAM UNKNOWN IMPORTED)
        set_target_properties(PAM::PAM PROPERTIES
            IMPORTED_LOCATION "${PAM_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${PAM_INCLUDE_DIR}"
        )
    endif()
endif()

mark_as_advanced(PAM_INCLUDE_DIR PAM_LIBRARY)
