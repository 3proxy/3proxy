# PamAuth - requires PAM

if(NOT PAM_FOUND)
    message(STATUS "PamAuth requires PAM, skipping")
    return()
endif()

add_3proxy_plugin(PamAuth
    SOURCES pamauth.c
)

if(TARGET PAM::PAM)
    target_link_libraries(PamAuth PRIVATE PAM::PAM)
else()
    target_link_libraries(PamAuth PRIVATE ${PAM_LIBRARIES})
    if(PAM_INCLUDE_DIRS)
        target_include_directories(PamAuth PRIVATE ${PAM_INCLUDE_DIRS})
    endif()
endif()
