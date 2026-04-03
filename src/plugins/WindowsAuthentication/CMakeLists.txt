# WindowsAuthentication
if(NOT WIN32)
    message(STATUS "WindowsAuthentication requires Windows, skipping")
    return()
endif()

add_3proxy_plugin(WindowsAuthentication
    SOURCES WindowsAuthentication.c
    LIBRARIES advapi32
)
