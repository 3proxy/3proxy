set(WINDOWS_AUTHENTICATION_SOURCES WindowsAuthentication.c)
add_library(WindowsAuthentication SHARED ${WINDOWS_AUTHENTICATION_SOURCES})
set_target_properties(WindowsAuthentication PROPERTIES PREFIX "")
