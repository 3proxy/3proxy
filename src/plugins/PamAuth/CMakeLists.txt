find_library (PAM_LIBRARY
  NAMES pam libpam
  )

set(PAMAUTH_PLUGIN_SOURCES pamauth.c)

add_library(pamauth SHARED ${PAMAUTH_PLUGIN_SOURCES })
target_link_libraries(pamauth PRIVATE ${PAM_LIBRARY})
set_target_properties(pamauth PROPERTIES PREFIX "")

