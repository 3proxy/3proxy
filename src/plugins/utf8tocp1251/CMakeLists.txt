set(UTFCP_PLUGIN_SOURCES utf8tocp1251.c)
add_library(utf8tocp1251 SHARED ${UTFCP_PLUGIN_SOURCES})
set_target_properties(utf8tocp1251 PROPERTIES PREFIX "")
