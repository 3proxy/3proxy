set(TRANSPARENT_PLUGIN_SOURCES transparent_plugin.c)
add_library(TransparentPlugin SHARED ${TRANSPARENT_PLUGIN_SOURCES})
set_target_properties(TransparentPlugin PROPERTIES PREFIX "")
