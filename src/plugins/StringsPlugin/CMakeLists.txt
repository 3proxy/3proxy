set(STRINGS_PLUGIN_SOURCES StringsPlugin.c)
add_library(StringsPlugin SHARED ${STRINGS_PLUGIN_SOURCES})
set_target_properties(StringsPlugin PROPERTIES PREFIX "")

