set(FILE_PLUGIN_SOURCES FilePlugin.c)
add_library(FilePlugin SHARED ${FILE_PLUGIN_SOURCES})
set_target_properties(FilePlugin PROPERTIES PREFIX "")
