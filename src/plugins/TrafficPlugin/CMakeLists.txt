set(TRAFFIC_PLUGIN_SOURCES TrafficPlugin.c)
add_library(TrafficPlugin SHARED ${TRAFFIC_PLUGIN_SOURCES})
set_target_properties(TrafficPlugin PROPERTIES PREFIX "")
