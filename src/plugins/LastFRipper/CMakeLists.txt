set(LAST_FRIPPER_SOURCES lastFripper.c)
add_library(lastFripper SHARED ${LAST_FRIPPER_SOURCES})
set_target_properties(lastFripper PROPERTIES PREFIX "")

