#
# 3proxy plugin definitions
#
# This file defines functions for building plugins
#

# Function to add a simple plugin (single source file, no dependencies)
function(add_3proxy_plugin_simple PLUGIN_NAME SOURCE_FILE)
    if(WIN32)
        set(PLUGIN_SUFFIX ".dll")
    else()
        set(PLUGIN_SUFFIX ".ld.so")
    endif()

    add_library(${PLUGIN_NAME} SHARED ${SOURCE_FILE})

    set_target_properties(${PLUGIN_NAME} PROPERTIES
        PREFIX ""
        SUFFIX ${PLUGIN_SUFFIX}
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    )

    target_link_libraries(${PLUGIN_NAME} PRIVATE Threads::Threads)

    target_include_directories(${PLUGIN_NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}/src
    )
endfunction()

# Function to add a plugin with dependencies
function(add_3proxy_plugin PLUGIN_NAME)
    set(options "")
    set(oneValueArgs "")
    set(multiValueArgs SOURCES LIBRARIES INCLUDE_DIRS COMPILE_DEFINITIONS LINK_OPTIONS)

    cmake_parse_arguments(PLUGIN "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(WIN32)
        set(PLUGIN_SUFFIX ".dll")
    else()
        set(PLUGIN_SUFFIX ".ld.so")
    endif()

    add_library(${PLUGIN_NAME} SHARED ${PLUGIN_SOURCES})

    set_target_properties(${PLUGIN_NAME} PROPERTIES
        PREFIX ""
        SUFFIX ${PLUGIN_SUFFIX}
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    )

    # Always link with Threads
    target_link_libraries(${PLUGIN_NAME} PRIVATE Threads::Threads)

    if(PLUGIN_LIBRARIES)
        target_link_libraries(${PLUGIN_NAME} PRIVATE ${PLUGIN_LIBRARIES})
    endif()

    if(PLUGIN_INCLUDE_DIRS)
        target_include_directories(${PLUGIN_NAME} PRIVATE ${PLUGIN_INCLUDE_DIRS})
    endif()

    if(PLUGIN_COMPILE_DEFINITIONS)
        target_compile_definitions(${PLUGIN_NAME} PRIVATE ${PLUGIN_COMPILE_DEFINITIONS})
    endif()

    if(PLUGIN_LINK_OPTIONS)
        set_target_properties(${PLUGIN_NAME} PROPERTIES LINK_OPTIONS "${PLUGIN_LINK_OPTIONS}")
    endif()

    target_include_directories(${PLUGIN_NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}/src
    )
endfunction()
