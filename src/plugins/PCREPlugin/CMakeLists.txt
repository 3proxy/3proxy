# PCREPlugin - requires PCRE2

if(NOT PCRE2_FOUND)
    message(STATUS "PCREPlugin requires PCRE2, skipping")
    return()
endif()

add_3proxy_plugin(PCREPlugin
    SOURCES pcre_plugin.c
    COMPILE_DEFINITIONS PCRE2_CODE_UNIT_WIDTH=8
)

if(TARGET PCRE2::PCRE2)
    target_link_libraries(PCREPlugin PRIVATE PCRE2::PCRE2)
else()
    target_link_libraries(PCREPlugin PRIVATE ${PCRE2_LIBRARIES})
    if(PCRE2_INCLUDE_DIRS)
        target_include_directories(PCREPlugin PRIVATE ${PCRE2_INCLUDE_DIRS})
    endif()
endif()
