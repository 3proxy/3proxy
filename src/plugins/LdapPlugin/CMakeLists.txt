find_library(LDAP_LIBRARY
  NAMES ldap
  HINTS "${CMAKE_SOURCE_DIR}/lib"
  )

add_library(ldapauth SHARED ldapauth.c)
target_include_directories(ldapauth PRIVATE ${CMAKE_SOURCE_DIR}/include/ldapwindev)
target_link_libraries(ldapauth PRIVATE ${LDAP_LIBRARY})
set_target_properties(ldapauth PROPERTIES PREFIX "")


add_executable(getldapuser WIN32 getldapuser.c)
target_include_directories(getldapuser PRIVATE ${CMAKE_SOURCE_DIR}/include/ldapwindev)
target_link_libraries(getldapuser PRIVATE ${LDAP_LIBRARY})

