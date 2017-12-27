if (3PROXY_PLUGIN_FILE)
  add_subdirectory(FilePlugin)
endif (3PROXY_PLUGIN_FILE)

if(3PROXY_PLUGIN_LR)
  add_subdirectory(LastFRipper)
endif(3PROXY_PLUGIN_LR)

if(3PROXY_PLUGIN_LDAP)
  add_subdirectory(LdapPlugin)
endif(3PROXY_PLUGIN_LDAP)

if(3PROXY_PLUGIN_PAM)
  add_subdirectory(PamAuth)
endif(3PROXY_PLUGIN_PAM)

if(3PROXY_PLUGIN_PCRE)
  add_subdirectory(PCREPlugin)
endif(3PROXY_PLUGIN_PCRE)

if(3PROXY_PLUGIN_SSL)
  add_subdirectory(SSLPlugin)
endif(3PROXY_PLUGIN_SSL)

if(3PROXY_PLUGIN_STRINGS)
  add_subdirectory(StringsPlugin)
endif(3PROXY_PLUGIN_STRINGS)

if(3PROXY_PLUGIN_TRAFFIC)
  add_subdirectory(TrafficPlugin)
endif(3PROXY_PLUGIN_TRAFFIC)

if(3PROXY_PLUGIN_TRANSPARENT)
  add_subdirectory(TransparentPlugin)
endif(3PROXY_PLUGIN_TRANSPARENT)

if(3PROXY_PLUGIN_U2C)
  add_subdirectory(utf8tocp1251)
endif(3PROXY_PLUGIN_U2C)

if(3PROXY_PLUGIN_WINAUTH)
  add_subdirectory(WindowsAuthentication)
endif(3PROXY_PLUGIN_WINAUTH)

