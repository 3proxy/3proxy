del ldapauth.dll
gcc  -o getldapuser getldapuser.c -DWIN32  -I"./ldapwindev" -L"./ldapwindev" -lldap
gcc  -shared -o ldapauth.dll ldapauth.c -DWIN32 -I"./ldapwindev" -L"./ldapwindev" -lldap

