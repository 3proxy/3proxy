#!/bin/sh
gcc   -shared -o libldapauth.so ldapauth_new.c  -DNOODBC -I/usr/include  -L/usr/lib -lldap 

