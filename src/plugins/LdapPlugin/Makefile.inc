all: $(BUILDDIR)ldapauth$(DLSUFFICS)

ldapauth$(OBJSUFFICS): ldapauth.c
	$(CC) $(DCFLAGS) $(CFLAGS) ldapauth.c

$(BUILDDIR)ldapauth$(DLSUFFICS): ldapauth$(OBJSUFFICS)
	$(LN) $(LNOUT)../../$(BUILDDIR)ldapauth$(DLSUFFICS) $(LDFLAGS) $(DLFLAGS) $(LIBSPREFIX)ladp$(LIBSSUFFIX) ldapauth$(OBJSUFFICS)
