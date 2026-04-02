all: $(BUILDDIR)PCREPlugin$(DLSUFFICS)

pcre_plugin$(OBJSUFFICS): pcre_plugin.c
	$(CC) $(DCFLAGS) $(CFLAGS) pcre_plugin.c

$(BUILDDIR)PCREPlugin$(DLSUFFICS): pcre_plugin$(OBJSUFFICS)
	$(LN) $(LNOUT)../../$(BUILDDIR)PCREPlugin$(DLSUFFICS) $(LDFLAGS) $(DLFLAGS) pcre_plugin$(OBJSUFFICS) $(LIBSPREFIX)pcre2-8$(LIBSSUFFIX)
