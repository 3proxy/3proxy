PAMLIB ?= pam

all: $(BUILDDIR)pamauth$(DLSUFFICS)

pamauth$(OBJSUFFICS): pamauth.c
	$(CC) $(DCFLAGS) $(CFLAGS) pamauth.c

$(BUILDDIR)pamauth$(DLSUFFICS): pamauth$(OBJSUFFICS)
	$(LN) $(LNOUT)../../$(BUILDDIR)pamauth$(DLSUFFICS) $(LDFLAGS) $(DLFLAGS) $(LIBSPREFIX)$(PAMLIB)$(LIBSSUFFIX) pamauth$(OBJSUFFICS)

