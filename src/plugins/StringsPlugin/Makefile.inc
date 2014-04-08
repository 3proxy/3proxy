all: $(BUILDDIR)StringsPlugin$(DLSUFFICS)

StringsPlugin$(OBJSUFFICS): StringsPlugin.c
	$(CC) $(DCFLAGS) $(CFLAGS) StringsPlugin.c

$(BUILDDIR)StringsPlugin$(DLSUFFICS): StringsPlugin$(OBJSUFFICS)
	$(LN) $(LNOUT)../../$(BUILDDIR)StringsPlugin$(DLSUFFICS) $(LDFLAGS) $(DLFLAGS) StringsPlugin$(OBJSUFFICS)
