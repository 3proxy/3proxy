all: $(BUILDDIR)FilePlugin$(DLSUFFICS)

FilePlugin$(OBJSUFFICS): FilePlugin.c
	$(CC) $(DCFLAGS) $(CFLAGS) FilePlugin.c

$(BUILDDIR)FilePlugin$(DLSUFFICS): FilePlugin$(OBJSUFFICS)
	$(LN) $(LNOUT)../../$(BUILDDIR)FilePlugin$(DLSUFFICS) $(LDFLAGS) $(DLFLAGS) FilePlugin$(OBJSUFFICS)
