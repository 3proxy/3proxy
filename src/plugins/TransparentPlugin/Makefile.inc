all: $(BUILDDIR)TransparentPlugin$(DLSUFFICS)



transparent_plugin$(OBJSUFFICS): transparent_plugin.c
	$(CC) $(DCFLAGS) $(CFLAGS) transparent_plugin.c


$(BUILDDIR)TransparentPlugin$(DLSUFFICS): transparent_plugin$(OBJSUFFICS)
	$(LN) $(LNOUT)../../$(BUILDDIR)TransparentPlugin$(DLSUFFICS) $(LDFLAGS) $(DLFLAGS) transparent_plugin$(OBJSUFFICS)
