all: $(BUILDDIR)TrafficPlugin$(DLSUFFICS)

TrafficPlugin$(OBJSUFFICS): TrafficPlugin.c
	$(CC) $(DCFLAGS) $(CFLAGS) TrafficPlugin.c

$(BUILDDIR)TrafficPlugin$(DLSUFFICS): TrafficPlugin$(OBJSUFFICS)
	$(LN) $(LNOUT)../../$(BUILDDIR)TrafficPlugin$(DLSUFFICS) $(LDFLAGS) $(DLFLAGS) TrafficPlugin$(OBJSUFFICS)
