all: $(BUILDDIR)lastFripper$(DLSUFFICS)

lastFripper$(OBJSUFFICS): lastFripper.c
	$(CC) $(DCFLAGS) $(CFLAGS) lastFripper.c

$(BUILDDIR)lastFripper$(DLSUFFICS): lastFripper$(OBJSUFFICS)
	$(LN) $(LNOUT)../../$(BUILDDIR)lastFripper$(DLSUFFICS) $(LDFLAGS) $(DLFLAGS) lastFripper$(OBJSUFFICS)
