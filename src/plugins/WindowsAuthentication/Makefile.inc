all: $(BUILDDIR)WindowsAuthentication$(DLSUFFICS)

WindowsAuthentication$(OBJSUFFICS): WindowsAuthentication.c
	$(CC) $(CFLAGS) $(DCFLAGS) WindowsAuthentication.c

$(BUILDDIR)WindowsAuthentication$(DLSUFFICS): WindowsAuthentication$(OBJSUFFICS)
	$(LN) $(LNOUT)../../$(BUILDDIR)WindowsAuthentication$(DLSUFFICS) $(LDFLAGS) $(DLFLAGS) WindowsAuthentication$(OBJSUFFICS) $(LIBS)

