all: $(BUILDDIR)WindowsAuthentication$(DLSUFFICS)

WindowsAuthentication$(OBJSUFFICS): WindowsAuthentication.c
	$(CC) $(DCFLAGS) $(CFLAGS) WindowsAuthentication.c

$(BUILDDIR)WindowsAuthentication$(DLSUFFICS): WindowsAuthentication$(OBJSUFFICS)
	$(LN) $(LNOUT)../../$(BUILDDIR)WindowsAuthentication$(DLSUFFICS) $(LDFLAGS) $(DLFLAGS) WindowsAuthentication$(OBJSUFFICS) $(LIBS)

