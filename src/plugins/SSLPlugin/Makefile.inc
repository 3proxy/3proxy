all: $(BUILDDIR)SSLPlugin$(DLSUFFICS)



ssl_plugin$(OBJSUFFICS): ssl_plugin.c
	$(CC) $(DCFLAGS) $(CFLAGS) ssl_plugin.c

my_ssl$(OBJSUFFICS): my_ssl.c
	$(CC) $(DCFLAGS) $(CFLAGS) my_ssl.c


$(BUILDDIR)SSLPlugin$(DLSUFFICS): ssl_plugin$(OBJSUFFICS) my_ssl$(OBJSUFFICS)
	$(LN) $(LNOUT)../../$(BUILDDIR)SSLPlugin$(DLSUFFICS) $(LDFLAGS) $(DLFLAGS) ssl_plugin$(OBJSUFFICS) my_ssl$(OBJSUFFICS) $(LIBS) 
	