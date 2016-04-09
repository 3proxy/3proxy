#
# 3 proxy common Makefile
#

all:	$(BUILDDIR)proxy$(EXESUFFICS)


sockmap$(OBJSUFFICS): sockmap.c proxy.h structures.h
	$(CC) $(CFLAGS) sockmap.c

common$(OBJSUFFICS): common.c proxy.h structures.h
	$(CC) $(CFLAGS) common.c

myalloc$(OBJSUFFICS): myalloc.c proxy.h structures.h
	$(CC) $(CFLAGS) myalloc.c

base64$(OBJSUFFICS): base64.c
	$(CC) $(CFLAGS) base64.c

ftp$(OBJSUFFICS): ftp.c proxy.h structures.h
	$(CC) $(CFLAGS) ftp.c

sockgetchar$(OBJSUFFICS): sockgetchar.c proxy.h structures.h
	$(CC) $(CFLAGS) sockgetchar.c

proxy$(OBJSUFFICS): proxy.c proxy.h structures.h proxymain.c
	$(CC) $(CFLAGS) $(DEFINEOPTION)WITHMAIN $(DEFINEOPTION)NOPORTMAP $(DEFINEOPTION)ANONYMOUS proxy.c

$(BUILDDIR)proxy$(EXESUFFICS): sockmap$(OBJSUFFICS) proxy$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) myalloc$(OBJSUFFICS) common$(OBJSUFFICS) base64$(OBJSUFFICS) ftp$(OBJSUFFICS) $(COMPATLIBS)
	$(LN) $(LNOUT)$(BUILDDIR)proxy$(EXESUFFICS) $(LDFLAGS) sockmap$(OBJSUFFICS) proxy$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) myalloc$(OBJSUFFICS) common$(OBJSUFFICS) base64$(OBJSUFFICS) ftp$(OBJSUFFICS) $(COMPATLIBS) $(LIBS)

mainfunc$(OBJSUFFICS): proxy.h structures.h proxymain.c
	$(CC) $(COUT)mainfunc$(OBJSUFFICS) $(CFLAGS) $(DEFINEOPTION)MODULEMAINFUNC=mainfunc proxymain.c



clean:
	@$(REMOVECOMMAND) *$(OBJSUFFICS) $(COMPFILES)
