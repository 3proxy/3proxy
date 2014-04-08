#$Id: Makefile.inc,v 1.3 2007/01/23 16:00:26 vlad Exp $
#
# 3 proxy common Makefile
#

all:
	$(TYPECOMMAND) $(MAKEFILE) > src/Makefile.var
	@cd src && $(MAKE)

clean:
	@$(REMOVECOMMAND) *$(OBJSUFFICS) $(COMPFILES)
	@cd src && $(MAKE) clean

