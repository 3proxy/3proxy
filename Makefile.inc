#
# 3 proxy common Makefile
#

all:
	$(TYPECOMMAND) $(MAKEFILE) > src/Makefile.var
	@cd src && $(MAKE)

clean:
	@$(REMOVECOMMAND) *$(OBJSUFFICS) $(COMPFILES)
	@cd src && $(MAKE) clean

