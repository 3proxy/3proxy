#
# 3 proxy common Makefile
#

all:
	@$(TYPECOMMAND) $(MAKEFILE) > src/Makefile.var
	@cd src && $(MAKE)

clean:
	@cd src && $(REMOVECOMMAND) *$(OBJSUFFICS) $(COMPFILES) && cd ..
	@$(AFTERCLEAN)
	

