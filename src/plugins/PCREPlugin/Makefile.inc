all: $(BUILDDIR)PCREPlugin$(DLSUFFICS) 

pcre_maketables$(OBJSUFFICS): pcre_maketables.c
	$(CC) $(DCFLAGS) $(CFLAGS) pcre_maketables.c

pcre_table$(OBJSUFFICS): pcre_table.c
	$(CC) $(DCFLAGS) $(CFLAGS) pcre_table.c

pcre_ucd$(OBJSUFFICS): pcre_ucd.c
	$(CC) $(DCFLAGS) $(CFLAGS) pcre_ucd.c

pcre_compile$(OBJSUFFICS): pcre_compile.c
	$(CC) $(DCFLAGS) $(CFLAGS) pcre_compile.c

pcre_config$(OBJSUFFICS): pcre_config.c
	$(CC) $(DCFLAGS) $(CFLAGS)  pcre_config.c

pcre_dfa_exec$(OBJSUFFICS): pcre_dfa_exec.c
	$(CC) $(DCFLAGS) $(CFLAGS) pcre_dfa_exec.c

pcre_exec$(OBJSUFFICS): pcre_exec.c
	$(CC) $(DCFLAGS) $(CFLAGS) pcre_exec.c

pcre_fullinfo$(OBJSUFFICS): pcre_fullinfo.c
	$(CC) $(DCFLAGS) $(CFLAGS) pcre_fullinfo.c

pcre_get$(OBJSUFFICS): pcre_get.c
	$(CC) $(DCFLAGS) $(CFLAGS) pcre_get.c

pcre_globals$(OBJSUFFICS): pcre_globals.c
	$(CC) $(DCFLAGS) $(CFLAGS)  pcre_globals.c

pcre_newline$(OBJSUFFICS): pcre_newline.c
	$(CC) $(DCFLAGS) $(CFLAGS)  pcre_newline.c

pcre_ord2utf8$(OBJSUFFICS): pcre_ord2utf8.c
	$(CC) $(DCFLAGS) $(CFLAGS)  pcre_ord2utf8.c

pcre_refcount$(OBJSUFFICS): pcre_refcount.c
	$(CC) $(DCFLAGS) $(CFLAGS)  pcre_refcount.c

pcre_study$(OBJSUFFICS): pcre_study.c
	$(CC) $(DCFLAGS) $(CFLAGS)  pcre_study.c

pcre_tables$(OBJSUFFICS): pcre_tables.c
	$(CC) $(DCFLAGS) $(CFLAGS)  pcre_tables.c

pcre_valid_utf8$(OBJSUFFICS): pcre_valid_utf8.c
	$(CC) $(DCFLAGS) $(CFLAGS)  pcre_valid_utf8.c

pcre_version$(OBJSUFFICS): pcre_version.c
	$(CC) $(DCFLAGS) $(CFLAGS)  pcre_version.c

pcre_xclass$(OBJSUFFICS): pcre_xclass.c
	$(CC) $(DCFLAGS) $(CFLAGS)  pcre_xclass.c

pcre_plugin$(OBJSUFFICS): pcre_plugin.c
	$(CC) $(DCFLAGS) $(CFLAGS) pcre_plugin.c

$(BUILDDIR)PCREPlugin$(DLSUFFICS): pcre_compile$(OBJSUFFICS) pcre_config$(OBJSUFFICS) pcre_dfa_exec$(OBJSUFFICS) pcre_exec$(OBJSUFFICS) pcre_fullinfo$(OBJSUFFICS) pcre_get$(OBJSUFFICS) pcre_globals$(OBJSUFFICS) pcre_newline$(OBJSUFFICS) pcre_ord2utf8$(OBJSUFFICS) pcre_refcount$(OBJSUFFICS) pcre_study$(OBJSUFFICS) pcre_tables$(OBJSUFFICS) pcre_valid_utf8$(OBJSUFFICS) pcre_version$(OBJSUFFICS) pcre_xclass$(OBJSUFFICS) pcre_plugin$(OBJSUFFICS) pcre_maketables$(OBJSUFFICS) pcre_ucd$(OBJSUFFICS) pcre_table$(OBJSUFFICS)
	$(LN) $(LNOUT)../../$(BUILDDIR)PCREPlugin$(DLSUFFICS) $(LDFLAGS) $(DLFLAGS) pcre_compile$(OBJSUFFICS) pcre_config$(OBJSUFFICS) pcre_dfa_exec$(OBJSUFFICS) pcre_exec$(OBJSUFFICS) pcre_fullinfo$(OBJSUFFICS) pcre_get$(OBJSUFFICS) pcre_globals$(OBJSUFFICS) pcre_newline$(OBJSUFFICS) pcre_ord2utf8$(OBJSUFFICS) pcre_refcount$(OBJSUFFICS) pcre_study$(OBJSUFFICS) pcre_tables$(OBJSUFFICS) pcre_valid_utf8$(OBJSUFFICS) pcre_version$(OBJSUFFICS) pcre_xclass$(OBJSUFFICS) pcre_plugin$(OBJSUFFICS) pcre_maketables$(OBJSUFFICS) pcre_ucd$(OBJSUFFICS) pcre_table$(OBJSUFFICS)

