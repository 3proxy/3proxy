#
# 3 proxy common Makefile
#

all:	$(BUILDDIR)3proxy$(EXESUFFICS) $(BUILDDIR)$(CRYPT_PREFIX)crypt$(EXESUFFICS) $(BUILDDIR)$(PREFIX)pop3p$(EXESUFFICS) $(BUILDDIR)$(PREFIX)smtpp$(EXESUFFICS) $(BUILDDIR)$(PREFIX)ftppr$(EXESUFFICS) $(BUILDDIR)$(PREFIX)tcppm$(EXESUFFICS) $(BUILDDIR)$(PREFIX)udppm$(EXESUFFICS) $(BUILDDIR)$(PREFIX)tlspr$(EXESUFFICS) $(BUILDDIR)$(PREFIX)socks$(EXESUFFICS) $(BUILDDIR)$(PREFIX)proxy$(EXESUFFICS) allplugins

sockmap$(OBJSUFFICS): sockmap.c proxy.h structures.h
	$(CC) $(CFLAGS) sockmap.c

udpsockmap$(OBJSUFFICS): udpsockmap.c proxy.h structures.h
	$(CC) $(COUT)udpsockmap$(OBJSUFFICS) $(CFLAGS) udpsockmap.c

common$(OBJSUFFICS): common.c proxy.h structures.h
	$(CC) $(CFLAGS) common.c

plugins$(OBJSUFFICS): plugins.c proxy.h structures.h
	$(CC) $(CFLAGS) plugins.c

base64$(OBJSUFFICS): base64.c
	$(CC) $(CFLAGS) base64.c

ftp$(OBJSUFFICS): ftp.c proxy.h structures.h
	$(CC) $(CFLAGS) ftp.c

sockgetchar$(OBJSUFFICS): sockgetchar.c proxy.h structures.h
	$(CC) $(CFLAGS) sockgetchar.c

proxy$(OBJSUFFICS): proxy.c proxy.h structures.h proxymain.c
	$(CC) $(CFLAGS) $(DEFINEOPTION)WITHMAIN $(DEFINEOPTION)NOPORTMAP $(DEFINEOPTION)ANONYMOUS $(DEFINEOPTION)NOUDPMAIN proxy.c

pop3p$(OBJSUFFICS): pop3p.c proxy.h structures.h proxymain.c
	$(CC) $(CFLAGS) $(DEFINEOPTION)WITHMAIN $(DEFINEOPTION)NOPORTMAP $(DEFINEOPTION)NOUDPMAIN pop3p.c

smtpp$(OBJSUFFICS): smtpp.c proxy.h structures.h proxymain.c
	$(CC) $(CFLAGS) $(DEFINEOPTION)WITHMAIN $(DEFINEOPTION)NOPORTMAP $(DEFINEOPTION)NOUDPMAIN smtpp.c

ftppr$(OBJSUFFICS): ftppr.c proxy.h structures.h proxymain.c
	$(CC) $(CFLAGS) $(DEFINEOPTION)WITHMAIN $(DEFINEOPTION)NOPORTMAP $(DEFINEOPTION)NOUDPMAIN ftppr.c

tcppm$(OBJSUFFICS): tcppm.c proxy.h structures.h proxymain.c
	$(CC) $(CFLAGS) $(DEFINEOPTION)WITHMAIN $(DEFINEOPTION)PORTMAP $(DEFINEOPTION)NOUDPMAIN tcppm.c

udppm$(OBJSUFFICS): udppm.c proxy.h structures.h proxymain.c
	$(CC) $(CFLAGS) $(DEFINEOPTION)WITHMAIN $(DEFINEOPTION)PORTMAP udppm.c

tlspr$(OBJSUFFICS): tlspr.c proxy.h structures.h proxymain.c
	$(CC) $(CFLAGS) $(DEFINEOPTION)WITHMAIN $(DEFINEOPTION)PORTMAP $(DEFINEOPTION)NOUDPMAIN tlspr.c


socks$(OBJSUFFICS): socks.c proxy.h structures.h proxymain.c
	$(CC) $(CFLAGS) $(DEFINEOPTION)WITHMAIN $(DEFINEOPTION)NOPORTMAP $(DEFINEOPTION)NOUDPMAIN socks.c

3proxy$(OBJSUFFICS): 3proxy.c proxy.h structures.h
	$(CC) $(CFLAGS) 3proxy.c

$(BUILDDIR)$(PREFIX)proxy$(EXESUFFICS): sockmap$(OBJSUFFICS) proxy$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) common$(OBJSUFFICS) log$(OBJSUFFICS) base64$(OBJSUFFICS) ftp$(OBJSUFFICS) $(COMPATLIBS)
	$(LN) $(LNOUT)$(BUILDDIR)$(PREFIX)proxy$(EXESUFFICS) $(LDFLAGS) sockmap$(OBJSUFFICS) proxy$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) log$(OBJSUFFICS) common$(OBJSUFFICS) base64$(OBJSUFFICS) ftp$(OBJSUFFICS) $(COMPATLIBS) $(LIBS)

$(BUILDDIR)$(PREFIX)pop3p$(EXESUFFICS): sockmap$(OBJSUFFICS) pop3p$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) common$(OBJSUFFICS) log$(OBJSUFFICS) $(COMPATLIBS)
	$(LN) $(LNOUT)$(BUILDDIR)$(PREFIX)pop3p$(EXESUFFICS) $(LDFLAGS) sockmap$(OBJSUFFICS) pop3p$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) log$(OBJSUFFICS) common$(OBJSUFFICS) $(COMPATLIBS) $(LIBS)

$(BUILDDIR)$(PREFIX)smtpp$(EXESUFFICS): sockmap$(OBJSUFFICS) smtpp$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) common$(OBJSUFFICS) log$(OBJSUFFICS) base64$(OBJSUFFICS) $(COMPATLIBS)
	$(LN) $(LNOUT)$(BUILDDIR)$(PREFIX)smtpp$(EXESUFFICS) $(LDFLAGS) sockmap$(OBJSUFFICS) smtpp$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) base64$(OBJSUFFICS) log$(OBJSUFFICS) common$(OBJSUFFICS) $(COMPATLIBS) $(LIBS)

$(BUILDDIR)$(PREFIX)ftppr$(EXESUFFICS): sockmap$(OBJSUFFICS) ftppr$(OBJSUFFICS) ftp$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) common$(OBJSUFFICS) log$(OBJSUFFICS) $(COMPATLIBS)
	$(LN) $(LNOUT)$(BUILDDIR)$(PREFIX)ftppr$(EXESUFFICS) $(LDFLAGS) sockmap$(OBJSUFFICS) ftppr$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) common$(OBJSUFFICS) log$(OBJSUFFICS) ftp$(OBJSUFFICS) $(COMPATLIBS) $(LIBS)

$(BUILDDIR)$(PREFIX)socks$(EXESUFFICS): sockmap$(OBJSUFFICS) udpsockmap$(OBJSUFFICS) socks$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) common$(OBJSUFFICS) log$(OBJSUFFICS)
	$(LN) $(LNOUT)$(BUILDDIR)$(PREFIX)socks$(EXESUFFICS) $(LDFLAGS) sockmap$(OBJSUFFICS) udpsockmap$(OBJSUFFICS) socks$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) log$(OBJSUFFICS) common$(OBJSUFFICS) $(LIBS)

$(BUILDDIR)$(PREFIX)tcppm$(EXESUFFICS): sockmap$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) tcppm$(OBJSUFFICS) common$(OBJSUFFICS) log$(OBJSUFFICS)
	$(LN) $(LNOUT)$(BUILDDIR)$(PREFIX)tcppm$(EXESUFFICS) $(LDFLAGS) sockmap$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) tcppm$(OBJSUFFICS) log$(OBJSUFFICS) common$(OBJSUFFICS) $(LIBS)

$(BUILDDIR)$(PREFIX)udppm$(EXESUFFICS): sockmap$(OBJSUFFICS) udpsockmap$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) udppm$(OBJSUFFICS) common$(OBJSUFFICS) log$(OBJSUFFICS) hash$(OBJSUFFICS)
	$(LN) $(LNOUT)$(BUILDDIR)$(PREFIX)udppm$(EXESUFFICS) $(LDFLAGS) sockmap$(OBJSUFFICS) udpsockmap$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) udppm$(OBJSUFFICS) log$(OBJSUFFICS) common$(OBJSUFFICS) hash$(OBJSUFFICS) $(LIBS)

$(BUILDDIR)$(PREFIX)tlspr$(EXESUFFICS): sockmap$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) tlspr$(OBJSUFFICS) common$(OBJSUFFICS) log$(OBJSUFFICS)
	$(LN) $(LNOUT)$(BUILDDIR)$(PREFIX)tlspr$(EXESUFFICS) $(LDFLAGS) sockmap$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) tlspr$(OBJSUFFICS) log$(OBJSUFFICS) common$(OBJSUFFICS) $(LIBS)

mainfunc$(OBJSUFFICS): proxy.h structures.h proxymain.c
	$(CC) $(COUT)mainfunc$(OBJSUFFICS) $(CFLAGS) $(DEFINEOPTION)MODULEMAINFUNC=mainfunc proxymain.c

srvproxy$(OBJSUFFICS): proxy.c proxy.h structures.h
	$(CC) $(COUT)srvproxy$(OBJSUFFICS) $(CFLAGS) proxy.c

srvpop3p$(OBJSUFFICS): pop3p.c proxy.h structures.h
	$(CC) $(COUT)srvpop3p$(OBJSUFFICS) $(CFLAGS) pop3p.c

srvsmtpp$(OBJSUFFICS): smtpp.c proxy.h structures.h
	$(CC) $(COUT)srvsmtpp$(OBJSUFFICS) $(CFLAGS) smtpp.c

srvftppr$(OBJSUFFICS): ftppr.c proxy.h structures.h
	$(CC) $(COUT)srvftppr$(OBJSUFFICS) $(CFLAGS) ftppr.c

srvtcppm$(OBJSUFFICS): tcppm.c proxy.h structures.h
	$(CC) $(COUT)srvtcppm$(OBJSUFFICS) $(CFLAGS) tcppm.c

srvtlspr$(OBJSUFFICS): tlspr.c proxy.h structures.h
	$(CC) $(COUT)srvtlspr$(OBJSUFFICS) $(CFLAGS) tlspr.c

srvauto$(OBJSUFFICS): auto.c proxy.h structures.h
	$(CC) $(COUT)srvauto$(OBJSUFFICS) $(CFLAGS) auto.c

srvsocks$(OBJSUFFICS): socks.c proxy.h structures.h
	$(CC) $(COUT)srvsocks$(OBJSUFFICS) $(CFLAGS) socks.c

srvwebadmin$(OBJSUFFICS): webadmin.c proxy.h structures.h
	$(CC) $(COUT)srvwebadmin$(OBJSUFFICS) $(CFLAGS) webadmin.c

srvudppm$(OBJSUFFICS): udppm.c proxy.h structures.h
	$(CC) $(COUT)srvudppm$(OBJSUFFICS) $(CFLAGS) udppm.c

srvdnspr$(OBJSUFFICS): dnspr.c proxy.h structures.h
	$(CC) $(COUT)srvdnspr$(OBJSUFFICS) $(CFLAGS) dnspr.c

auth$(OBJSUFFICS): auth.c proxy.h structures.h
	$(CC) $(COUT)auth$(OBJSUFFICS) $(CFLAGS) auth.c

acl$(OBJSUFFICS): acl.c proxy.h structures.h
	$(CC) $(COUT)acl$(OBJSUFFICS) $(CFLAGS) acl.c

limiter$(OBJSUFFICS): limiter.c proxy.h structures.h
	$(CC) $(COUT)limiter$(OBJSUFFICS) $(CFLAGS) limiter.c

redirect$(OBJSUFFICS): redirect.c proxy.h structures.h
	$(CC) $(COUT)redirect$(OBJSUFFICS) $(CFLAGS) redirect.c

hash$(OBJSUFFICS): hash.c proxy.h structures.h
	$(CC) $(COUT)hash$(OBJSUFFICS) $(CFLAGS) hash.c

hashtables$(OBJSUFFICS): hashtables.c proxy.h structures.h libs/blake2.h
	$(CC) $(COUT)hashtables$(OBJSUFFICS) $(CFLAGS) hashtables.c

resolve$(OBJSUFFICS): resolve.c proxy.h structures.h
	$(CC) $(COUT)resolve$(OBJSUFFICS) $(CFLAGS) resolve.c

authradius$(OBJSUFFICS): authradius.c proxy.h structures.h mdhash.h
	$(CC) $(COUT)authradius$(OBJSUFFICS) $(CFLAGS) authradius.c

conf$(OBJSUFFICS): conf.c proxy.h structures.h
	$(CC) $(COUT)conf$(OBJSUFFICS) $(CFLAGS) conf.c

log$(OBJSUFFICS): log.c proxy.h structures.h
	$(CC) $(COUT)log$(OBJSUFFICS) $(CFLAGS) log.c

datatypes$(OBJSUFFICS): datatypes.c proxy.h structures.h
	$(CC) $(COUT)datatypes$(OBJSUFFICS) $(CFLAGS) datatypes.c

3proxy_crypt$(OBJSUFFICS): 3proxy_crypt.c libs/blake2.h mdhash.h
	$(CC) $(COUT)3proxy_crypt$(OBJSUFFICS) $(CFLAGS) 3proxy_crypt.c

3proxy_cryptmain$(OBJSUFFICS): 3proxy_crypt.c libs/blake2.h mdhash.h
	$(CC) $(COUT)3proxy_cryptmain$(OBJSUFFICS) $(CFLAGS) $(DEFINEOPTION)WITHMAIN 3proxy_crypt.c

blake2$(OBJSUFFICS):  libs/blake2b-ref.c
	$(CC) $(COUT)blake2$(OBJSUFFICS) $(CFLAGS) libs/blake2b-ref.c

mdhash$(OBJSUFFICS): mdhash.c mdhash.h proxy.h structures.h
	$(CC) $(COUT)mdhash$(OBJSUFFICS) $(CFLAGS) mdhash.c

md4$(OBJSUFFICS): libs/md4.c libs/md4.h
	$(CC) $(COUT)md4$(OBJSUFFICS) $(CFLAGS) libs/md4.c

md5$(OBJSUFFICS): libs/md5.c libs/md5.h
	$(CC) $(COUT)md5$(OBJSUFFICS) $(CFLAGS) libs/md5.c

$(BUILDDIR)$(CRYPT_PREFIX)crypt$(EXESUFFICS): $(BUNDLED_HASH_OBJS) 3proxy_cryptmain$(OBJSUFFICS) base64$(OBJSUFFICS) mdhash$(OBJSUFFICS)
	$(LN) $(LNOUT)$(BUILDDIR)$(CRYPT_PREFIX)crypt$(EXESUFFICS) $(LDFLAGS) $(BUNDLED_HASH_OBJS) base64$(OBJSUFFICS) mdhash$(OBJSUFFICS) 3proxy_cryptmain$(OBJSUFFICS) $(LIBS)

stringtable$(OBJSUFFICS):  stringtable.c
	$(CC) $(COUT)stringtable$(OBJSUFFICS) $(CFLAGS) stringtable.c

ssllib$(OBJSUFFICS): ssllib.c structures.h proxy.h ssl.h
	$(CC) $(COUT)ssllib$(OBJSUFFICS) $(CFLAGS) ssllib.c

ssl$(OBJSUFFICS): ssl.c structures.h proxy.h ssl.h
	$(CC) $(COUT)ssl$(OBJSUFFICS) $(CFLAGS) ssl.c

pcre$(OBJSUFFICS): pcre.c structures.h
	$(CC) $(COUT)pcre$(OBJSUFFICS) $(CFLAGS) $(DEFINEOPTION)WITH_PCRE pcre.c

$(BUILDDIR)3proxy$(EXESUFFICS): 3proxy$(OBJSUFFICS) mainfunc$(OBJSUFFICS) srvproxy$(OBJSUFFICS) srvpop3p$(OBJSUFFICS) srvsmtpp$(OBJSUFFICS) srvftppr$(OBJSUFFICS) srvsocks$(OBJSUFFICS) srvtcppm$(OBJSUFFICS) srvtlspr$(OBJSUFFICS) srvauto$(OBJSUFFICS) srvudppm$(OBJSUFFICS) sockmap$(OBJSUFFICS) udpsockmap$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) common$(OBJSUFFICS) auth$(OBJSUFFICS) acl$(OBJSUFFICS) limiter$(OBJSUFFICS) redirect$(OBJSUFFICS) authradius$(OBJSUFFICS) hash$(OBJSUFFICS) hashtables$(OBJSUFFICS) resolve$(OBJSUFFICS) sql$(OBJSUFFICS) conf$(OBJSUFFICS) log$(OBJSUFFICS) datatypes$(OBJSUFFICS) $(BUNDLED_HASH_OBJS) 3proxy_crypt$(OBJSUFFICS) base64$(OBJSUFFICS) ftp$(OBJSUFFICS) stringtable$(OBJSUFFICS) srvwebadmin$(OBJSUFFICS) srvdnspr$(OBJSUFFICS) plugins$(OBJSUFFICS) mdhash$(OBJSUFFICS) $(SSL_OBJS) $(PCRE_OBJS) $(COMPATLIBS) $(VERSIONDEP)
	$(LN) $(LNOUT)$(BUILDDIR)3proxy$(EXESUFFICS) $(LDFLAGS) $(VERFILE)  3proxy$(OBJSUFFICS) mainfunc$(OBJSUFFICS) auth$(OBJSUFFICS) acl$(OBJSUFFICS) limiter$(OBJSUFFICS) redirect$(OBJSUFFICS) authradius$(OBJSUFFICS) hash$(OBJSUFFICS) hashtables$(OBJSUFFICS) resolve$(OBJSUFFICS) sql$(OBJSUFFICS) conf$(OBJSUFFICS) datatypes$(OBJSUFFICS) srvauto$(OBJSUFFICS) srvproxy$(OBJSUFFICS) srvpop3p$(OBJSUFFICS) srvsmtpp$(OBJSUFFICS) srvftppr$(OBJSUFFICS) srvsocks$(OBJSUFFICS) srvtcppm$(OBJSUFFICS) srvtlspr$(OBJSUFFICS) srvudppm$(OBJSUFFICS) sockmap$(OBJSUFFICS) udpsockmap$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) common$(OBJSUFFICS) log$(OBJSUFFICS) 3proxy_crypt$(OBJSUFFICS) $(BUNDLED_HASH_OBJS) base64$(OBJSUFFICS) ftp$(OBJSUFFICS) stringtable$(OBJSUFFICS) srvwebadmin$(OBJSUFFICS) srvdnspr$(OBJSUFFICS) plugins$(OBJSUFFICS) mdhash$(OBJSUFFICS) $(SSL_OBJS) $(PCRE_OBJS) $(COMPATLIBS) $(LIBS) $(PCRE_LIBS)

