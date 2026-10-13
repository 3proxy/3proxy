/* The configuration as it is before any command: included where both the
   template for a new configuration and the first one are defined. */
	.timeouts = {
		1,    /* SINGLEBYTE_S */
		5,    /* SINGLEBYTE_L */
		30,   /* STRING_S */
		60,   /* STRING_L */
		180,  /* CONNECTION_S */
		1800, /* CONNECTION_L */
		15,   /* DNS_TO */
		60,   /* CHAIN_TO */
		15,   /* CONNECT_TO */
		5,    /* CONNBACK_TO */
		5,    /* LINGER_TO */
		0
	},
	.acl = NULL,
	.conffile = NULL,
	.bandlimiter = NULL,
	.bandlimiterout = NULL,
	.connlimiter = NULL,
	.trafcounter = NULL,
	.services = NULL,
	.stacksize = 0,
	.poolmax = -1,
	.pooltimeout = 60,
	.counterd = -1,
	.rotate = 0,
	.paused = 0,
	.archiverc = 0,
	.demon = 0,
	.maxchild = DEFAULT_MAXCHILD,
	.backlog = 0,
	.version = 0,
	.noforce = 0,
	.bandlimver = 0,
	.parentretries = 2,
	.authcachetype = 6,
	.authcachetime = 600,
	.filtermaxsize = 1048576,
	.gracetraf = 0,
	.gracenum = 0,
	.gracedelay = 0,
	.maxseg = 0,
	.logname = NULL,
	.archiver = NULL,
	.logtype = NONE,
	.countertype = NONE,
	.counterfile = NULL,
#ifndef NOIPV6
	.intsa = {AF_INET},
	.extsa6 = {AF_INET6},
	.extsa = {AF_INET},
#else
	.intsa = {AF_INET},
	.extsa = {AF_INET},
#endif
	.pwl = NULL,
	.authenticate = NULL,
	.authfunc = doconnect,
	.logfunc = lognone,
	.bandlimfunc = NULL,
	.trafcountfunc = NULL,
	.logtarget = NULL,
	.logformat = NULL,
	.fmon = NULL,
	.filters = NULL,
	.authfuncs = NULL,
	.stdlog = NULL,
	.stringtable = NULL,
	.logtime = (time_t)0,
	.logdumpsrv = 0,
	.logdumpcli = 0,
	.delimchar = '@',
