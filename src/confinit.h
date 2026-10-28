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
	/* clients served on event loops, their data relayed by the loops */
	.loopmode = 2,
	.poolmax = DEFAULT_POOLMAX,
	.pooltimeout = DEFAULT_POOLTIMEOUT,
	.counterd = -1,
	.rotate = 0,
	.paused = 0,
	.archiverc = 0,
	.minlogqueue = LOGQUEUEMIN,
	.maxlogqueue = LOGQUEUEMAX,
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
	.archiver = NULL,
	.logtype = NONE,
	.countertype = NONE,
	.counterfile = NULL,
	.intsa = {AF_INET},
	.extsa6 = {AF_INET6},
	.extsa = {AF_INET},
	.pwl = NULL,
	.authenticate = NULL,
	.authfunc = doconnect,
	.logfunc = logdo,
	.bandlimfunc = NULL,
	.trafcountfunc = NULL,
	.logger = NULL,
	.logformat = NULL,
	.fmon = NULL,
	.filters = NULL,
	.authfuncs = NULL,
	.stringtable = NULL,
	.logdumpsrv = 0,
	.logdumpcli = 0,
	.delimchar = '@',
