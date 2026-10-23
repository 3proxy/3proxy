#include "proxy.h"
#ifdef WITH_ODBC

/* ODBC drivers require noticeably more stack than the file logger */
#define LOGSTACKSIZE 32768

struct logodbc {
    SQLHENV  henv;
    SQLHDBC hdbc;
    SQLHSTMT hstmt;
};

static void odbcdisconnect(struct logodbc *d){
    if(d->hstmt) {
	SQLFreeHandle(SQL_HANDLE_STMT, d->hstmt);
	d->hstmt = NULL;
    }
    if(d->hdbc){
	SQLDisconnect(d->hdbc);
	SQLFreeHandle(SQL_HANDLE_DBC, d->hdbc);
	d->hdbc = NULL;
    }
    if(d->henv) {
	SQLFreeHandle(SQL_HANDLE_ENV, d->henv);
	d->henv = NULL;
    }
}

/* The log string is &DATASOURCE,USERNAME,PASSWORD. The data source
   alone names the log; user and password are its parameters, the
   password being whatever follows the comma after the user. */
static int odbcconnect(struct logger *lg){
    struct logodbc *d = (struct logodbc *)lg->data;
    SQLRETURN  retcode;
    char * datasource;
    char * username = NULL;
    char * password = NULL;
    char * string = NULL;
    size_t slen = 0;

    if(d->hstmt || d->hdbc || d->henv) odbcdisconnect(d);
    if(!d->henv){
	retcode = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &d->henv);
	if (!d->henv || (retcode != SQL_SUCCESS && retcode != SQL_SUCCESS_WITH_INFO)){
	    d->henv = NULL;
	    return 0;
	}
	retcode = SQLSetEnvAttr(d->henv, SQL_ATTR_ODBC_VERSION, (void*)SQL_OV_ODBC3, 0); 

	if (retcode != SQL_SUCCESS && retcode != SQL_SUCCESS_WITH_INFO) {
	    return 0;
	}
    }
    if(!d->hdbc){
	retcode = SQLAllocHandle(SQL_HANDLE_DBC, d->henv, &d->hdbc); 
	if (!d->hdbc || (retcode != SQL_SUCCESS && retcode != SQL_SUCCESS_WITH_INFO)) {
	    d->hdbc = NULL;
	    SQLFreeHandle(SQL_HANDLE_ENV, d->henv);
	    d->henv = NULL;
	    return 0;
	}
            SQLSetConnectAttr(d->hdbc, SQL_LOGIN_TIMEOUT, (void*)15, 0);
    }
    datasource = (char *)lg->selector + 1;
    if(lg->params){
	if(!(string = strdup((char *)lg->params))) return 0;
	slen = strlen(string);
	username = string;
	if((password = strchr(string, ','))) *password++ = 0;
    }

         /* Connect to data source */
        retcode = SQLConnect(d->hdbc, (SQLCHAR*) datasource, (SQLSMALLINT)strlen(datasource),
                (SQLCHAR*) username, (SQLSMALLINT)((username)?strlen(username):0),
                (SQLCHAR*) password, (SQLSMALLINT)((password)?strlen(password):0));

    if(string) {
	/* no copy of the password left behind */
	memset(string, 0, slen);
	free(string);
    }
    if (retcode != SQL_SUCCESS && retcode != SQL_SUCCESS_WITH_INFO){
	SQLFreeHandle(SQL_HANDLE_DBC, d->hdbc);
	d->hdbc = NULL;
	SQLFreeHandle(SQL_HANDLE_ENV, d->henv);
	d->henv = NULL;
	return 0;
    }
        retcode = SQLAllocHandle(SQL_HANDLE_STMT, d->hdbc, &d->hstmt); 
        if (retcode != SQL_SUCCESS && retcode != SQL_SUCCESS_WITH_INFO){
	odbcdisconnect(d);
	return 0;
    }
    return 1;
}

static int odbcmatch(const unsigned char *selector){
    return *selector == '&';
}

/* A data source down is not an error of the configuration: the log
   connects again later. */
static int odbcinit(struct logger *lg){
    if(!lg->data && !(lg->data = calloc(1, sizeof(struct logodbc)))) return 21;
    return odbcconnect(lg)? 0 : -1;
}

static int odbcformat(struct logger *lg, struct clientparam *param, const unsigned char *s, unsigned char *buf){
    return logbuf(param, buf, s, (unsigned char *)"\'");
}

static int odbcwrite(struct logger *lg, struct clientparam *param, const unsigned char *buf, int len){
    struct logodbc *d = (struct logodbc *)lg->data;
    SQLRETURN ret;

    if(!d || !d->hstmt) return 1;
    ret = SQLExecDirect(d->hstmt, (SQLCHAR *)buf, (SQLINTEGER)len);
    if(ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO){
	/* the connection may be gone: once more on a new one */
	if(!odbcconnect(lg)) return 1;
	ret = SQLExecDirect(d->hstmt, (SQLCHAR *)buf, (SQLINTEGER)len);
	if(ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) return 1;
    }
    return 0;
}

static void odbcclose(struct logger *lg){
    if(!lg->data) return;
    odbcdisconnect((struct logodbc *)lg->data);
    free(lg->data);
    lg->data = NULL;
}

const struct logtype logtype_odbc = {
    "odbc", odbcmatch, odbcinit, odbcformat, odbcwrite, odbcclose, NULL, LOGSTACKSIZE, 0, 0, 1
};

#endif
