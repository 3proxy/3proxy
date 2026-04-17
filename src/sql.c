#include "proxy.h"
#ifndef NOODBC

SQLHENV  henv = NULL;
SQLHSTMT hstmt = NULL;
SQLHDBC hdbc = NULL;
char * sqlstring = NULL;


void close_sql(){
    if(hstmt) {
	SQLFreeHandle(SQL_HANDLE_STMT, hstmt);
	hstmt = NULL;
    }
    if(hdbc){
	SQLDisconnect(hdbc);
	SQLFreeHandle(SQL_HANDLE_DBC, hdbc);
	hdbc = NULL;
    }
    if(henv) {
	SQLFreeHandle(SQL_HANDLE_ENV, henv);
	henv = NULL;
    }
}

int attempt = 0;
time_t attempt_time = 0;

int init_sql(char * s){
    SQLRETURN  retcode;
    char * datasource;
    char * username;
    char * password;
    char * string;

    if(!s) return 0;
    if(!sqlstring || strcmp(sqlstring, s)){
	string = sqlstring;
	sqlstring=mystrdup(s);
	if(string)myfree(string);
    }

    if(hstmt || hdbc || henv) close_sql();
    attempt++;
    attempt_time = time(0);
    if(!henv){
	retcode = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &henv);
	if (!henv || (retcode != SQL_SUCCESS && retcode != SQL_SUCCESS_WITH_INFO)){
	    henv = NULL;
	    return 0;
	}
	retcode = SQLSetEnvAttr(henv, SQL_ATTR_ODBC_VERSION, (void*)SQL_OV_ODBC3, 0); 

	if (retcode != SQL_SUCCESS && retcode != SQL_SUCCESS_WITH_INFO) {
	    return 0;
	}
    }
    if(!hdbc){
	retcode = SQLAllocHandle(SQL_HANDLE_DBC, henv, &hdbc); 
	if (!hdbc || (retcode != SQL_SUCCESS && retcode != SQL_SUCCESS_WITH_INFO)) {
	    hdbc = NULL;
	    SQLFreeHandle(SQL_HANDLE_ENV, henv);
	    henv = NULL;
	    return 0;
	}
            SQLSetConnectAttr(hdbc, SQL_LOGIN_TIMEOUT, (void*)15, 0);
    }
    string = mystrdup(sqlstring);
    if(!string) return 0;
    datasource = strtok(string, ",");
    username = strtok(NULL, ",");
    password = strtok(NULL, ",");
    

         /* Connect to data source */
        retcode = SQLConnect(hdbc, (SQLCHAR*) datasource, (SQLSMALLINT)strlen(datasource),
                (SQLCHAR*) username, (SQLSMALLINT)((username)?strlen(username):0),
                (SQLCHAR*) password, (SQLSMALLINT)((password)?strlen(password):0));

    myfree(string);
    if (retcode != SQL_SUCCESS && retcode != SQL_SUCCESS_WITH_INFO){
	SQLFreeHandle(SQL_HANDLE_DBC, hdbc);
	hdbc = NULL;
	SQLFreeHandle(SQL_HANDLE_ENV, henv);
	henv = NULL;
	return 0;
    }
        retcode = SQLAllocHandle(SQL_HANDLE_STMT, hdbc, &hstmt); 
        if (retcode != SQL_SUCCESS && retcode != SQL_SUCCESS_WITH_INFO){
	close_sql();
	return 0;
    }
    return 1;
}

void sqlerr (char *buf){
    if(conf.stdlog){
	fprintf(conf.stdlog, "%s\n", buf);
	fflush(conf.stdlog);
    }
    pthread_mutex_unlock(&log_mutex);
}

unsigned char statbuf[8192];

void logsql(struct clientparam * param, const unsigned char *s) {
    SQLRETURN ret;
    int len;


    if(param->nolog) return;
    pthread_mutex_lock(&log_mutex);
    len = dobuf(param, statbuf, s, (unsigned char *)"\'");

    if(attempt > 5){
	time_t t;

	t = time(0);
	if (t - attempt_time < 180){
	    sqlerr((char *)statbuf);
	    return;
	}
    }
    if(!hstmt){
	if(!init_sql(sqlstring)) {
	    sqlerr((char *)statbuf);
	    return;
	}
    }
    if(hstmt){
	ret = SQLExecDirect(hstmt, (SQLCHAR *)statbuf, (SQLINTEGER)len);
	if(ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO){
	    close_sql();
	    if(!init_sql(sqlstring)){
		sqlerr((char *)statbuf);
		return;
	    }
	    if(hstmt) {
		ret = SQLExecDirect(hstmt, (SQLCHAR *)statbuf, (SQLINTEGER)len);
		if(ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO){
		    sqlerr((char *)statbuf);
		    return;
		}
		attempt = 0;
	    }
	}
	attempt = 0;
    }
    pthread_mutex_unlock(&log_mutex);
}

#endif