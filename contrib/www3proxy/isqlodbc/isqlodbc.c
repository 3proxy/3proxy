#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#include <io.h>
#include <windows.h>
#endif
#ifdef UNIX
#include <sqltypes.h>
#endif
#include <sql.h>
#include <sqlext.h>



#define  BUF_LENGTH 65000

/* environment variable */
SQLHENV    env=NULL;
SQLHDBC    dbc=NULL;
SQLHSTMT   stmt=NULL;
SQLHSTMT   cstmt=NULL;
unsigned  char *dsn;
unsigned  char *user;
unsigned  char *pass;

RETCODE    retcod;

/*description a columns of result of request */
SQLSMALLINT      ColumnCount;
unsigned int     ColNumber;
unsigned char    ColName[SQL_MAX_COLUMN_NAME_LEN];
unsigned int     Length;
unsigned int     Type;
unsigned int     Size;
unsigned int     Digits;
unsigned int     Nullable;


unsigned char    data_buf[BUF_LENGTH];
unsigned long    OutData;

/* function print error message*/
void PrintError(HENV env,HDBC dbc,HSTMT stmt,RETCODE retcod)
{
 SQLINTEGER nError;
 SQLSMALLINT  TextLength;
 unsigned char    BufErrMsg[SQL_MAX_MESSAGE_LENGTH+1];
 unsigned char    SqlState[128];

 SQLError(env,dbc,stmt,SqlState,&nError,BufErrMsg,512, &TextLength);
 printf("%s\n" ,BufErrMsg);
}

void sqlquery(SQLHDBC dbc,SQLHSTMT stmt, unsigned char *strquery)
{
 retcod=SQLAllocStmt(dbc, &stmt);

 retcod=SQLExecDirect(stmt,strquery,SQL_NTS);
 if(retcod!=SQL_SUCCESS)
   { PrintError(env,dbc,stmt,retcod);}

    SQLNumResultCols(stmt,&ColumnCount);

    while(SQLFetch(stmt)==SQL_SUCCESS)
     {
      for(ColNumber=1; ColNumber<=ColumnCount ; ColNumber++)
       {
        SQLGetData(stmt,ColNumber,SQL_CHAR,data_buf,BUF_LENGTH,&OutData);
        printf("%s|",data_buf);
       }
       printf("\n",data_buf);
       strcpy(data_buf,"");
     }
 SQLFreeStmt( stmt, SQL_DROP );
}

/* isqlodbc dsn[[,user][,pass]] ["SQLCMD"] */
int main(int argc, char *argv[])
{
 unsigned char qbuf[64000];
 unsigned char *ptr=NULL;

 /* Allocate environment and database connection  handles */
 retcod=SQLAllocEnv( &env );
 if(retcod!=SQL_SUCCESS)
  {
   PrintError(env,dbc,stmt,retcod);
   SQLFreeEnv(env);
   return (-1);
  }
 retcod = SQLAllocConnect( env, &dbc );
 if(retcod!=SQL_SUCCESS)
  {
   PrintError(env,dbc,stmt,retcod);
   SQLFreeConnect( dbc );
   return (-1);
  }
 
 
 if(argc > 1 )
 {
  /* parsing command line and get parametrs */
  dsn = strtok(argv[1],",");
  user = strtok(NULL, ",");
  pass = strtok(NULL, ",");

  /* Connect from DSN */
  retcod=SQLConnect(dbc,dsn,SQL_NTS,user,SQL_NTS,pass,SQL_NTS);

  if(retcod!=SQL_SUCCESS)
     { PrintError(env,dbc,stmt,retcod); }
    else
     {
      if (argc > 2)
       {
        /*sql cmd from command line*/
        sqlquery(dbc,stmt,argv[2]);
       }
      else
       {
         /*sql cmd from stdin */
         if( isatty(0) ){ printf(".tables - list table\n.q - exit\nsql>"); }
         while(fgets(qbuf,63000,stdin) != NULL )
         {
          ptr=strrchr(qbuf,';');
          if (ptr!=NULL)
           {
            sqlquery(dbc,stmt,qbuf);
           }
          else
           {
            /*cmd exit*/
            if (strstr(qbuf,".q")){ break; };

            /*cmd table list*/
            if (strstr(qbuf,".tables")) 
             {
              retcod=SQLAllocStmt(dbc, &stmt);
              if(retcod!=SQL_SUCCESS){ PrintError(env,dbc,stmt,retcod); }
              else
               {
                retcod=SQLTables(stmt,NULL,0,NULL,0,NULL,0,NULL,0);
                if(retcod !=SQL_SUCCESS) { PrintError(env,dbc,stmt,retcod);}
                while(SQLFetch(stmt)==SQL_SUCCESS)
                 {
                   SQLGetData(stmt,3,SQL_CHAR,data_buf,BUF_LENGTH,&OutData);
                   printf("%s|",data_buf);

                   /*list columns */
                   retcod=SQLAllocStmt(dbc, &cstmt);
                   retcod=SQLColumns(cstmt,NULL,0,NULL,0,data_buf,strlen(data_buf),NULL,0);

                   if(retcod !=SQL_SUCCESS) { PrintError(env,dbc,stmt,retcod);}
                   else
                   {
                     printf("create table %s (",data_buf);
                     while(SQLFetch(cstmt)==SQL_SUCCESS)
                      {
                       SQLGetData(cstmt,4,SQL_CHAR,data_buf,BUF_LENGTH,&OutData);
                       printf("%s ",data_buf);
                       SQLGetData(cstmt,6,SQL_CHAR,data_buf,BUF_LENGTH,&OutData);
                       printf("%s, ",data_buf);
                      }
                     printf(");\n");
                     SQLFreeStmt( cstmt, SQL_DROP );
                   }/*end list columns*/
               
                 }/*end while SQLFetch */
                SQLFreeStmt( stmt, SQL_DROP );
               }

             }/*end if (strstr(qbuf,".tables")) */


           } /*end else cmd*/
          if( isatty(0) ){ printf("sql>"); }
         } /*end while*/
       }
     }
  SQLDisconnect(dbc);
 } /* if (argc > 2) */
 else
 {
  printf("isqlodbc dsn[[,user][,pass]] [\"SQLCMD\"]\n");
 }

 SQLFreeConnect( dbc );
 SQLFreeEnv( env );
 return 0;
}
