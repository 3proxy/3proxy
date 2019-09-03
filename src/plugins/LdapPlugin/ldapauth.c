
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#ifndef _WIN32
#include <ctype.h>
#endif

#include "../../structures.h"
#define LDAP_DEPRECATED 1
#include <ldap.h>

int         already_loaded = 0;

static struct auth myalwaysauth;
static struct commands ldap_serv_auth_handler;
static struct commands ldap_access_handler;
static struct commands ldap_sbase_handler;
static struct commands ldap_userenv_handler;
static struct commands ldap_trafgroup_handler;
static struct commands ldap_attrsgroup_handler;
static struct commands ldap_dircount_handler;

static char   *attrs[] = { NULL, NULL};
static char   *ldap_group_attr;
static char   *ldap_access;
static char   *ldap_sbase;
static char   *ldap_serv;
static char   *ldap_user;
static char   *ldap_pass;
static char   *ldap_userenv;
       int     ldap_userenv_size;
static char   *ldap_trafgroup;
static char   *ldap_dircount;
static int     usercaselow = 0;

struct pluginlink * mypluginlink;
struct schedule myschedule;

#ifndef _WIN32
void lower (char *string)
{
 int length, i;
 
 length = strlen(string);
 for (i=0; i<length; i++)
 {
    string[i] = tolower(string[i]);
 }
}
#endif

/* -------------------------------------------------------------------------- */
int savecounters(void)
{
 struct trafcount *tc=mypluginlink->conf->trafcounter;
 struct trafcount *tcd;
 struct counter_record wcounter;  
 FILE *f;
 unsigned char *tmpbuf,pat_file[]="%s%s.lc";


 /* timetoexit !=0 - будем завершаться.*/
 while (tc != NULL) 
  {
    tcd = tc;
    tc = tc->next;
    f=NULL;
    if(strcmp(tcd->comment,"ldapcounters")==0) {
      tmpbuf=malloc(strlen(pat_file)+strlen(ldap_dircount)+strlen(tcd->ace->users->user));
      sprintf(tmpbuf,pat_file,ldap_dircount,tcd->ace->users->user);
      f=fopen(tmpbuf,"w+b");
      fseek(f,0,SEEK_SET);
      fprintf(f,"%"PRINTF_INT64_MODIFIER"u %lu %lu\n",tcd->traf64,
					(unsigned long)tcd->cleared,(unsigned long)tcd->updated);

      fclose(f);
      free(tmpbuf);

     }
  }

 
 /*return 1 delete job , return 0 no delete job*/
 if (mypluginlink->conf->needreload !=0 )
  {
    return (0); 
  }

 return (0); 
}


/* --------------------------------------------------------------------------*/
static int ldapfunc(struct clientparam *param)
 {

  LDAP		*ld = NULL;
  LDAPMessage	*res = NULL; 
  int    rc = -1;
  char   tmpbuf[1024];

  /* test proxy user auth ------------------------*/
  if(!param->username || !param->password) return 4;
  if(strlen(param->password)==0) return 4;
   
  /* init ldap ---------------------- */
  ld = ldap_init( ldap_serv, 389 );
  if ( ld == NULL ) 
   {
    param->srv->logfunc(param,"Error ldap_init: No init lib ldap");
    /*ldap_perror( ld, "Error ldap_init" ); */
    return 7; 
   }

 
  /* this code for Active Directory LDAP catalog :( 
   detail see documentation for plugin  */
  if (usercaselow  > 0)
  #ifdef _WIN32
   { CharLower(param->username); }
  #else
   { lower(param->username);  }
  #endif
  
  
  /* create user for test auth */
  sprintf(tmpbuf,"%.200s=%.200s,%.200s",attrs[0],param->username,ldap_userenv);
  
  rc = ldap_bind_s( ld, tmpbuf, param->password, LDAP_AUTH_SIMPLE );

  
  if ( rc != LDAP_SUCCESS ) 
    {
     param->srv->logfunc(param,"Error ldap_bind: No connect ldap catalog");
     ldap_unbind_s(ld);	
     return 7;
    }
    
  ldap_unbind_s(ld);

  ld = ldap_init( ldap_serv, 389 );

  if ( ld == NULL ) 
   {
    param->srv->logfunc(param,"Error ldap_init: No init lib ldap");
    /*ldap_perror( ld, "Error ldap_init" ); */
    return 7; 
   }

  rc = ldap_bind_s( ld, ldap_user, ldap_pass, LDAP_AUTH_SIMPLE );
 
   if ( rc != LDAP_SUCCESS ) 
    {
     param->srv->logfunc(param, "Error ldap_bind: Not authorize in ldap\
     catalog,  checked option \'ldapconnect\' ");
     ldap_unbind_s(ld);
     return 7;
    }

  /* test enter user in filter ------------------------------
     create filter for search*/
  
  sprintf(tmpbuf,"(&(%.200s=%.200s)(%.200s=%.200s))",attrs[0],param->username,
                                      ldap_group_attr,ldap_access);

  
  /* search */
  rc = ldap_search_s( ld, ldap_sbase, LDAP_SCOPE_SUBTREE,
				tmpbuf, attrs, 0, &res );
    
  rc=ldap_count_entries(ld,res);

  ldap_msgfree(res);
  ldap_unbind_s(ld);
  
  /* user not found */
  if (rc == 0)
    {  return 5;  }

  return 0;
 }

/* --------------------------------------------------------------------------
 handle command ldapserv */
int h_ldapconnect(int argc, unsigned char ** argv)
{
 LDAP		*ld = NULL;
 
 if (argc < 2) 
  {
   fprintf(stderr, "Error in ldapconnect: See documentation of ldapauth plugin.\n");		
   return 1;
  }

 ldap_serv=strdup(argv[1]);
 ldap_user=strdup(argv[2]);  

 ld = ldap_init( ldap_serv, 389 );
 ldap_unbind_s(ld);
 
 if (argc == 4) 
  {
   ldap_pass= strdup(argv[3]);   
   }
 else
  {
   ldap_pass=NULL;
  }
  
 return 0;
}
/* --------------------------------------------------------------------------
 handle command ldapaccess */
int h_access(int argc, unsigned char ** argv)
{
 if (argc < 1) 
  {
   fprintf(stderr, "Error in ldapaccess: See documentation of ldapauth plugin.\n");		
   return 1;
  }
 ldap_access=strdup(argv[1]);
 return 0;
}
/* --------------------------------------------------------------------------
 handle command ldapsbase
 searching base */
int h_sbase(int argc, unsigned char ** argv)
{
 if (argc < 1) 
  {
   fprintf(stderr, "Error in ldapsbase: See documentation of ldapauth plugin.\n");		
   return 1;
  }
  ldap_sbase=strdup(argv[1]);   
 return 0;
}
/* --------------------------------------------------------------------------	
 handle command ldapuserenv */
int h_userenv(int argc, unsigned char ** argv)
{
 if (argc < 1) 
  {
   fprintf(stderr, "Error in ldapsbase: See documentation of ldapauth plugin.\n");		
   return 1;
  }
  ldap_userenv=strdup(argv[1]);   
  return 0;
}
/* --------------------------------------------------------------------------
 handle command ldaptrafgroup */
int h_trafgroup(int argc, unsigned char ** argv)
{
  struct trafcount *newtrafcount;
  struct bandlim *newbandlim;
  static struct ace *newace;
  static struct userlist *newuserlist;
  struct counter_record rcounter;

  LDAP		*ld = NULL;
  LDAPMessage	*res = NULL; 
  LDAPMessage	*msg = NULL;
  BerElement 	*ber = NULL;
  int    rc = -1;
  char   *tmpbuf,pat_file[]="%s%s.lc",pat_group[]="(%s=%s)";
  char   *getattr,**vals,buf[256];
  ROTATION   rtype;
  unsigned long traflimit;
  int bandwidth ;
  
  FILE *f;
 
  if (argc < 3) 
  {
   fprintf(stderr, "Error in ldaptrafgroup: See documentation of ldapauth plugin.\n");		
   return 1;
  }

  ld = ldap_init( ldap_serv, 389 );

  if ( ld == NULL ) 
   {
    fprintf(stderr,"Error in ldaptrafgroup: ldap_init: No init lib ldap");
    return 7; 
   }

  rc = ldap_bind_s( ld, ldap_user, ldap_pass, LDAP_AUTH_SIMPLE );
 
   if ( rc != LDAP_SUCCESS ) 
    {
     fprintf(stderr, "Error in ldaptrafgroup: ldap_bind: Not authorize in ldap\
     catalog,  checked option \'ldapconnect\' ");
     ldap_unbind_s(ld);
     return 7;
    }

  /* type traf limit */
  if(strcmp(argv[2],"MONTHLY")==0||strcmp(argv[2],"monthly")==0)
  {rtype=MONTHLY;}
  
  if(strcmp(argv[2],"DAILY")==0||strcmp(argv[2],"daily")==0)
  {rtype=DAILY;}

  if(strcmp(argv[2],"WEEKLY")==0||strcmp(argv[2],"weekly")==0)
  {rtype=WEEKLY;}
  
  traflimit = atol((char *)argv[3]);
  bandwidth = atoi((char *)argv[4]);

  /* name ldap group */
  tmpbuf=malloc(strlen(pat_group)+strlen(ldap_group_attr)+strlen(argv[1]));
  sprintf(tmpbuf,pat_group,ldap_group_attr,argv[1]);
  rc = ldap_search_s( ld, ldap_sbase, LDAP_SCOPE_SUBTREE,
                                        			tmpbuf, attrs, 0, &res );
  free(tmpbuf);

  rc=ldap_count_entries(ld,res);
 
  /* users found */
  if (rc > 0)
     {
       msg=ldap_first_entry(ld, res);
       getattr=ldap_first_attribute(ld, msg, &ber);
     
       while (rc > 0)
        {
         vals=ldap_get_values(ld, msg, getattr);
         if (vals != NULL && vals[0] != NULL )
           {
             
             /* -------------bandlim----------
             create user list 	    */  
             newuserlist = (*mypluginlink->mallocfunc)(sizeof (struct userlist));
             if (usercaselow  > 0)
                #ifdef _WIN32
                { CharLower(vals[0]); }
                #else
                { lower(vals[0]); }
                #endif

             newuserlist->user = (*mypluginlink->strdupfunc)(vals[0]);
             newuserlist->next = NULL; 
             /*create user rule */
             newace = (*mypluginlink->mallocfunc)(sizeof (struct ace));
             memset(newace, 0, sizeof(struct ace));
             newace->users = newuserlist;
             newace->action = BANDLIM;
             /*create user bandlim */
             newbandlim =(*mypluginlink->mallocfunc)(sizeof (struct bandlim));
             memset(newbandlim, 0, sizeof(struct bandlim));
             newbandlim->rate = bandwidth;
             newbandlim->ace = newace;
             newbandlim->next = mypluginlink->conf->bandlimiter;
             mypluginlink->conf->bandlimiter = newbandlim;
             
             /* -------------counters----------
             create user list */	     
             newuserlist = (*mypluginlink->mallocfunc)(sizeof (struct userlist));
             if (usercaselow  > 0)
                #ifdef _WIN32
                { CharLower(vals[0]); }
                #else
                { lower(vals[0]);  }
                #endif
             newuserlist->user = (*mypluginlink->strdupfunc)(vals[0]);
             newuserlist->next = NULL; 
             /*create user rule */
             newace = (*mypluginlink->mallocfunc)(sizeof (struct ace));
             memset(newace, 0, sizeof(struct ace));
             newace->users = newuserlist;
             newace->action = COUNTIN;
             /*create user counter */
             newtrafcount =(*mypluginlink->mallocfunc)(sizeof (struct trafcount));
             memset(newtrafcount, 0, sizeof(struct trafcount));
             newtrafcount->ace = newace;
             newtrafcount->type=rtype;
             newtrafcount->traflim64  = traflimit;
             newtrafcount->comment=(*mypluginlink->strdupfunc)("ldapcounters");
             newtrafcount->number=0;
             tmpbuf=malloc(strlen(pat_file)+strlen(ldap_dircount)+strlen(vals[0]));
             sprintf(tmpbuf,pat_file,ldap_dircount,vals[0]);
             f=NULL;
             f=fopen(tmpbuf,"rb");
             if(f!=NULL)
              {
		
               fseek(f,0,SEEK_SET);
               fgets(buf, 256, f); 
  	       sscanf(buf,"%"PRINTF_INT64_MODIFIER"u %lu %lu\n",&rcounter.traf64, 
				&rcounter.cleared, &rcounter.updated);


               newtrafcount->traf64=rcounter.traf64;
               newtrafcount->cleared=rcounter.cleared;
               newtrafcount->updated=rcounter.updated;
               fclose(f);
              }
             free(tmpbuf);   

             newtrafcount->next = mypluginlink->conf->trafcounter;
             mypluginlink->conf->trafcounter = newtrafcount;
              
             ldap_value_free(vals);
           }
          msg=ldap_next_entry(ld, msg);
         rc--;
        } 
     
   }/* end if (rc > 0) */
     
  ldap_unbind_s(ld);
   
  return 0;
}
/* --------------------------------------------------------------------------
 handle command ldapattrsgroup */
int h_attrsgroup(int argc, unsigned char ** argv)
{
 if (argc < 1) 
  {
   fprintf(stderr, "Error in ldapattr: See documentation of ldapauth plugin.\n");		
   return 1;
  }
  attrs[0]=strdup(argv[1]);
  ldap_group_attr=strdup(argv[2]);   
 
  if(argc == 4)
   { usercaselow=atoi(argv[3]); }
   
  return 0;
}
/* --------------------------------------------------------------------------
 handle command ldapdircount */
int h_dircount(int argc, unsigned char ** argv)
{
 if (argc < 1) 
  {
   fprintf(stderr, "Error in ldapdircount: See documentation of ldapauth plugin.\n");		
   return 1;
  }
  ldap_dircount=strdup(argv[1]);
  return 0;
}

/*------------------------------- MAIN --------------------------------------
 start plugin init  */

#ifdef WATCOM
#pragma aux start "*" parm caller [ ] value struct float struct routine [eax] modify [eax ecx edx]
#undef PLUGINCALL
#define PLUGINCALL
#endif

PLUGINAPI int PLUGINCALL start(struct pluginlink * pluginlink, 
					 int argc, char** argv)

{
  

 if (already_loaded != 0)
   {
    free(ldap_access);
    free(ldap_sbase);
    free(ldap_serv);
    free(ldap_user);
    free(ldap_pass);
    free(ldap_userenv);
    free(ldap_dircount);
    free(ldap_group_attr);
    free(attrs[0]);
    return (0);
   }

   already_loaded = 1;
    
    mypluginlink=pluginlink;
     
    ldap_access=NULL;
    ldap_sbase=NULL;
    ldap_serv=NULL;
    ldap_user=NULL;
    ldap_pass=NULL;
    ldap_userenv=NULL;
    ldap_trafgroup=NULL;
    ldap_dircount=NULL;
    ldap_group_attr=NULL;

	
   
    myalwaysauth.authenticate = ldapfunc;
    myalwaysauth.authorize = pluginlink->checkACL;
    myalwaysauth.desc = "ldap";
    myalwaysauth.next = pluginlink->authfuncs->next;
    pluginlink->authfuncs->next = &myalwaysauth;

    /* add command: ldapconnect ipserv user_serv pass_serv  */
    ldap_serv_auth_handler.minargs = 3;
    ldap_serv_auth_handler.maxargs = 4;
    ldap_serv_auth_handler.command = "ldapconnect";
    ldap_serv_auth_handler.handler = h_ldapconnect;
    ldap_serv_auth_handler.next = pluginlink->commandhandlers->next;
    pluginlink->commandhandlers->next = &ldap_serv_auth_handler;

    /* add command:  ldapaccess cn=internet,cn=users,dc=domain,dc=ru  */
    ldap_access_handler.minargs = 2;
    ldap_access_handler.maxargs = 2;
    ldap_access_handler.command = "ldapaccess";
    ldap_access_handler.handler = h_access;
    ldap_access_handler.next = pluginlink->commandhandlers->next;
    pluginlink->commandhandlers->next = &ldap_access_handler;

    /* add command: ldapsbase cn=users,dc=domain,dc=ru  */
    ldap_sbase_handler.minargs = 2;
    ldap_sbase_handler.maxargs = 2;
    ldap_sbase_handler.command = "ldapsbase";
    ldap_sbase_handler.handler = h_sbase;
    ldap_sbase_handler.next = pluginlink->commandhandlers->next;
    pluginlink->commandhandlers->next = &ldap_sbase_handler;

    /* add command: ldapuserenv (cn=users,dc=domain,dc=ru)  */
    ldap_userenv_handler.minargs = 2;
    ldap_userenv_handler.maxargs = 2;
    ldap_userenv_handler.command = "ldapuserenv";
    ldap_userenv_handler.handler = h_userenv;
    ldap_userenv_handler.next = pluginlink->commandhandlers->next;
    pluginlink->commandhandlers->next = &ldap_userenv_handler;

    /* add command: ldaptrafgroup cn=traf500,cn=users,dc=domain,dc=ru M 500 333 */
    ldap_trafgroup_handler.minargs = 5;
    ldap_trafgroup_handler.maxargs = 5;
    ldap_trafgroup_handler.command = "ldaptrafgroup";
    ldap_trafgroup_handler.handler = h_trafgroup;
    ldap_trafgroup_handler.next = pluginlink->commandhandlers->next;
    pluginlink->commandhandlers->next = &ldap_trafgroup_handler;

    /* add command: ldapattr cn memberOf usercaselow=1 */
    ldap_attrsgroup_handler.minargs = 3; 
    ldap_attrsgroup_handler.maxargs = 4;
    ldap_attrsgroup_handler.command = "ldapattr";
    ldap_attrsgroup_handler.handler = h_attrsgroup;
    ldap_attrsgroup_handler.next = pluginlink->commandhandlers->next;
    pluginlink->commandhandlers->next = &ldap_attrsgroup_handler;

    /* add command: ldapdircount c:\3proxy\ */
    ldap_dircount_handler.minargs = 2; 
    ldap_dircount_handler.maxargs = 2;
    ldap_dircount_handler.command = "ldapdircount";
    ldap_dircount_handler.handler = h_dircount;
    ldap_dircount_handler.next = pluginlink->commandhandlers->next;
    pluginlink->commandhandlers->next = &ldap_dircount_handler;
         
    /*create job shedule for processing reload, save counters to file */
    memset(&myschedule,0,sizeof(struct schedule)); 
    myschedule.type=MINUTELY;
    myschedule.function=savecounters;
    myschedule.next = *pluginlink->schedule;
    *pluginlink->schedule=&myschedule;
    
    return 0;
}


