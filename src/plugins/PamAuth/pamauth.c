/* plugin for 3proxy with PAM auth only for *NIX (linux,*bsd)
Kirill Lopuchov <lopuchov@mail.ru>

   Compile with: gcc -shared -o pamauth.so pamauth.c -lpam  -DNOODBC
*/

#include "../../structures.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <security/pam_appl.h>


pthread_mutex_t pam_mutex;

static int         already_loaded = 0;

static struct auth pamauth;
#ifdef USERCASE
static int     usercaselow = 0;
#endif
static unsigned char *service=NULL;
static struct pluginlink * pl;



					
static char *password = NULL;


static int password_conversation ( int num_msg,  const struct pam_message **msg, 
					struct pam_response **resp, 
					 void *appdata_ptr)
  {
   if (num_msg != 1 || msg[0]->msg_style != PAM_PROMPT_ECHO_OFF)
    {
     return PAM_CONV_ERR;
    }
   if (!appdata_ptr) appdata_ptr = password;
    if (!appdata_ptr)
     {
      return PAM_CONV_ERR;
     }
     *resp = calloc (num_msg, sizeof (struct pam_response));
   if (!*resp)
    {
     return PAM_CONV_ERR;
    }
    (*resp)[0].resp = strdup ((char *) appdata_ptr);
    (*resp)[0].resp_retcode = 0;
    return ((*resp)[0].resp ? PAM_SUCCESS : PAM_CONV_ERR);
  }

#ifdef USERCASE
static void lower (char *string)
{
 int length, i;
 
 length = strlen(string);
 for (i=0; i<length; i++)
 {
    string[i] = tolower(string[i]);
 }
}
#endif


/* --------------------------------------------------------------------------*/
static int pamfunc(struct clientparam *param)
 {
  pam_handle_t *pamh = NULL;
  int retval;
  int rc=0;

  struct pam_conv conv = {
        &password_conversation,
        NULL };

  /* test proxy user auth ------------------------*/
  if(!param->username || !param->password) return 4;
  /*if(strlen(param->password)==0) return 4;*/

  #ifdef USERCASE
   if (usercaselow > 0) 
   { lower(param->username);  }
  #endif

  /*start process auth */  
  conv.appdata_ptr = (char *) param->password;

  pthread_mutex_lock(&pam_mutex);
  if (!pamh)
    {
	retval = pam_start ((char *)service, "3proxy@" , &conv, &pamh);
    }
   if (retval == PAM_SUCCESS)
       retval = pam_set_item (pamh, PAM_USER, param->username); 
/*fprintf(stderr,"pam_set_item1 rc=%d\n",retval);*/
   if (retval == PAM_SUCCESS)
       retval = pam_set_item (pamh, PAM_CONV, &conv); 
/*fprintf(stderr,"pam_set_item2 rc=%d\n",retval); */       
   if (retval == PAM_SUCCESS)
         retval = pam_authenticate (pamh, 0);  
/*fprintf(stderr,"pam_authenticate rc=%d\n",retval);*/
   
   if (retval == PAM_SUCCESS) {  /*auth OK*/  rc=0;   }
   else  { /*auth ERR*/  rc=5;     }

   if (pamh)
      retval = pam_end (pamh, retval);
   if (retval != PAM_SUCCESS)
      {  pamh = NULL;   }
  pthread_mutex_unlock(&pam_mutex);

  return rc;

}

#ifdef WATCOM
#pragma aux start "*" parm caller [ ] value struct float struct routine [eax] modify [eax ecx edx]
#undef PLUGINCALL
#define PLUGINCALL
#endif

/*------------------------------- MAIN --------------------------------------
 start plugin init  */
PLUGINAPI int PLUGINCALL start(struct pluginlink * pluginlink, int argc, unsigned char** argv)
{
  
  
 if(argc < 2) return 1;
 pl = pluginlink;
 if(service) free(service);
 service=strdup((char *)argv[1]); 

 if (already_loaded) { return (0); }

 already_loaded = 1;
    
 pthread_mutex_init(&pam_mutex, NULL);
 pamauth.authenticate = pamfunc;
 pamauth.authorize = pluginlink->checkACL;
 pamauth.desc = "pam";
 pamauth.next = pluginlink->authfuncs->next;
 pluginlink->authfuncs->next = &pamauth;
  
 return 0;
}
