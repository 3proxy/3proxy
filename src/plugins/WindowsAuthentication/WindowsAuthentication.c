/*
   (c) 2007-2021 by Vladimir Dubrovin <3proxy@3proxy.org>

   please read License Agreement

*/

#include "../../structures.h"
#include <string.h>
#include <ctype.h>
#include <locale.h>

#ifdef  __cplusplus
extern "C" {
#endif

static struct auth alwaysauth;

static char sidbuf[4096];
static PSID psid = (PSID)sidbuf;

#ifdef  __cplusplus
extern "C" {
#endif

 static int windowsfunc(struct clientparam *param){
	char *dom;
	HANDLE h;
	DWORD dw, sidlen, i;
	char tokenbuf[4096];
	PTOKEN_GROUPS ptg = (PTOKEN_GROUPS)tokenbuf;


	if(!param->username || !param->password || param->pwtype != 0) return 4;
	dom = strchr((char *)param->username, '\\');
	if(dom)*dom++=0;
	if(!LogonUser(	dom?dom:(char *)param->username,
					dom?(char *)param->username:NULL,
					(char *)param->password,
					LOGON32_LOGON_NETWORK,
					LOGON32_PROVIDER_DEFAULT,
					&h))return 5;

	if(dom)*(dom-1)='\\';
	if(!GetTokenInformation(h, TokenGroups, ptg, sizeof(tokenbuf), &dw)) return 6;
	CloseHandle(h);
	sidlen = GetLengthSid(psid);
	for(i=0; i < ptg->GroupCount; i++){
		if(GetLengthSid(ptg->Groups[i].Sid)==sidlen){
			if(!memcmp((void *)ptg->Groups[i].Sid, (void *)psid, sidlen)) {
				setlocale(LC_CTYPE, ".ACP");
				_strlwr((char *)param->username);
				return 0;
			}
		}
	}
	return 7;
 }

#ifdef WATCOM
#pragma aux WindowsAuthentication "*" parm caller [ ] value struct float struct routine [eax] modify [eax ecx edx]
#undef PLUGINCALL
#define PLUGINCALL
#endif

PLUGINAPI int PLUGINCALL WindowsAuthentication(struct pluginlink * pluginlink, int argc, char** argv){
	char tmpbuf[4096];
	DWORD dlen, sidlen;
	SID_NAME_USE snu;
	static int loaded = 0;


	if(argc != 2) return 11;
	dlen = sizeof(tmpbuf)/sizeof(TCHAR);
	sidlen = sizeof(sidbuf);
	if(!LookupAccountName(NULL, argv[1], psid, &sidlen,
		(LPTSTR) tmpbuf, &dlen, &snu)) return 100000 + (int)GetLastError();
	if(snu != SidTypeGroup && snu != SidTypeAlias && snu != SidTypeWellKnownGroup) return 12;
	if(!loaded){
		alwaysauth.authenticate = windowsfunc;
		alwaysauth.authorize = pluginlink->checkACL;
		alwaysauth.desc = "windows";
		alwaysauth.next = pluginlink->authfuncs->next;
		pluginlink->authfuncs->next = &alwaysauth;
		loaded = 1;
	}
	return 0;
}

#ifdef  __cplusplus
}
#endif

