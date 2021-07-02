/*
   (c) 2007-2021 by Vladimir Dubrovin <3proxy@3proxy.org>

   please read License Agreement

*/

#include "../../structures.h"
#include <string.h>
#include <ctype.h>

#ifdef  __cplusplus
extern "C" {
#endif

static struct auth alwaysauth;



#ifdef  __cplusplus
extern "C" {
#endif

unsigned char * conv_utf8_to_cp1251(unsigned char *s){
	int i, j=0, n=(int)strlen((char *)s);
	int byte2 = 0;
	int c1, new_c1, new_c2, new_i;
	for(i = 0; i < n; i++){
		if(byte2 && s[i]>=128 && s[i]<=192){
			new_c2=(c1&3)*64+(s[i]&63);
			new_c1=(c1>>2)&5;
			new_i=(new_c1*256)+new_c2;
			if(new_i == 1025) s[j++] = 168;
			else if (new_i==1105) s[j++] = 184;
			else if (new_i < (192 + 848) || new_i > (255 + 848)){
				return s;
			}
			else s[j++] = new_i - 848;
			byte2 = 0;
		}
		else if(byte2){
			return s;
		}
		else if((s[i]>>5)==6){
			c1 = s[i];
			byte2 = 1;
		}
		else if(s[i] < 128) s[j++] = s[i];
		else return s;
	}
	s[j] = 0;
	return s;
}


 static int aufunc(struct clientparam *param){
	if(!param->username || !param->password || param->pwtype != 0) return 4;
	conv_utf8_to_cp1251(param->username);
	conv_utf8_to_cp1251(param->password);
	return 4;
 }


#ifdef WATCOM
#pragma aux utf8tocp1251 "*" parm caller [ ] value struct float struct routine [eax] modify [eax ecx edx]
#undef PLUGINCALL
#define PLUGINCALL
#endif

PLUGINAPI int PLUGINCALL utf8tocp1251(struct pluginlink * pluginlink, int argc, char** argv){
	static int loaded = 0;


	if(!loaded){
		alwaysauth.authenticate = aufunc;
		alwaysauth.authorize = pluginlink->checkACL;
		alwaysauth.desc = "utf8tocp1251";
		alwaysauth.next = pluginlink->authfuncs->next;
		pluginlink->authfuncs->next = &alwaysauth;
		loaded = 1;
	}
	return 0;
}


#ifdef  __cplusplus
}
#endif

