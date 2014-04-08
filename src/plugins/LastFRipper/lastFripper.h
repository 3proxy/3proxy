//
// released as a public domain
//             std.denis, 2009
//
/*
 #include "direct.h"
*/

#ifdef _WIN32
#define strcasecmp stricmp
#define strncasecmp strnicmp
#else
#define closesocket close
extern pthread_attr_t pa;
#endif

#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif


typedef enum {
	LFM_NONE,
	LFM_PLAYLIST, // GET http://ws.audioscrobbler.com/radio/adjust.php(...)
	LFM_REDIR,    // GET http://play.last.fm/user/(...)
	LFM_GET
} LFM_CLASS;

struct playlist_item {
	struct playlist_item* next;

	char* artist;
	char* title;
	char* album;
	char* url;
	int   url_len;
};

#define TOKEN_MAXLEN 1024
struct xml_state {
	int state;
	int closing;
	char sep;

	int level;
	char tree[128]; // 128 levels nesting

	int n_token;
	char p_token[TOKEN_MAXLEN];

	struct playlist_item* p_item;
};

struct lfm_filter_data {
	pthread_mutex_t mutex;
	struct playlist_item* playlist;
	int refs;
};
struct lfm_client_data {
	struct lfm_filter_data* p_data;

	int req_type;
	struct xml_state* pl_xml;
	struct playlist_item* pl_item;
	FILE* fp;
};
