/*
 released as a public domain
             std.denis, 2009
*/
#include "../../structures.h"
#include "lastFripper.h"

#define strdup _strdup
#define strnicmp _strnicmp
#define ltoa _ltoa

#define mkdir _mkdir

#define PART_SUFFIX "_partial"

void my_mkdir( char* name )
{
	char* pdir = name;
	
	while( 1 ) {
		char ch;
		char* pnext = pdir;
		while( *pnext && *pnext != '\\' && *pnext != '/' )
			pnext++;
		if( *pnext == 0 )
			break;

		ch = *pnext;
		*pnext = 0;
		mkdir( name );
		*pnext = ch;

		pdir = pnext + 1;
	}
	mkdir( name );
}


__inline void myOutputDebugStringA1( char* str )
{
/*	char fname[128];
	ltoa( GetCurrentThreadId(), fname, 10 );
	FILE* fp = fopen( fname, "ab" );
	fputs( str, fp );
	fputs( "\r\n", fp );
	fflush( fp );
	fclose( fp ); 
*/
}

__inline void myOutputDebugStringA( void* buf, int len )
{
/*	char fname[128];
	ltoa( GetCurrentThreadId(), fname, 10 );
	FILE* fp = fopen( fname, "ab" );
	fwrite( buf, len, 1, fp );
	fputs( "\r\n", fp );
	fflush( fp );
	fclose( fp ); */
}

#ifndef isnumber
#define isnumber(i_n_arg) ((i_n_arg>='0')&&(i_n_arg<='9'))
#endif

#define sizearr(x) (sizeof(x)/sizeof(x[0]))
#define xmalloc( type, len )  ((type*)malloc( (len) * sizeof(type) ) )
#define xcalloc( type, len )  ((type*)calloc( (len), sizeof(type) ) )

int clean_filename( char* filename )
{
	int i;
	for( i = 0; filename[i]; i++ )
		switch( filename[i] ) {
		case '*':
		case '?':
		case '<':
		case '>':
		case '\\':
		case '/':
		case ':':
		case '"':
			filename[i] = '_';
		break;
	}
	return i;
}


static struct pluginlink * pl;
static int lfm_loaded = 0;
static char* g_folder = 0;
static char* g_format = 0;

static int lfm_format_filename( struct playlist_item* p_item, char* p_filename, int n_filename )
{
	int i = 0, j;
	char ch;
	char* fmt;
	char *ff = NULL;

	if( g_folder && *g_folder ) {
		strncpy( p_filename, g_folder, n_filename );
		i = strlen( p_filename );
		if( i < n_filename-1 && p_filename[i-1] != '\\' )
			p_filename[i++] = '\\';
	}
	
	fmt = g_format;
	if( fmt == NULL ) fmt = "%a\\%t.mp3";
	while( ( ch = *fmt++ ) != 0 ) {
		if( ch == '%' ) {
			char* p_sz = NULL;
			char  a_sz[32];
			ch = *fmt++;
			switch( ch ) {
			case 0:
				fmt--; break;
			case '%':
				p_sz = "%";
				break;
			case 'n': {
				static unsigned ndx = 0;
				ltoa( ndx++, a_sz, 10 );
				p_sz = a_sz;
				break;
			}
			case 'a':
				p_sz = p_item->artist;
				break;				
			case 't':
				p_sz = p_item->title;
				break;				
			case 'l':
				p_sz = p_item->album;
				break;
			}
			if( p_sz ) {
				strncpy( p_filename+i, p_sz, n_filename-i );
				p_filename[n_filename-1] = 0;
				i += clean_filename( p_filename+i );
			}
		} else
			if( i < n_filename ) p_filename[i++] = ch;
	}
	
	for( j = i-1; j >= 0; j-- )
		if( p_filename[j] == '\\' || p_filename[j] == '/' ) {
			ff = p_filename + j;
			break;
		}
	if( ff ) {
		char ch = *ff;
		*ff = 0;
		my_mkdir( p_filename );
		*ff = ch;
	}

	return i;
}

static void lfm_close_request( struct lfm_client_data* p_client )
{
	struct lfm_filter_data* p_data;
	if( p_client == NULL ) return;
	p_data = p_client->p_data;
	if( p_data == NULL ) return;

	if( p_client->req_type == LFM_PLAYLIST ) {
		free( p_client->pl_xml );
	} else if( p_client->req_type == LFM_GET && p_client->fp ) {
		struct playlist_item* p_item = p_client->pl_item;
		if( p_item ) {
			char id3v1[128];
			memset( id3v1, 0, 128 );
			strcpy( id3v1, "TAG" );
			strncpy( id3v1+3, p_item->title, 30 );
			strncpy( id3v1+33, p_item->artist, 30 );
			strncpy( id3v1+63, p_item->album, 30 );
			id3v1[127] = -1;
			fwrite( id3v1, 128, 1, p_client->fp );
		}
		fclose( p_client->fp );
/*
		if( p_item ) {
			char filename_part[512], filename[512];
			int i = lfm_format_filename( p_item, filename_part, sizearr(filename_part) );
			memcpy( filename, filename_part, sizeof(filename) );
			strncpy( filename_part+i, PART_SUFFIX, sizearr(filename_part)-i );
			rename( filename_part, filename );
		}
*/
		pthread_mutex_lock( &p_data->mutex );
		if( p_data->playlist != NULL && p_item != NULL ) {
			if( p_data->playlist == p_item )
				p_data->playlist = p_item->next;
			else {
				struct playlist_item *p_last = p_data->playlist;

				while( p_last->next != NULL && p_last->next != p_item )
					p_last = p_last->next;

				if( p_last->next )
					p_last->next = p_item->next;
			}
			if( p_item->artist ) free( p_item->artist );
			if( p_item->title ) free( p_item->title );
			if( p_item->album ) free( p_item->album );
			if( p_item->url ) free( p_item->url );
			free( p_item );
		}
		pthread_mutex_unlock( &p_data->mutex );
	}
	p_client->req_type = LFM_NONE;
}

static void* lfm_filter_open( void * idata, struct srvparam * param ){
	struct lfm_filter_data* pdata = (struct lfm_filter_data*)idata;
	if( pdata ){
		pthread_mutex_lock( &pdata->mutex );
		pdata->refs++;
		pthread_mutex_unlock( &pdata->mutex );
	} else {
		if( ( pdata = xcalloc( struct lfm_filter_data, 1 ) ) != NULL ) {
			pthread_mutex_init( &pdata->mutex, NULL );
			pdata->playlist = NULL;
			pdata->refs++;
		}
	}
	return pdata;
}

static FILTER_ACTION lfm_filter_client( void *fo, struct clientparam* param, void** fc )
{
	struct lfm_filter_data* p_data;
	struct lfm_client_data* p_client;
	*fc = NULL;
	if( fo == NULL ) return PASS;

	p_data = (struct lfm_filter_data*)fo;
	p_client = xcalloc( struct lfm_client_data, 1 );
	if( p_client == NULL ) return PASS;

	p_client->p_data = p_data;
	p_client->req_type = LFM_NONE;
	
	*fc = p_client;
	return CONTINUE;
}

static void lfm_filter_clear( void *fc )
{
	struct lfm_client_data* p_client;

	p_client = (struct lfm_client_data*)fc;
	if( p_client == NULL ) return;
	
	lfm_close_request( p_client );

	free( p_client );
}

static void lfm_filter_close(void *fo){
	struct lfm_filter_data* p_data;
	struct playlist_item* p_item;

	p_data = (struct lfm_filter_data*)fo;
	if( p_data == NULL ) return;

	if( --p_data->refs > 0 ) return;

	pthread_mutex_destroy( &p_data->mutex );
	p_item = p_data->playlist;
	while( p_item ) {
		struct playlist_item* p_old = p_item;
		p_item = p_item->next;

		if( p_old->artist ) free( p_old->artist );
		if( p_old->title ) free( p_old->title );
		if( p_old->album ) free( p_old->album );
		if( p_old->url ) free( p_old->url );
		free( p_old );
	}

	free( p_data );
}

static FILTER_ACTION lfm_filter_request( void *fc, struct clientparam *param, unsigned char** buf_p, int* bufsize_p, int offset, int* length_p )
{
	char* p_buf = (char*)( *buf_p + offset );
	int n_buf = *length_p - offset;
	struct lfm_client_data* p_client;
	struct lfm_filter_data* p_data;

	if( p_buf == NULL || n_buf < 5 ) return CONTINUE;

	p_client = (struct lfm_client_data*)fc;
	if( p_client == NULL ) return CONTINUE;
	p_data = p_client->p_data;
	if( p_data == NULL ) return CONTINUE;

	pl->conf->filtermaxsize = 0;

	lfm_close_request( p_client );

	p_client->req_type = LFM_NONE;
	p_client->fp = NULL;
	
	if( strncasecmp( p_buf, "GET ", 4 ) != 0 ) return CONTINUE;
	
	p_buf += 4;

	if( strncasecmp( p_buf, "http://ws.audioscrobbler.com/radio/xspf.php?", 44 ) == 0 ) {
		myOutputDebugStringA1( "getting a playlist" );
		p_client->req_type = LFM_PLAYLIST;
	} else {
		char zzz[256];
		int i;
		struct playlist_item* p_item;
		for( i = 0; i < n_buf && i < 256; i++ ) {
			if( p_buf[i] == '\r' ) break;
			zzz[i] = p_buf[i];
		}
		zzz[i] = 0;
		myOutputDebugStringA1( zzz );
		pthread_mutex_lock( &p_data->mutex );
		p_item = p_data->playlist;
		while( p_item ) {
			if( strncasecmp( p_buf, p_item->url, p_item->url_len ) == 0 )
				break;
			p_item = p_item->next;
		}
		pthread_mutex_unlock( &p_data->mutex );
		if( p_item ) {
			myOutputDebugStringA1( "getting a known url: " );
			myOutputDebugStringA1( p_item->title );
			p_client->req_type = LFM_GET;
			p_client->pl_item = p_item;
		}
	}

	return CONTINUE;
}

static FILTER_ACTION lfm_filter_header_srv( void *fc, struct clientparam *param, unsigned char** buf_p, int* bufsize_p, int offset, int* length_p )
{
	char* p_buf = (char*)( *buf_p + offset );
	struct lfm_client_data* p_client;
	int n_buf = *length_p - offset;
	struct lfm_filter_data* p_data;
	char zzz[100];
	int code;

	if( p_buf == NULL || n_buf < 9 ) return CONTINUE;

	p_client = (struct lfm_client_data*)fc;
	if( p_client == NULL ) return CONTINUE;
	p_data = p_client->p_data;
	if( p_data == NULL ) return CONTINUE;

	code = atoi( p_buf + 9 );
	sprintf( zzz, "http code: %d", code );
	myOutputDebugStringA1( zzz );
	myOutputDebugStringA( p_buf, n_buf );
	if( p_client->req_type == LFM_GET && ( code > 300 && code < 304 || code == 307 ) ) {
		p_client->req_type = LFM_REDIR;
		do {
			char* p_line = p_buf;
			int n_line;

			for(; n_buf > 0 && *p_buf != '\r'; p_buf++, n_buf-- ) {};
			n_line = p_buf - p_line;
			if( n_line <= 0 ) break;
			if( n_line > 10 && strncasecmp( p_line, "location: ", 10 ) == 0 ) {
				myOutputDebugStringA1( "redir/location: " );
				myOutputDebugStringA( p_line + 10, n_line - 10 );
				if( p_client->pl_item ) {
					char* p_url = p_line + 10;
					int n_url = n_line - 10;
					pthread_mutex_lock( &p_data->mutex );
					if( p_client->pl_item->url ) free( p_client->pl_item->url );
					p_client->pl_item->url = xmalloc( char, n_url + 1 + 1 );
					memcpy( p_client->pl_item->url, p_url, n_url );
					p_client->pl_item->url[n_url] = ' ';
					p_client->pl_item->url[n_url+1] = 0;
					p_client->pl_item->url_len = n_url + 1;
					myOutputDebugStringA1( "got a url: " );
					myOutputDebugStringA1( p_client->pl_item->url );
					pthread_mutex_unlock( &p_data->mutex );
				}
				p_client->req_type = LFM_NONE;
			}
			for(; n_buf > 0 && ( *p_buf == '\n' || *p_buf == '\r' ); p_buf++, n_buf-- ) {};
		} while( n_buf > 0 );
	}

	if( code == 200 && p_client->req_type == LFM_GET ) {
		struct playlist_item* p_item = p_client->pl_item;
		char filename[512];
		int i = lfm_format_filename( p_item, filename, sizearr(filename) );
		/*
			strncpy( filename + i, PART_SUFFIX, sizearr(filename)-i );
		*/
		p_client->fp = fopen( filename, "wb" );
	}
	else if( code == 200 && p_client->req_type == LFM_PLAYLIST ) {
		p_client->pl_xml = xcalloc( struct xml_state, 1 );
	}

	return CONTINUE;
}

void playlist_analyze( struct lfm_client_data* p_client, const char* p_buf, int len );
static FILTER_ACTION lfm_filter_data_srv( void *fc, struct clientparam *param, unsigned char** buf_p, int* bufsize_p, int offset, int* length_p )
{
	char* p_buf = (char*)( *buf_p + offset );
	int n_buf = *length_p - offset;
	struct lfm_client_data* p_client;
	struct lfm_filter_data* p_data;


	myOutputDebugStringA1( "filter_data_srv" );
	myOutputDebugStringA( p_buf, n_buf );

	if( p_buf == NULL || n_buf < 1 ) return CONTINUE;

	p_client = (struct lfm_client_data*)fc;
	if( p_client == NULL ) return CONTINUE;
	p_data = p_client->p_data;
	if( p_data == NULL ) return CONTINUE;

	if( p_client->req_type == LFM_PLAYLIST )
		myOutputDebugStringA1( "filter_data_srv: playlist" );
	else if( p_client->req_type == LFM_GET ) {
		myOutputDebugStringA1( "filter_data_srv: retrieving" );
		if( p_client->fp == NULL )
			myOutputDebugStringA1( "but no file allocated" );
	}

	if( p_client->req_type == LFM_PLAYLIST )
		playlist_analyze( p_client, p_buf, n_buf );
	if( p_client->fp )
		fwrite( p_buf, n_buf, 1, p_client->fp );

	return CONTINUE;
}

enum XmlState
{
	XML_TEXT,
	XML_TAGNAME,
	XML_ATTRNAME_W,
	XML_ATTRNAME,
	XML_ATTRVALUE_W,
	XML_ATTRVALUE,
	XML_TAGCLOSE,
	XML_TAGOPENCLOSE,
};

int xml_get_token_id( char** table, char* token )
{
	int i;
	char* psz;
	for( psz = token; *psz; psz++ )
		*psz = tolower( *psz );
	for( i = 0; *table; i++, table++ )
		if( strcmp( *table, token ) == 0 ) return i;

	return -1;
}

enum {
	XT_PLAYLIST,
	XT_TRACK_LIST,
	XT_TRACK,
	XT_LOCATION,
	XT_CREATOR,
	XT_ALBUM,
	XT_TITLE
};

char* xt_list[] = {
	"playlist",
	"tracklist",
	"track",
	"location",
	"creator",
	"album",
	"title",
	NULL
};

void playlist_analyze( struct lfm_client_data* p_client, const char* p_buf, int len )
{
	struct xml_state* xs = p_client->pl_xml;
	int n_buf = len;

	if( xs == NULL ) return;

	while( n_buf > 0 ) {
		enum {
			XMS_NONE,
			XMS_TAG,
			XMS_ATTR_NAME,
			XMS_ATTR_VALUE,
			XMS_TEXT
		} gotta = XMS_NONE;
		char ch = *p_buf++;
		n_buf--;
lbl_retry:
		switch( xs->state ) {
		case XML_TAGNAME:
			if( ch == '>' ) {
				xs->state = XML_TEXT;
				gotta = XMS_TAG;
				break;
			} else if( ch == '/' ) {
				if( xs->n_token == 0 )
					xs->closing = 1;
				else {
					xs->state = XML_ATTRNAME_W;
					gotta = XMS_TAG;
					xs->n_token--;
				}
				break;
			} else if( isspace( ch ) ) {
				xs->state = XML_ATTRNAME_W;
				gotta = XMS_TAG;
				break;
			}
			if( xs->n_token < TOKEN_MAXLEN ) xs->p_token[xs->n_token++] = ch;
			break;
		case XML_ATTRNAME_W:
			if( ch == '>' ) {
				xs->state = XML_TEXT;
				break;
			} else if( ch == '/' ) {
				xs->closing = 1;
				xs->state = XML_TEXT;
				gotta = XMS_TAG;
				break;
			} else if( !isspace( ch ) ) {
				xs->state = XML_ATTRNAME;
				goto lbl_retry;
			}
			break;
		case XML_ATTRNAME:
			if( ch == '=' ) {
				xs->state = XML_ATTRVALUE_W;
				gotta = XMS_ATTR_NAME;
				break;
			}
			if( xs->n_token < TOKEN_MAXLEN ) xs->p_token[xs->n_token++] = ch;
			break;
		case XML_ATTRVALUE_W:
			if( ch == '"' || ch == '\'' ) {
				xs->sep = ch;
				xs->state = XML_ATTRVALUE;
				break;
			}
			break;
		case XML_ATTRVALUE:
			if( ch == xs->sep ) {
				xs->state = XML_ATTRNAME_W;
				gotta = XMS_ATTR_VALUE;
				break;
			}
			if( xs->n_token < TOKEN_MAXLEN ) xs->p_token[xs->n_token++] = ch;
			break;
		case XML_TEXT:
			if( ch == '<' ) {
				xs->state = XML_TAGNAME;
				gotta = XMS_TEXT;
				break;
			}
			if( xs->n_token < TOKEN_MAXLEN ) xs->p_token[xs->n_token++] = ch;
			break;
		}

		if( gotta != XMS_NONE ) {
			xs->p_token[xs->n_token] = 0;

			switch( gotta ) {
			case XMS_TAG: {
				int id = xml_get_token_id( xt_list, xs->p_token );
				if( !xs->closing ) {
					if( xs->level < sizeof(xs->tree) ) xs->tree[xs->level] = id;
					xs->level++;

					if( id == XT_TRACK && xs->level == 3 && xs->tree[1] == XT_TRACK_LIST )
						xs->p_item = xcalloc( struct playlist_item, 1 );
				} else {
					if( xs->level > 0 ) xs->level--;
					if( id == XT_TRACK && xs->level == 2 && xs->tree[1] == XT_TRACK_LIST ) {
						char zzz[1024];
						_snprintf( zzz, 1024, "artist: <%s>, title: <%s>, url: <%s>",
						           xs->p_item->artist, xs->p_item->title, xs->p_item->url );
						myOutputDebugStringA1( zzz );
						pthread_mutex_lock( &p_client->p_data->mutex );
						xs->p_item->next = p_client->p_data->playlist;
						p_client->p_data->playlist = xs->p_item;
						pthread_mutex_unlock( &p_client->p_data->mutex );
					}
					xs->closing = 0;
				}

				break;
			}
			case XMS_ATTR_NAME:
				break;
			case XMS_ATTR_VALUE:
				break;
			case XMS_TEXT:
				if( xs->level == 4 && xs->tree[1] == XT_TRACK_LIST && xs->tree[2] == XT_TRACK ) {
					struct playlist_item* item = xs->p_item;
					if( item )
					switch( xs->tree[3] ) {
						case XT_LOCATION:
							item->url_len = xs->n_token;
							item->url = xmalloc( char, item->url_len + 1 + 1);
							memcpy( item->url, xs->p_token, item->url_len );
							item->url[item->url_len++] = ' ';
							item->url[item->url_len] = 0;
							break;
						case XT_CREATOR:
							item->artist = strdup( xs->p_token );
							break;
						case XT_ALBUM:
							item->album = strdup( xs->p_token );
							break;
						case XT_TITLE:
							item->title = strdup( xs->p_token );
							break;
					}
				}
				break;
			}
			xs->n_token = 0;
		}
	}
}


static struct filter lfm_filter = {
	NULL,
	"last.fm spy",
	NULL,

	lfm_filter_open,
	lfm_filter_client,
	lfm_filter_request,
	NULL,
	lfm_filter_header_srv,
	NULL,
	NULL,
	lfm_filter_data_srv, 
	lfm_filter_clear,
	lfm_filter_close
};

static int h_lfm_folder( int argc, unsigned char **argv )
{
	if( g_folder ) free( g_folder );
	g_folder = strdup( (char*)argv[1] );
	return 0;
}

static int h_lfm_format( int argc, unsigned char **argv )
{
	if( g_format ) free( g_format );
	g_format = strdup( (char*)argv[1] );
	return 0;
}

static struct commands lfm_commandhandlers[] = {
	{lfm_commandhandlers+1, "lfm_folder",  h_lfm_folder, 2, 2},
	{NULL,                  "lfm_format",  h_lfm_format, 2, 2}
};

#ifdef  __cplusplus
extern "C" {
#endif
#ifdef _WIN32
__declspec(dllexport)
#endif
int lfm_plugin( struct pluginlink * pluginlink, int argc, char** argv )
{
	pl = pluginlink;
	myOutputDebugStringA1( "lfm_plugin" );
	if( !lfm_loaded ) {
		lfm_loaded = 1;

		lfm_filter.next = pl->conf->filters;
		pl->conf->filters = &lfm_filter;

		lfm_commandhandlers[1].next = pl->commandhandlers->next;
		pl->commandhandlers->next = lfm_commandhandlers;
	}
	return 0;		
}

#ifdef  __cplusplus
}
#endif
