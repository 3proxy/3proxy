#ifdef  __cplusplus
extern "C" {
#endif


#define FP_OK 0
#define FP_REJECT 65536

#define FP_CLIDATA 1
#define FP_SRVDATA 2
#define FP_CLIHEADER 4
#define FP_SRVHEADER 8
#define FP_KEEPFILE 16
#define FP_SHAREFILE 32
#define FP_PREVIEWCLI 64
#define FP_PREVIEWSRV 128
#define FP_CALLONREQUEST 256
#define FP_CALLAFTERCLIHEADERS 512
#define FP_CALLAFTERSRVHEADERS 1024
#define FP_CALLONREMOVE 2048

struct fp_filedata {
 struct clientparam *cp;
#ifdef _WIN32
 HANDLE h_cli, h_srv;
#else
 int fd_cli, fd_srv;
#endif
 char *path_cli;
 char *path_srv;
};


typedef int (*FP_CALLBACK)(int what, void *data, struct fp_filedata *fpd, char *buf, int size);

typedef int (*FP_REGISTERCALBACK) (int what, int max_size, int preview_size, struct clientparam *cp, FP_CALLBACK cb, void *data);


#ifdef  __cplusplus
}
#endif
