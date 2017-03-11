#ifndef BASICFETCHER_H
#define BASICFETCHER_H
#include "fetcher_lib.h"

#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>
#include <glib.h>
#include <pthread.h>
#include <time.h>
#include <zmq.h>
#include <assert.h>
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <zlog.h>
#include <string.h>
#include <libgen.h>
#include <openssl/sha.h>
#include <magic.h>
#include <dirent.h>
#include <limits.h>


#define CMD_TAR "tar -xf "
#define CMD_GZ "gunzip -f "
#define CMD_ZIP "unzip -o "

#define FILETYPE_UNKNOWN -1
#define FILETYPE_PLAINTEXT 1
#define FILETYPE_TAR 2
#define FILETYPE_GZIP 3
#define FILETYPE_ZIP 4

typedef struct {
    char *filename;
    long mtime;
}file_detail_t;

typedef struct {
    long mtime;
    long offset;
    char *sha1;
}file_store_detail_t;

void libssh2_shutdown(LIBSSH2_SESSION *session);
LIBSSH2_SESSION * create_session(void);
LIBSSH2_SFTP * create_sftp_session(LIBSSH2_SESSION *session, config_data_t *config_data,\
	const  char *user,const char *password);
int populate_file_list(LIBSSH2_SESSION *session, LIBSSH2_SFTP *sftp_session,\
	 GArray *filenames,char *path);
LIBSSH2_SFTP_HANDLE * fetch_file(LIBSSH2_SESSION *session,\
	 LIBSSH2_SFTP *sftp_session,char *sftppath, config_data_t *config_data,  int offset);
void save_file_offset_and_mtime_to_store(char *sid,const char *file, long mtime, char *sha1);
file_store_detail_t *get_offset_and_mtime_from_store(const char *sid, char *file);
void *thread_main_cb(void *parm);
int ensure_checksum_file(const char *basedir);

#endif


