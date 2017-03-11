#ifndef COLLECTOR_H
#define COLLECTOR_H

#define _USE_XOPEN
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <jansson.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <oniguruma.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <zmq.h>
/** External Libaries **/ 
#include <libcidr.h>

/* LIBEV */
#include <ev.h>

#include "zlog.h"


struct collector_init_param {
	long last_col_ts;
	long log_counter;
};

struct config_parameters {
	const char* col_type;
	const char* lp_name;
	json_t *client_map;
	int port;
};

struct sock_ev_serv {
  ev_io io;
  int fd;
  int socket_len;
  char *device_ip;
};

struct sock_ev_client {
  ev_io io;
  int fd;
  int index;
  struct sock_ev_serv* server;
  char *device_ip;
};

struct syslog_data {
    OnigRegion *region;
    UChar *str;
    int pri;
    char *year;
    char *date_time;
};


struct config_parameters params;
struct collector_init_param init;


#ifdef BENCHMARK
unsigned int cnt=0;
#endif

//global Variables
char * config_path;//TODO:// config path as a local to main
void *sender;
json_t *config;
zlog_category_t *c;
OnigRegex re;
OnigRegion *region;




//Macro
#define MAX_BACKLOG 1024
#define RCVBUFSIZE 4096
#define RCVBUFSIZEUDP 8192
#define MAPPED_IPV4_PREFIX "::ffff:"
#define FALSE				0
#define TRUE				1


//lplog
#ifdef LPLOG
#define lplog(...) { _lplog(__FILE__, __LINE__, __func__, ##__VA_ARGS__); }
#else
#define lplog(...)
/* do nothing */
#endif

#define AFREE(p) { if(p) free(p); }

#define MAX_LOGBUFFER_SIZE 32768
struct _lplog_context {
    char *logbuf;
    char *va_logbuf;
};

typedef struct _lplog_context lplog_context_t;

lplog_context_t *lplog_context_global=NULL;


extern int echo(int sock, char* device_ip);
extern char *collector_get_message_id(char *dev_ip, long col_ts, long counter);//
extern void collector_parse_message_line_by_line(char *msg, char *dev_ip, json_t *dev_config);
extern void collector_send_event_with_mid(void *sender, json_t *event, const char *normalizer, const char *repo);
extern void collector_set_config_parameters();//
extern char *collector_get_ip(char* dev_ip);
extern json_t *collector_create_json_object(OnigRegex re , OnigRegion *region, const char *lp_name, char *message, char *dev_ip, json_t *dev_config,
                  char *mid, long col_ts, long log_counter, const char *col_type);
extern json_t *collector_get_json_from_config_file(char *config_path);
extern const char *collector_get_string_value_from_json(json_t *root,char *field);
extern int collector_get_integer_value_from_json(json_t *root, char *field);
extern json_t *collector_get_json_object_from_json(json_t *root, char *field);
extern char *collector_get_config_ip(char *dev_ip, json_t *client_map);
extern void *get_collector_out_socket();
extern struct syslog_data * collector_parse_syslog_message(char *message, OnigRegex re , OnigRegion *region);



//callbacks
void* collector_start_tcp_syslog_server_cb();/*callback function*/
void collector_event_client_cb(EV_P_ struct ev_io *w, int revents);//
void collector_event_server_cb(EV_P_ struct ev_io *w, int revents);//
int name_callback(const OnigUChar *name, const OnigUChar *end, int ngroups, int *group_list,
					OnigRegex re, void *arg);




#endif


