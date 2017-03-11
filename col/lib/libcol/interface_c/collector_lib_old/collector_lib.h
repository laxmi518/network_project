#ifndef COLLECTORLIB_H
#define COLLECTORLIB_H

#include <math.h>
#include <libcidr.h>
#include <jansson.h>
#include <glib.h>
#include <assert.h>
#include <zmq.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <ev.h>
#include <openssl/bio.h> 
#include <openssl/ssl.h> 
#include <openssl/err.h>


#include "../../../../apps/collector_c/collector_main.h"



int tcp;
int udp;
int ssl;

char* config_path;
char* lp_name;
char* col_type;
int port;
int ssl_port;
json_t* client_map;
json_t* config;
const char* ssl_certfile;
const char* ssl_keyfile;

#define RCVBUFSIZEUDP 8192
#define RCVBUFSIZE 4096

#define MAPPED_IPV4_PREFIX "::ffff:"
#define MAX_BACKLOG 1024


GArray *array_of_collectors;
int count;

struct sock_ev_with_ssl {
    ev_io io;/**< Event io  */
    SSL *cSSL; /**< SSL */
    char *device_ip;/**< device ip  */
};


struct sock_ev_serv_tcp {
  ev_io io;
  int fd;
  int socket_len;
  char *device_ip;
};

struct sock_ev_client_tcp {
  ev_io io;
  int fd;
  int index;
  struct sock_ev_serv* server;
  char *device_ip;
};


const char *get_string_value_from_json(json_t *root, const char *field);
int get_integer_value_from_json(json_t *root, char *field);
json_t *get_json_object_from_json(json_t *root, char *field);
json_t *get_json_from_config_file(char *config_path);




void start_tcp_collector();
void start_udp_collector();
void start_ssl_collector();
void start_collector();
void sighup();
void set_config_parameters();
char *get_ip(char *dev_ip);
static void set_rcv_buf(int sockfd, int new_rcvbuff, int set_rcv_buf);
//void send_event_with_mid(void *sender, json_t *event, const char *normalizer, const char *repo);
json_t *create_json_object(const char *lp_name, char *message, char *dev_ip, json_t *dev_config,
						char *mid, long col_ts, long log_counter, const char *col_type);
void *get_collector_out_socket();



int is_dot_present(char *dev_ip);

//void* handle_data_cb (unsigned char * msg);






#endif
