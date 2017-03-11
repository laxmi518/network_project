/*! \file syslog_collector_c/syslog_collector.c
* @author Ritesh and Hari 
* @date 8/22/2013.... 
    
* Syslog Server for receiving Syslog Messages 
*/
#include <Python.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <math.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <locale.h>
#include <errno.h>


/* External Libraries */
/* LIBEV */
#include <ev.h>
#include <zlog.h>
#include <oniguruma.h>
#include <jansson.h>
#include <glib.h>
#include <openssl/bio.h> 
#include <openssl/ssl.h> 
#include <openssl/err.h>

/* Custom made C libraries */
#include "json_creator.h"

/* Custome made C libraries from "clib" */
#include "../../lib/clib/lputil.h"
#include "../../lib/clib/cidr.h"
#include "../../lib/clib/wiring.h"
#include "../../lib/clib/config_reader.h"

//********************************MACROS**********************************
/**
  A number to represent maximum backlog
 */
#define MAX_BACKLOG 1024
/**
  Receive buffer size
 */
#define RCVBUFSIZE 4096
/**
  Receive buffer size for UDP
 */
#define RCVBUFSIZEUDP 8192
/**
Prifix when mapping IPV4 to IPV6
*/
#define MAPPED_IPV4_PREFIX "::ffff:"


#ifdef BENCHMARK
unsigned int cnt=0;
#endif

/** @brief Rrepresents thread pools from glib. */
static GThreadPool *pool;   

/** @brief hash table to store message without new line character at end */
GHashTable *TCP_CACHE = NULL;

/** @brief mutex for global vairable cnt while benchmarking.*/
GMutex mutex_cnt;   
/** @brief mutex for zmq socket.*/ 
GMutex mutex_socket;    
/** @brief mutex for global vairable log_counter and last_col_ts.*/
GMutex mutex_log_counter; 
/** @brief mutex for global vairable OnigRegex.*/
GMutex mutex_regex;
GMutex mutex_encode;

int no_of_threads = 4;
int queue_size    = 10000;

#define MAX_THREADS 4
#define MAX_UNUSED_THREADS 10
#define MAX_IDLE_TIME_MILLISECOND 10000

//****************************GLOBALS****************************************
/**time stamp  
*/
long last_col_ts=0;
/** Number of syslog message per secone
*/
long log_counter=0;

//int config_changed = 0;
/** ZMQ Socket
*/
void *sender;
/** ZMQ Context
*/
void *context;
/**
  configuration file path which is an input file(example-config.json path).
 */
char *config_path;
/**
  configuration which we are getting from json file(example-config.json).
 */
json_t *config;
/** json object containing different device ip
*/
json_t *client_map;
/** collection type(syslog collector)
*/
const char *col_type;
/**log  point name
*/
const char *lp_name;
/** device port
*/
int port;
/** device port ssl
*/
int ssl_port;
/**log  ssl private key file path location
*/
const char *ssl_keyfile;
/**log  ssl certificate file path location
*/
const char *ssl_certfile;
/** Related to log
*/
zlog_category_t *c;
zlog_category_t *bc;
/** regex object is used for extracting the priority and datetime from syslog
*/
OnigRegex re;
/**OnigRegion
*/
OnigRegion *region;
/** regex object is used for extracting the priority and datetime for new syslog parser
*/
OnigRegex re_new;
/**OnigRegion new syslog parser
*/
OnigRegion *region_new;

//******************************STRUCTURES***********************************

/**
  Its for server event
 */
struct sock_ev_serv {
    ev_io io;/**< Event io  */
    int fd;/**< descriptor  */
    int socket_len;/**< length of the socket  */
    char *device_ip;/**< device ip  */
};
/**
Its for client event
*/
struct sock_ev_client {
    ev_io io;/**< Event io  */
    int fd;/**< descriptor  */
    int index;/**<#####not used##########*/
    struct sock_ev_serv* server;/**<Its for server event*/
    char *device_ip;/**< device ip  */
};

/**
ev structure containing SSL
*/
struct sock_ev_with_ssl {
    ev_io io;/**< Event io  */
    SSL *cSSL; /**< SSL */
    char *device_ip;/**< device ip  */
};

/**
* @brief structure to be passed to thread 
*/

typedef struct data {
    int n;  /**< Length of the reveived message. */
    struct sockaddr_in6 client_addr; /**< client_addr */
    char *message; /**< data received from socket */
} data_t;

/**
* Checking whether dot is present in device ip.If its present its returning 1(IPV4 case) otherwise 0(IPV6 case)
*@param[in]  dev_ip ip of machine
*@return  TRUE/FALSE
*/
int is_dot_present(char *dev_ip) {
    int ip_len = strlen(dev_ip);
    int i;
    for (i=ip_len-1; i>=0; i--) {
        if ('.' == dev_ip[i]) {
            return 1;
        }
    }
    return 0;
}


/**
* Checking for IPV4/IPV6, its checking against MAPPED_IPV4_PREFIX if its present, it will check for dot, if dot is present it will manipulate the ip 
* otherwise its not doing anything simply return the device ip.
*@param[in]  dev_ip device ip.
*@return  
*/ 
char *get_ip(char *dev_ip) {
    int rc;
    int ip_len=strlen(dev_ip);
    if (ip_len < 8) {
        return strdup(dev_ip);
    }
    char mapping_prefix[8];
    strncpy(mapping_prefix, dev_ip, 7);
    mapping_prefix[7]= '\0';
    //    char *ip = NULL;
    rc = strcmp(mapping_prefix, MAPPED_IPV4_PREFIX);
    
    if (!rc && is_dot_present(dev_ip)) {
        char *ip = (char *)malloc(sizeof(char) *(ip_len-7+1));//1 for terminating null character
        strncpy(ip, &dev_ip[7], ip_len-7);
        ip[ip_len - 7] = '\0';
        return ip;
    } else {
        return strdup(dev_ip);
    }
}



/**
*Setting the paramaters like client_map,time stamp,loginpoint name and port.
*@return void
*/
void set_config_parameters() {
    config = get_json_from_config_file(config_path);

    client_map = get_json_object_from_json(config, "client_map");
    col_type = get_string_value_from_json(config, "col_type");
    lp_name = get_string_value_from_json(config, "loginspect_name");
    port = get_integer_value_from_json(config, "port");
    no_of_threads = get_integer_value_from_json(config, "no_of_threads");
    queue_size = get_integer_value_from_json(config, "queue_size");
    ssl_port = get_integer_value_from_json(config, "ssl_port");
    ssl_keyfile = get_string_value_from_json(config, "ssl_keyfile");
    ssl_certfile = get_string_value_from_json(config, "ssl_certfile");
}

// /**
// *   @brief  It will write the backtrace to the log file 
// *   @param[in] sig  signal received
// */
// void do_backtrace(int sig) {
//     void *array[10];
//     int size;
//     size = backtrace(array, 10);
//     // print out all the frames to stderr
//     fprintf(stderr, "Error: signal %d:\n", sig);
//     char **str=backtrace_symbols(array,size);
//     backtrace_symbols_fd(array, size, 2); //2 is for stderr
//     int i;
//     zlog_fatal(c, "Signal received: %d",sig);
//     for (i = 0; i < size; i++) {
//     //printf("%s\n", str[i]);
//         zlog_fatal(c,"%s",str[i]);
//     }
//     free(str);
//     exit(sig);
// }

/** handle SIGHUP signal,reload the config parameter
*/
void sig_callback(int signum) {
    
    if(signum == 2 || signum == 15) //2 = SIGINT 15 = SIGTERM
    {
        zlog_fatal(c, "Signal received: %d",signum);
        exit(signum);
    }
    else if( signum == 1)
    {
        zlog_info(c, "Signal received: %d (SIGHUP)",signum);
        signal(SIGHUP,sig_callback); //reset signal
        set_config_parameters(); /* reload config parameters */
    }
}


char *get_encoded_msg(char *buffer, char *charset)
{
    Py_ssize_t ssize = (Py_ssize_t)strlen(buffer);
    PyObject *pyobject_unicode= PyUnicode_Decode(buffer,ssize,charset,"replace");
    if(pyobject_unicode==NULL)
    {
        zlog_error(c,"decode failed for: %s",buffer);
        return NULL;
    }
    PyObject *pystring= PyUnicode_AsUTF8String(pyobject_unicode);
    if(pystring == NULL)
    {
        zlog_error(c,"UTF-8 encode failed for: %s",buffer);
        return NULL;   
    }
    const char *encoded_str = PyString_AsString(pystring);
    char *encoded_str_dup = strdup(encoded_str);
    Py_DECREF(pystring);
    Py_DECREF(pyobject_unicode);
    zlog_debug(c,"Encoded string: %s",encoded_str_dup);
    return encoded_str_dup;
}

/**
*Creating message id
*@param[in]  dev_ip device ip
*@param[in]  col_ts time stamp of syslog message(in sec)
*@param[in]  counter  will count the message per sec
*@return message id
*/
__inline char *inl_get_message_id(char *dev_ip, long col_ts, long counter){
    char *mid = (char *) malloc(100);
    memset(mid, 0, 100);
    sprintf(mid, "%s|%s|%s|%010ld|%06ld", lp_name, col_type, dev_ip, col_ts, log_counter );
    return mid;
}

/**
*   @brief internal method used by dbg_hash
*/
void dbg_hash_device_ip_loop(gpointer key, gpointer value, gpointer user_data)
{
    printf("Key: %s\n",(char *)key);
    struct syslog_data *d = (struct syslog_data*)value;
    printf("\tValue: str:%s pri:%d year:%s date_time:%s\n",d->str,d->pri,d->year,d->date_time);
}

/**
*   @brief  break use this method in gdb to debug GHashTable object eg (gdb)call debug_hash(hash)
*   @param hash_table   input GHashTable
*/
void dbg_hash(GHashTable *hash_table)
{
    printf("printing hash\n");   
    if(hash_table==NULL)
    {
        printf("hash_table is null\n");
        return;
    }
    g_hash_table_foreach (hash_table, dbg_hash_device_ip_loop,NULL);
}

/** removes leading and trailing white spaces
*@param[in] input string
*@return char *
*@warning Note: This function returns a pointer to a substring of the original string.
    If the given string was allocated dynamically, the caller must not overwrite
    that pointer with the returned value, since the original pointer must be
    deallocated using the same allocator with which it was allocated.  The return
    value must NOT be deallocated using free() etc.
*/
char *trimwhitespace(char *str)
{
  char *end;

  // Trim leading space
  while(isspace(*str)) str++;

  if(*str == 0)  // All spaces?
    return str;

  // Trim trailing space
  end = str + strlen(str) - 1;
  while(end > str && isspace(*end)) end--;

  // Write new null terminator
  *(end+1) = 0;

  return str;
}

/**
*parse the  message for tcp, create message id,get the normilization and repo and then create event.
*@param[in]  dev_ip device ip of machine which is sending the message
*@param[in]  dev_config device configuration
*@param[in]  d syslog_data containing pri, date and time
*@return void
*/
void process_token(char *dev_ip, json_t *dev_config, struct syslog_data *d)
{
    json_t *event;

    long col_ts;
    time_t now;
    now = time(0);
    col_ts = (long)now;

    g_mutex_lock(&mutex_log_counter);
    if(col_ts > last_col_ts)
    {
        last_col_ts = col_ts;
        log_counter = 0;
    }

    log_counter += 1;

    char *mid;
    mid = inl_get_message_id(dev_ip, col_ts, log_counter);
    g_mutex_unlock(&mutex_log_counter);

    char *charset;
    char *encoded_msg;

    charset =(char *)get_string_value_from_json(dev_config, "charset");
    g_mutex_lock(&mutex_encode);
    encoded_msg = get_encoded_msg(d->str, charset);
    g_mutex_unlock(&mutex_encode);
    if(encoded_msg == NULL)
    {
         return;
    }
    const char *normalizer, *repo;
    normalizer = get_string_value_from_json(dev_config, "normalizer");
    repo = get_string_value_from_json(dev_config, "repo");

    event = create_json_object(lp_name, encoded_msg, dev_ip, dev_config, mid, col_ts, col_type,d);

    /* send message to upper layer */
    send_event_with_mid(sender, event, normalizer, repo);

    AFREE(mid);
    json_decref(event);
    AFREE(encoded_msg);
}


/**
*tokenize message for tcp
*@param[in]  msg_full Syslog message received
*@param[in]  dev_ip device ip of machine which is sending the message
*@param[in]  dev_config device configuration
*@return void
*/
void process_message_tcp(char *msg_full, char *dev_ip, json_t *dev_config){
   /* Split message by new line */
    const char *parser = get_string_value_from_json(dev_config, "parser");
    if(strcmp(parser,"NewSyslogParser")==0)
    {
        zlog_debug(c, "NewSyslogParser");
        int len = strlen(msg_full);
        char last_char = msg_full[len-1];
        char *token;
        char *remaining_str=NULL;
        token = strtok_r(msg_full, "\n", &remaining_str);
        while(token != NULL)
        {
            zlog_debug(c,"new syslog parser");
            struct syslog_data *d = get_syslog_data_from_message(re_new,region_new,token);
            //dbg_hash(TCP_CACHE);
            if(d==NULL)
            {
                zlog_debug(c,"no match");
                struct syslog_data *value = (struct syslog_data *)g_hash_table_lookup(TCP_CACHE, dev_ip);
                if(value==NULL)
                {
                    zlog_debug(c,"not prior pattern match exists, ignoring the message");
                    free(d);
                    token = strtok_r(NULL, "\n", &remaining_str);
                    continue;
                }   
                else
                {
                    zlog_debug(c,"There is data already, appending");
                    char *new_value=NULL;
                    asprintf(&new_value,"%s%s",value->str,token);
                    free(value->str);
                    value->str = new_value;
                    // g_hash_table_insert(TCP_MESSAGE_CACHE,strdup(dev_ip),new_value);
                } 
            }
            else
            {
                zlog_debug(c,"match");
                struct syslog_data *value = (struct syslog_data *)g_hash_table_lookup(TCP_CACHE, dev_ip);
                if(value!=NULL)
                {
                    zlog_debug(c,"sending data: %s and clearing cache",value->str);
                    // zlog_debug(c,"d-",d->);
                    process_token(dev_ip,dev_config,value);
                    g_hash_table_remove(TCP_CACHE,dev_ip);
                }
            
                zlog_debug(c,"inserting new token in the CACHE");
                d->str = strdup(token);
                g_hash_table_insert(TCP_CACHE,strdup(dev_ip),d);
            }
#ifdef DEBUG
            dbg_hash(TCP_CACHE);
#endif 
            token = strtok_r(NULL, "\n", &remaining_str);
        }
    }
    else
    {
        zlog_debug(c, "SyslogParser or LineParser");
        char *msg_concat;
        struct syslog_data *value = (struct syslog_data*)g_hash_table_lookup(TCP_CACHE, dev_ip);
        if(value!=NULL)//if the hash has device ip, append the value to msg
        {
            zlog_debug(c,"concatenating: str1: %s and str2: %s\n",value->str,msg_full);
            asprintf(&msg_concat,"%s%s",value->str,msg_full);
            g_hash_table_remove(TCP_CACHE,dev_ip);
            msg_full=msg_concat;
        }
        int len = strlen(msg_full);
        char last_char = msg_full[len-1];
        char *token;
        char *remaining_str=NULL;
        token = strtok_r(msg_full, "\n", &remaining_str);
        while (token != NULL)
        {
            if(token[0]==' ')
            {
                token = trimwhitespace(token);
                if(strcmp(token,"")==0)
                {
                    token = strtok_r(NULL, "\n", &remaining_str);
                    continue;
                }
            }
            if(strcmp(remaining_str,"")==0)
            {
                if(len>10000)
                {
                    zlog_warn(c, "Message too big(more than 10000 len). Stop looking for new line and process msg");
                    g_hash_table_remove(TCP_CACHE,dev_ip);
                }
                else
                {
                    if(last_char=='\n')
                    {
                        //new line is the last character. do nothing
                        zlog_debug(c, "last character is new line");
                    }
                    else
                    {
                        zlog_debug(c, "last character is not new line");
                        //new line not received
                        struct syslog_data *data = (struct syslog_data*)malloc(sizeof(struct syslog_data));
                        data->str=strdup(token);            
                        g_hash_table_insert(TCP_CACHE,strdup(dev_ip),data);
                        return;
                    }
                }
            }
            struct syslog_data *d = get_syslog_data_from_message(re,region,token);
            if(d!=NULL)
            {
                process_token(dev_ip,dev_config,d);    
                // if(d->str)
                //     free(d->str);
                if(d->year)
                    free(d->year);
                if(d->date_time)
                    free(d->date_time);
                free(d);
            }
            token = strtok_r(NULL, "\n", &remaining_str);
        }
    }
}

/**
*tokenize message for udp
*@param[in]  msg Syslog message received
*@param[in]  dev_ip device ip of machine which is sending the message
*@param[in]  dev_config device configuration
*@return void
*/
void process_message_udp(char *msg, char *dev_ip, json_t *dev_config){
    /* Split message by new line */
    char *message;
    char *saveptr;
    message = strtok_r(msg, "\n", &saveptr);
    while (message != NULL)
    {
        struct syslog_data *d = get_syslog_data_from_message_r(re,region,message);
        process_token(dev_ip,dev_config,d);
        message = strtok_r(NULL, "\n", &saveptr);
    }
}

/**
*@brief Print SSL error  
*@param[in]  ssl ssl context
*@param[in]  sslerr ssl error
*/
void print_ssl_error(const SSL *ssl, int sslerr)
{
     int rc = SSL_get_error(ssl,sslerr);
     switch(rc){
        case SSL_ERROR_NONE:
            zlog_error(c,"SSL_ERROR_NONE");
            break;
        case SSL_ERROR_ZERO_RETURN:
            zlog_error(c,"SSL_ERROR_ZERO_RETURN");
            break;
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            zlog_error(c,"SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE");
            break;
        case SSL_ERROR_WANT_CONNECT:
        case SSL_ERROR_WANT_ACCEPT:
            zlog_error(c,"SSL_ERROR_WANT_CONNECT,SSL_ERROR_WANT_ACCEPT");
            break;
        case SSL_ERROR_WANT_X509_LOOKUP:
            zlog_error(c,"SSL_ERROR_WANT_X509_LOOKUP");
            break;        
        case SSL_ERROR_SYSCALL:
            zlog_error(c,"SSL_ERROR_SYSCALL");
            break;
        case SSL_ERROR_SSL:
            zlog_error(c,"SSL_ERROR_SSL");
            break;
        default:
            zlog_error(c,"default");
            break;
     }
}
/**
*@brief Initialize SSL 
*/
void InitializeSSL()
{
    SSL_load_error_strings(); //registers the error strings for all libcrypto functions
    SSL_library_init(); //registers the available SSL/TLS ciphers and digests
    OpenSSL_add_all_algorithms(); //adds all algorithms to the table (digests and ciphers). 
}

/**
*@brief Destroy SSL 
*/
void DestroySSL()
{
    ERR_free_strings();
    EVP_cleanup();
}

/**
*@brief Shutdown SSL 
*@param[in]  ssl SSL connection structure
*/
void ShutdownSSL(SSL *ssl)
{
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

/**
*@brief Load Certificate 
*@param[in]  sslctx ssl context
*@param[in]  crtfile certificate file
*@param[in]  keyfile key file
*/
int LoadCertificates(SSL_CTX* sslctx,const char* crtfile,const char* keyfile)
{
    int use_cert = SSL_CTX_use_certificate_file(sslctx, crtfile , SSL_FILETYPE_PEM);
    if(use_cert!=1)
    {
        zlog_error(c,"cert file error. Path: %s",crtfile);
        return -1;
    }
    int use_prv = SSL_CTX_use_PrivateKey_file(sslctx, keyfile, SSL_FILETYPE_PEM);
    if(use_prv!=1)
    {
        zlog_error(c,"privatekey file error. Path: %s",keyfile);
        return -1;
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(sslctx) )
    {
        zlog_error(c, "Private key does not match the public certificate\n");
        return -1;
    }
    return 0;
}


/**
*callback method once a tcp connection is accepted 
*@param[in]  loop ev_loop
*@param[in]  watcher structure with with ev_io and SSL
*@param[in]  revents revents
*/
void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents){
    struct sock_ev_with_ssl* client = (struct sock_ev_with_ssl*) watcher;
    SSL *cSSL = client->cSSL;
    char *device_ip = client->device_ip;
    
    char buf[RCVBUFSIZE];
    ssize_t len;

    if(EV_ERROR & revents)
    {
      zlog_error(c, "got invalid event");
      return;
    }

    // Receive message from client socket
    len = SSL_read(cSSL, buf, RCVBUFSIZE);
    if(len >0)
    {
      buf[len]='\0';
    }
    else if(len==0)
    {
        ev_io_stop(loop,watcher);
        free(watcher);
        return;
      // printf("message:%s\n",buffer);
    }
    else
    {
        return;
    }

    /** check for the cidr address for config_ip **/
    char *config_ip;
    config_ip = get_config_ip(device_ip, client_map);
    zlog_debug(c,"The config ip for dev_ip:%s is :%s\n", device_ip, config_ip);
    if (config_ip == NULL) {
        zlog_warn(c, "Connection attempted from unregistered IP : %s\n", device_ip);
        return;
    }

    json_t *dev_config;
    dev_config = get_json_object_from_json(client_map, config_ip);
    if (dev_config==NULL) {
        zlog_warn(c, "Connection attempted from unregistered IP : %s\n", device_ip);
        return;
    }
    process_message_tcp(buf, device_ip, dev_config);
#ifdef BENCHMARK
    SSL_write(cSSL, buf, len);
#endif
}


/**
*callback method once a tcp connection is setup and accept request is received
*@param[in]  loop ev_loop
*@param[in]  watcher structure with with ev_io and SSL
*@param[in]  revents revents
*/
void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{   
    struct sock_ev_with_ssl* ev_ssl = (struct sock_ev_with_ssl*) watcher;
    SSL *cSSL = ev_ssl->cSSL;

    struct sockaddr_in6 addr;
    socklen_t len = sizeof(addr);
    int client_fd;

    if(EV_ERROR & revents)
    {
      zlog_error(c, "got invalid event");
      return;
    }

    // Accept client request
    client_fd = accept(watcher->fd, (struct sockaddr *)&addr, &len);

    if (client_fd < 0)
    {
      zlog_error(c, "Error accepting connection from client");
      return;
    }

    char ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &addr.sin6_addr, ip, INET6_ADDRSTRLEN);
    char *dev_ip = get_ip(ip);
    zlog_debug(c,"The obtained ip is %s and dev_ip is %s\n", ip, dev_ip);

    // if ((flags = fcntl(client_fd, F_GETFL, 0)) < 0 || fcntl(client_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    //     zlog_error(c,"fcntl(2)");
    // }

    //ssl
    int rc = SSL_set_fd(cSSL, client_fd ); //connect the SSL object with a file descriptor
    if(rc==0)
        zlog_error(c,"SSL_set_fd failed\n");
    //Here is the SSL Accept portion.  Now all reads and writes must use SSL
    int ssl_err = SSL_accept(cSSL);
    if(ssl_err<1)
    {
      //log and close down ssl    
      print_ssl_error(cSSL,ssl_err);
      ShutdownSSL(cSSL);
      return;
    }
    
    struct sock_ev_with_ssl* client = malloc(sizeof(struct sock_ev_with_ssl));
    client->cSSL = cSSL;
    client->device_ip = dev_ip;
   
    ev_io_init(&client->io, read_cb, client_fd, EV_READ);
    ev_io_start(loop, &client->io);
}

/**
*@brief creates, binds and start listening to tcp socket 
*@return socket fd
*/
int setup_tcp_socket(int portnum)
{
   int sock, flags, yes=1;
    struct sockaddr_in6 addr;

    if ((sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        zlog_error(c,"Error creating TCP socket\n");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(portnum);

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    if (bind(sock, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        zlog_error(c,"Error binding to TCP port %d\n",portnum);
        return -1;
    }

    if (listen(sock, MAX_BACKLOG) < 0) {
        zlog_error(c,"Error creating TCP listener on port %d\n",portnum);
        return -1;
    }

    if ((flags = fcntl(sock, F_GETFL, 0)) < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        zlog_error(c,"Error in fcnt in TCP collector \n");
    }
    return sock;
}

/**
*@brief Callback function which is starting tcp syslog server ssl 
*@return void*
*/
void *start_tcp_syslog_server_ssl()
{
    int fd =setup_tcp_socket(ssl_port);
    if(fd<0)
    {
        return NULL;
    }
    // struct ev_loop *loop = ev_default_loop(0);// use the default event loop unless you have special needs
    struct ev_loop *loop = ev_loop_new(EVBACKEND_EPOLL | EVFLAG_NOENV);

    InitializeSSL();
    SSL_CTX *sslctx = SSL_CTX_new( SSLv23_server_method()); //SSLv23_server_method() indicates
    //application is a server and supports 
    //Secure Sockets Layer version 2 (SSLv2), Secure Sockets Layer version 3 (SSLv3), and Transport Layer Security version 1 (TLSv1).
    if(sslctx == NULL)
    {
        zlog_error(c, "Cannot create SSL context");
        return NULL;
    } 
    SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE); //all this negotiation is done using ephemeral keying.
    
    int rc = LoadCertificates(sslctx,ssl_certfile,ssl_keyfile);
    if(rc == -1)
    {
        zlog_error(c,"Could not start TCP SSL Server");
        return NULL;
    }
    SSL *cSSL = SSL_new(sslctx); //creates a new SSL structure which is needed to hold the data for a TLS/SSL connection.
    if(cSSL == NULL)
    {
        zlog_error(c, "Cannot create SSL structure");
        return NULL;
    }

    struct sock_ev_with_ssl* ev_ssl = malloc(sizeof(struct sock_ev_with_ssl));
    ev_ssl->cSSL = cSSL;

    ev_io_init(&ev_ssl->io, accept_cb, fd, EV_READ);
    ev_io_start(loop,&ev_ssl->io);
    zlog_info(c,"TCP SSL Server started at port: %d",ssl_port);
    ev_loop(loop, 0);

    return 0;
}

/**
*check for the cidr address for config_ip parse message and send message back to client
*@param[in]  sock Socket
*@param[in]  device_ip ip of device
*@return  
*/ 
int echo(int sock, char* device_ip) {
	/* Get as function arguments*/
    char buf[RCVBUFSIZE];
    size_t len;

    if ((len = recv(sock, buf, RCVBUFSIZE, 0)) < 0) {
    	zlog_info(c, "Error accepting data from client");
        //perror("recv(2)");
        return -1;
    }

    if (len == 0) {
        return -1;
    }
    buf[len]='\0';
    
    /* Handle received message */
    zlog_debug(c, "Received message = %s\n", buf);

    /** check for the cidr address for config_ip **/
    char *config_ip;
    config_ip = get_config_ip(device_ip, client_map);
    zlog_debug(c,"The config ip for dev_ip:%s is :%s\n", device_ip, config_ip);
    if (config_ip == NULL) {
        zlog_warn(c, "Connection attempted from unregistered IP : %s\n", device_ip);
        return -1;
    }

    json_t *dev_config;
    dev_config = get_json_object_from_json(client_map, config_ip);
    if (dev_config==NULL) {
        zlog_warn(c, "Connection attempted from unregistered IP : %s\n", device_ip);
        return -1;
    }
    process_message_tcp(buf, device_ip, dev_config);

// #ifdef BENCHMARK
    /* send message back to client */
	if (send(sock, buf, len, 0) < 0) {
		perror("send(2)");
		return -1;
	}
// #endif
	
    return len;
}

/**
*Callback function for closing the client file descriptor and stop client io.
*@param[in]  w a struct of type EV_P_
*@param[in]  revents can be  EV_ERROR, EV_READ, EV_WRITE or EV_TIMEOUT
*@return  void
*/ 
void event_client(EV_P_ struct ev_io *w, int revents) {
    struct sock_ev_client* client = (struct sock_ev_client*) w;
    if (echo(client->fd, client->device_ip) < 1) {
        close(client->fd);
        ev_io_stop(EV_A_ &client->io);
        free(client);
    }
}


/**
*Callback function ,check for the cidr address for config_ip
*@param[in] w EV_P_ structure
*@param[in] revents remaing
*@return void
*/
void event_server(EV_P_ struct ev_io *w, int revents) {
    int flags;
    struct sockaddr_in6 addr;
    socklen_t len = sizeof(addr);

    int client_fd;

    // since ev_io is the first member,
    // watcher `w` has the address of the 
    // start of the sock_ev_serv struct
    struct sock_ev_serv* server = (struct sock_ev_serv*) w;
    server->socket_len = len;

    for (;;) {
        if ((client_fd = accept(server->fd, (struct sockaddr*) &addr, &len)) < 0) {
            switch (errno) {
            case EINTR:
            case EAGAIN:
                break;
            default:
            	zlog_info(c, "Error accepting connection from client \n");
                //perror("accept");
            }
            break;
        }
        char ip[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &addr.sin6_addr, ip, INET6_ADDRSTRLEN);
		char *dev_ip = get_ip(ip);
        server->device_ip = dev_ip;

        zlog_debug(c,"The obtained ip is %s and dev_ip is %s\n", ip, dev_ip);

        /** check for the cidr address for config_ip **/
        char *config_ip;
        config_ip = get_config_ip(dev_ip, client_map);
        zlog_debug(c,"The config ip for dev_ip:%s is :%s\n", dev_ip, config_ip);
        if (config_ip == NULL) {
            zlog_debug(c,"Connection attempted from unreigistered IP: %s\n", dev_ip);
            zlog_info(c, "Connection attempted from unregistered IP : %s\n", dev_ip);
            continue;
        }

        json_t *dev_config;
        dev_config = get_json_object_from_json(client_map, config_ip);
        if (dev_config==NULL) {
            zlog_debug(c,"Connection attempted from unreigistered IP: %s\n", dev_ip);
            zlog_info(c, "Connection attempted from unregistered IP : %s\n", dev_ip);
            continue;
        }

        if ((flags = fcntl(client_fd, F_GETFL, 0)) < 0 || fcntl(client_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            zlog_error(c, "fcntl(2)");
        }


        struct sock_ev_client* client = malloc(sizeof(struct sock_ev_client));
        client->device_ip = dev_ip;
        client->server = server;
        client->fd = client_fd;

        // ev_io *watcher = (ev_io*)calloc(1, sizeof(ev_io));
        ev_io_init(&client->io, event_client, client_fd, EV_READ);
        ev_io_start(EV_DEFAULT, &client->io);
    }
}

/**
*   @brief  Destroys the key
*/
void key_destroy_cb(gpointer data)
{
    AFREE(data);
}

/**
*   @brief  Destroys the value
*/
void value_destroy_cb(gpointer data)
{
    struct syslog_data *d= (struct syslog_data*)data;
    AFREE(d->str);
    AFREE(d);
}

/**
*Callback function which is starting tcp syslog server,creating socket
*@return void*
*/
void *start_tcp_syslog_server() {
    TCP_CACHE = g_hash_table_new_full(g_str_hash, g_str_equal, key_destroy_cb, value_destroy_cb);
    zlog_info(c,"TCP Server started at port: %d",port);
    int fd =setup_tcp_socket(port);
    if(fd<0)
    {
        return NULL;
    }
    struct ev_loop *loop = EV_DEFAULT;
    struct sock_ev_serv server;
    server.fd = fd;
    ev_io_init(&server.io, event_server, server.fd, EV_READ);
    ev_io_start(EV_A_ &server.io);

    // ev_init(&watcher, event_server);
    // ev_io_set(&watcher, sock, EV_READ);
    // ev_io_start(loop, &watcher);
    ev_loop(loop, 0);
    return 0;
}

/**
*It will set the max receive buffer size 
*@param[in] sockfd socket file descriptor
*@param[in] new_rcvbuff new buffer size to set
*@param set_rcv_buf 1
*@return void
*/
static void set_rcv_buf(int sockfd, int new_rcvbuff, int set_rcv_buf)
{
    int rcvbuff;

    socklen_t optlen;
    int res = 0;

    // Get buffer size
    optlen = sizeof(rcvbuff);
    res = getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuff, &optlen);

    if(res == -1)
        zlog_warn(c,"Error getsockopt one");
    else
        zlog_info(c, "old receive buffer size = %d", rcvbuff);
    
    if(set_rcv_buf==1)
    {
        zlog_info(c,"setting the receive buffer to %d", new_rcvbuff);
        res = setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &new_rcvbuff, sizeof(new_rcvbuff));
    }

    if(res == -1)
        zlog_error(c,"Error setsockopt");

    // Get buffer size
    optlen = sizeof(rcvbuff);
    res = getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuff, &optlen);

    if(res == -1)
        zlog_warn(c,"Error getsockopt two");
    else
        zlog_info(c,"new receive buffer size = %d", rcvbuff);
}

/**
*   @brief  Parse the recived packets on the basis of version type
*   @param[in] thread_data thread data from buffer for parsing
*   @param[in] user_data any extra data if needed
*   @return void
*/
void parse_data(gpointer thread_data, gpointer user_data)
{
    data_t *data= (data_t *)thread_data;
    char ip[INET6_ADDRSTRLEN];
    errno=0;
    const char *rs = inet_ntop(AF_INET6, &data->client_addr.sin6_addr, ip, INET6_ADDRSTRLEN);
    if(rs == NULL)
    {
        zlog_error(c,"Error: %s",strerror(errno));
        return;
    }
    char *dev_ip = get_ip(ip);
    zlog_debug(c,"The obtained ip is %s and dev_ip is %s", ip, dev_ip);
 
    char *config_ip = get_config_ip(dev_ip, client_map);
    zlog_debug(c,"The config ip for dev_ip:%s is :%s", dev_ip, config_ip);
    if (config_ip == NULL) { 
       zlog_warn(c, "Connection attempted from unregistered IP : %s", dev_ip);
        return;
    }

    json_t *dev_config = get_json_object_from_json(client_map, config_ip);
    if (dev_config==NULL) {
        zlog_warn(c, "Connection attempted from unregistered IP : %s", dev_ip);
        return;
    }

    process_message_udp(data->message, dev_ip, dev_config);
    AFREE(dev_ip);
    AFREE(data->message);
    AFREE(data);
}

/**
*   @brief  Initializes the thread pool and mutexes for multithreading
*   @return void
*/
static void thread_init(void)
{
    if(g_thread_supported()!= TRUE)
    {
        zlog_fatal(c,"Thread support False. Unable to run the service");
        exit(-1);
    }
    pool= g_thread_pool_new (parse_data, NULL,no_of_threads , FALSE, NULL);
    zlog_info(c,"Number of threads: %d",no_of_threads);
    //max thread
    g_thread_pool_set_max_threads (pool,no_of_threads,NULL );
    zlog_info(c,"Max number of threads: %d",no_of_threads);
    
    //max unused thread
    g_thread_pool_set_max_unused_threads(MAX_UNUSED_THREADS);
    zlog_info(c,"Max unused threads: %d",MAX_UNUSED_THREADS);
    
    //max idle time
    g_thread_pool_set_max_idle_time(MAX_IDLE_TIME_MILLISECOND);
    zlog_info(c,"Max Idle Time: %d",MAX_IDLE_TIME_MILLISECOND);

    //mutex
    g_mutex_init(&mutex_cnt);
    g_mutex_init(&mutex_log_counter);
    g_mutex_init(&mutex_socket);
    g_mutex_init(&mutex_regex);
    g_mutex_init(&mutex_encode);
}

/**
*   @brief  Clean up all the allocated memories
*/
void memory_cleanup(void)
{
    //process all thread and free up memory
    g_thread_pool_free(pool,FALSE,TRUE); // return when all the queued task in pool has been completed
    json_decref(config);
    free_zmq(context, sender); 
    zlog_fini();
    g_mutex_clear(&mutex_cnt);
    g_mutex_clear(&mutex_regex);
    g_mutex_clear(&mutex_log_counter);
    g_mutex_clear(&mutex_socket);
    onig_region_free(region, 1 /* 1:free self, 0:free contents only */);
    onig_free(re);
    onig_end();

}

/**
Main function for the syslog collector get the config_path from the argument,
*set parameters for syslog parser,
*save config file data in memory,
*starts the server
*/
int main(int argc, char *argv[]) {
    
    setlocale(LC_CTYPE, "");

	/* check argument passed to program */
	if(argv[1] == NULL)	{
		printf("A config file is expected as argument.\n");
		exit(1);
	}

	config_path = argv[1];

	//if(argv[2] == NULL)	{
	//	printf("A zlog config file is expected as argument.\n");
	//	exit(1);
	//}

	int zrc;

	// zrc = zlog_init(argv[2]);
    errno = 0;
	zrc = zlog_init("/opt/immune/storage/col/zlog_syslog.conf");
	// zrc = zlog_init("zlog.conf");
	if (zrc) {
		printf("Zlog init failed. %s\n",strerror(errno));
		exit(1);
	}

	c = zlog_get_category("lp_cat");
	if (!c) {
		printf("Zlog: get category failed. \n");
		//zlog_fini();
		exit(1);
	}

    bc = zlog_get_category("lp_cat_bench");
    if (!bc) {
        printf("Zlog: get category failed for benchmark. \n");
        //zlog_fini();
        exit(1);
    }

    Py_Initialize();
    if(Py_IsInitialized() == 1)
        zlog_info(c,"Py_IsInitialization succeed");
    else
    {
        zlog_fatal(c, "Py_IsInitialization failed");
        exit(1);
    }

	/* handle signals */
    signal(SIGHUP, sig_callback);
    signal(SIGINT, sig_callback);
    // signal(SIGTERM, sig_callback);
    // signal(SIGABRT, do_backtrace);
    // signal(SIGFPE, do_backtrace);
    // signal(SIGILL, do_backtrace);
    // signal(SIGSEGV, do_backtrace);

	/* get collector out socket */
	sender = get_collector_out_socket("syslog_c_collector");

	/* set parameters for syslog parser */
    OnigErrorInfo errinfo;

    char *pattern = strdup("\\s*(?:<(?<pri>\\d{1,3})>)?\\s*(?:(?<log_time>[a-zA-Z]{3}\\s+\\d{1,2}\\s+(?<year>\\d{4}\\s+)?\\d\\d:\\d\\d:\\d\\d))?");

    int r = onig_new(&re, (const OnigUChar *)pattern, (const OnigUChar *)(pattern + strlen(pattern)),
						ONIG_OPTION_DEFAULT, ONIG_ENCODING_UTF8, ONIG_SYNTAX_DEFAULT, &errinfo);
    if(r!=ONIG_NORMAL)
        zlog_error(c,"onig_new failed");
    region = onig_region_new();

    char *pattern_new = strdup("\\s*\\d{1,5}\\s*(?:<(?<pri>\\d{1,3})>)\\d\\s*(?:(?<log_time>[a-zA-Z]{3}\\s+\\d{1,2}\\s+(?<year>\\d{4}\\s+)?\\d\\d:\\d\\d:\\d\\d))?");

    r = onig_new(&re_new, (const OnigUChar *)pattern_new, (const OnigUChar *)(pattern_new + strlen(pattern_new)),
                        ONIG_OPTION_DEFAULT, ONIG_ENCODING_UTF8, ONIG_SYNTAX_DEFAULT, &errinfo);

    region_new = onig_region_new();


    /* save config file data in memory*/
	set_config_parameters();

	zlog_debug(c,"config_file_path  : %s\n", config_path);
	zlog_debug(c,"col_type : %s\n", col_type);
	zlog_debug(c,"logpoint_name : %s\n", lp_name);
	zlog_debug(c,"port : %d\n", port);
	zlog_debug(c,"This is the starting of all the chaos. \n ");

	zlog_info(c, "Starting Syslog TCP Server\n");
	//printf("Starting Syslog TCP Server\n");

#ifdef BENCHMARK
        if(cnt == 0){
            struct timeval start_time;
            gettimeofday(&start_time, NULL);
            
            printf("benchmark data: start_time = \n");
            timeval_print(&start_time);
        }        
#endif
	/* Run TCP Server in thread */
	pthread_t tcp_thread;
	pthread_create(&tcp_thread, NULL, start_tcp_syslog_server, NULL);
	//start_tcp_syslog_server();

     // Run TCP SSL Server in thread 
    pthread_t tcp_ssl_thread;
    pthread_create(&tcp_ssl_thread, NULL, start_tcp_syslog_server_ssl, NULL);

	/* Syslog UDP Server */
	int sd, rc, n;
	struct sockaddr_in6 client_addr, server_addr;
	// char msg[RCVBUFSIZEUDP];

	sd = socket(AF_INET6, SOCK_DGRAM, 0);
	if(sd<0) {
		zlog_info(c, "Cannot open socket for UDP connection. \n");
		//printf("cannot open socket \n");
		exit(1);
	}

    //setting max receiver buffer size 8388608 (8MB)
    set_rcv_buf(sd,pow(2,23),1);

	server_addr.sin6_family = AF_INET6;
	server_addr.sin6_addr = in6addr_any;
	server_addr.sin6_port = htons(port);

	rc = bind (sd, (struct sockaddr *) &server_addr,sizeof(server_addr));
	if(rc<0) {
		zlog_info(c, "Cannot bind port number %d\n", port);
		//printf("cannot bind port number %d \n", port);
		exit(1);
	}
	zlog_info(c, "Starting Syslog UDP Server \n");
	//printf("Starting Syslog UDP Server \n");

    thread_init();
    GError *err=NULL;
	/* server infinite loop */
	while(1) {
        /** @warning
        It makes no differences when using a char* as a string. 
        The only time signed/unsigned would make a difference is if you would be interpreting it as a number, 
        like for arithmetic or if you were to print it as an integer.
        **/
        char *msg =(char *)malloc(sizeof(char)*RCVBUFSIZEUDP);
		memset(msg, 0x0, RCVBUFSIZEUDP);

		socklen_t cliLen = (socklen_t)sizeof(client_addr);
		n = recvfrom(sd, msg, RCVBUFSIZEUDP, 0, (struct sockaddr *) &client_addr, &cliLen);

		if(n<0) {
			zlog_info(c, "Cannot receive data from client \n");
			AFREE(msg);
			continue;
		}
        int unprocessed = g_thread_pool_unprocessed(pool);
        if(unprocessed > queue_size)
        {
            AFREE(msg);
            continue;
        }
        data_t *data = (data_t *)malloc(sizeof(data_t));
        data->n = n;
        data->client_addr = client_addr;
        data->message = msg;
        err = NULL;
        g_thread_pool_push (pool,data, &err);
        if(err!=NULL)
        {
            zlog_error(c, "Error pushing to threadpool %s", err->message);
        }
        // parse_data(data,NULL);


	}/* end of server infinite loop */
    AFREE(pattern);
    Py_Finalize();
    memory_cleanup();	
	return 0;
}
