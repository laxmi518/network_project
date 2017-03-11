/*! \file syslog_collector_c/syslog_collector._c
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
#include <oniguruma.h>
#include <jansson.h>
#include <glib.h>
#include <openssl/bio.h> 
#include <openssl/ssl.h> 
#include <openssl/err.h>

/* Custom made C libraries */
#include "json_creator.h"
#include "collector_lib.h"
/* Custome made C libraries from "clib" */
#include "lputil.h"
#include "cidr.h"
#include "wiring.h"


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

/** @brief function pointers to hold callback of application */
_COLLECTOR_UDP_CB _collector_udp_cb = NULL;
_COLLECTOR_TCP_CB _collector_tcp_cb = NULL;
_COLLECTOR_TCP_SSL_CB _collector_tcp_ssl_cb = NULL;

#ifdef BENCHMARK
unsigned int _cnt=0;
#endif

/** @brief Rrepresents thread pools from glib. */
static GThreadPool *pool;   

/** @brief hash table to store message without new line character at end */
GHashTable *_TCP_CACHE = NULL;
/** @brief mutex for regex */
GMutex _mutex_regex;
/** @brief mutex for global vairable _cnt while benchmarking.*/
GMutex _mutex_cnt;   
/** @brief mutex for zmq socket.*/ 
GMutex _mutex_socket;    
/** @brief mutex for global vairable _log_counter and _last_col_ts.*/
GMutex _mutex_log_counter; 
/** @brief mutex for global vairable OnigRegex.*/
GMutex _mutex_encode;

int _no_of_threads = 4;
int _queue_size    = 10000;

#define MAX_THREADS 4
#define MAX_UNUSED_THREADS 10
#define MAX_IDLE_TIME_MILLISECOND 10000

//****************************GLOBALS****************************************
/**time stamp  
*/
long _last_col_ts=0;
/** Number of syslog message per secone
*/
long _log_counter=0;

//int config_changed = 0;
/** ZMQ Socket
*/
void *_sender;
/** ZMQ _context
*/
void *_context;
/**
  configuration file path which is an input file(example-_config.json path).
 */
char *_config_path;
/**
  configuration which we are getting from json file(example-_config.json).
 */
json_t *_config;
/** json object containing different device ip
*/
json_t *_client_map;
/** collection type(syslog collector)
*/
const char *_col_type;
/**log  point name
*/
const char *_lp_name;
/** device _port
*/
int _port;
/** device _port ssl
*/
int _ssl_port;
/**log  ssl private key file path location
*/
const char *_ssl_keyfile;
/**log  ssl certificate file path location
*/
const char *_ssl_certfile;
/** Related to log
*/
zlog_category_t *_c;
zlog_category_t *_bc;
/** regex object is used for extracting the priority and datetime from syslog
*/
OnigRegex _re;
/**OnigRegion
*/
OnigRegion *_region;
/** regex object is used for extracting the priority and datetime for new syslog parser
*/
OnigRegex _re_new;
/**OnigRegion new syslog parser
*/
OnigRegion *_region_new;

//******************************STRUCTURES***********************************

/**
  Its for server event
 */
struct _sock_ev_serv {
    ev_io io;/**< Event io  */
    int fd;/**< descriptor  */
    int socket_len;/**< length of the socket  */
    char *device_ip;/**< device ip  */
};
/**
Its for client event
*/
struct _sock_ev_client {
    ev_io io;/**< Event io  */
    int fd;/**< descriptor  */
    int index;/**<#####not used##########*/
    struct _sock_ev_serv* server;/**<Its for server event*/
    char *device_ip;/**< device ip  */
};

/**
ev structure containing SSL
*/
struct _sock_ev_with_ssl {
    ev_io io;/**< Event io  */
    SSL *cSSL; /**< SSL */
    char *device_ip;/**< device ip  */
};

/**
* @brief structure to be passed to thread 
*/

typedef struct _data {
    int n;  /**< Length of the reveived message. */
    struct sockaddr_in6 client_addr; /**< client_addr */
    char *message; /**< _data received from socket */
} _data_t;

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
*Setting the paramaters like _client_map,time stamp,loginpoint name and _port.
*@return void
*/
void set_config_parameters() {
    _config = get_json_from_config_file(_config_path);

    _client_map = get_json_object_from_json(_config, "client_map");
    _col_type = get_string_value_from_json(_config, "col_type");
    _lp_name = get_string_value_from_json(_config, "loginspect_name");
    _port = get_integer_value_from_json(_config, "port");
    _no_of_threads = get_integer_value_from_json(_config, "no_of_threads");
    _queue_size = get_integer_value_from_json(_config, "queue_size");
    _ssl_port = get_integer_value_from_json(_config, "ssl_port");
    _ssl_keyfile = get_string_value_from_json(_config, "ssl_keyfile");
    _ssl_certfile = get_string_value_from_json(_config, "ssl_certfile");
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
//     zlog_fatal(_c, "Signal received: %d",sig);
//     for (i = 0; i < size; i++) {
//     //printf("%s\n", str[i]);
//         zlog_fatal(_c,"%s",str[i]);
//     }
//     free(str);
//     exit(sig);
// }

/**
*   @brief  Clean up all the allocated memories
*/
void memory_cleanup(void)
{
    zlog_debug(_c,"memory cleanup");
    //process all thread and free up memory
    g_thread_pool_free(pool,FALSE,TRUE); // return when all the queued task in pool has been completed
    json_decref(_config);
    free_zmq(_context, _sender); 
    g_mutex_clear(&_mutex_cnt);
    g_mutex_clear(&_mutex_regex);
    g_mutex_clear(&_mutex_log_counter);
    g_mutex_clear(&_mutex_socket);
    onig_region_free(_region, 1 /* 1:free self, 0:free contents only */);
    onig_free(_re);
    onig_end();
    zlog_debug(_c, "memory cleanup completed, exiting zlog");
    zlog_fini();
}

/** handle SIGHUP signal,reload the _config parameter
*/
void sig_callback(int signum) {
    
    if(signum == 2 || signum == 15) //2 = SIGINT 15 = SIGTERM
    {
        zlog_fatal(_c, "Signal received: %d",signum);
        Py_Finalize();
        memory_cleanup();    
        exit(signum);
    }
    else if( signum == 1)
    {
        zlog_debug(_c, "Signal received: %d (SIGHUP)",signum);
        signal(SIGHUP,sig_callback); //reset signal
        set_config_parameters(); /* reload _config parameters */
    }
}


char *get_encoded_msg(char *buffer, char *charset)
{
    Py_ssize_t ssize = (Py_ssize_t)strlen(buffer);
    PyObject *pyobject_unicode= PyUnicode_Decode(buffer,ssize,charset,"replace");
    if(pyobject_unicode==NULL)
    {
        zlog_error(_c,"decode failed for: %s",buffer);
        return NULL;
    }
    PyObject *pystring= PyUnicode_AsUTF8String(pyobject_unicode);
    if(pystring == NULL)
    {
        zlog_error(_c,"UTF-8 encode failed for: %s",buffer);
        return NULL;   
    }
    const char *encoded_str = PyString_AsString(pystring);
    char *encoded_str_dup = strdup(encoded_str);
    Py_DECREF(pystring);
    Py_DECREF(pyobject_unicode);
    zlog_debug(_c,"Encoded string: %s",encoded_str_dup);
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
    sprintf(mid, "%s|%s|%s|%010ld|%06ld", _lp_name, _col_type, dev_ip, col_ts, _log_counter );
    return mid;
}

/**
*   @brief internal method used by dbg_hash
*/
void dbg_hash_device_ip_loop(gpointer key, gpointer value, gpointer user_data)
{
    printf("Key: %s\n",(char *)key);
    _syslog_data_t *d = (_syslog_data_t*)value;
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
char *col_trim_whitespace(char *str)
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

json_t * col_create_basic_event(char *msg, char *dev_ip, json_t *dev_config)
{
    long col_ts;
    time_t now;
    now = time(0);
    col_ts = (long)now;

    g_mutex_lock(&_mutex_log_counter);
    if(col_ts > _last_col_ts)
    {
        _last_col_ts = col_ts;
        _log_counter = 0;
    }

    _log_counter += 1;

    char *mid;
    mid = inl_get_message_id(dev_ip, col_ts, _log_counter);
    g_mutex_unlock(&_mutex_log_counter);

    char *charset;
    char *encoded_msg;

    charset =(char *)get_string_value_from_json(dev_config, "charset");
    g_mutex_lock(&_mutex_encode);
    encoded_msg = get_encoded_msg(msg, charset);
    g_mutex_unlock(&_mutex_encode);
    if(encoded_msg == NULL)
    {
         return NULL;
    }
    json_t *event = create_json_object(_lp_name, encoded_msg, dev_ip, dev_config, mid, col_ts, _col_type);
    /* send message to upper layer */

    AFREE(mid);
    // json_decref(event);
    AFREE(encoded_msg);
    return event;
}


/**
*process message for tcp
*@param[in]  msg_full Syslog message received
*@param[in]  dev_ip device ip of machine which is sending the message
*@param[in]  dev_config device configuration
*@return void
*/
void process_message_tcp(char *msg_full, char *dev_ip, json_t *dev_config){
    (*_collector_tcp_cb)(msg_full, dev_ip, dev_config);   
}

/**
*process message for tcp with ssl
*@param[in]  msg_full Syslog message received
*@param[in]  dev_ip device ip of machine which is sending the message
*@param[in]  dev_config device configuration
*@return void
*/
void process_message_tcp_ssl(char *msg_full, char *dev_ip, json_t *dev_config){
    (*_collector_tcp_ssl_cb)(msg_full, dev_ip, dev_config);   
}

/**
*process message for udp
*@param[in]  msg Syslog message received
*@param[in]  dev_ip device ip of machine which is sending the message
*@param[in]  dev_config device configuration
*@return void
*/
void process_message_udp(char *msg, char *dev_ip, json_t *dev_config){
    (*_collector_udp_cb)(msg, dev_ip, dev_config);
}

/**
*@brief Print SSL error  
*@param[in]  ssl ssl _context
*@param[in]  sslerr ssl error
*/
void print_ssl_error(const SSL *ssl, int sslerr)
{
     int rc = SSL_get_error(ssl,sslerr);
     switch(rc){
        case SSL_ERROR_NONE:
            zlog_error(_c,"SSL_ERROR_NONE");
            break;
        case SSL_ERROR_ZERO_RETURN:
            zlog_error(_c,"SSL_ERROR_ZERO_RETURN");
            break;
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            zlog_error(_c,"SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE");
            break;
        case SSL_ERROR_WANT_CONNECT:
        case SSL_ERROR_WANT_ACCEPT:
            zlog_error(_c,"SSL_ERROR_WANT_CONNECT,SSL_ERROR_WANT_ACCEPT");
            break;
        case SSL_ERROR_WANT_X509_LOOKUP:
            zlog_error(_c,"SSL_ERROR_WANT_X509_LOOKUP");
            break;        
        case SSL_ERROR_SYSCALL:
            zlog_error(_c,"SSL_ERROR_SYSCALL");
            break;
        case SSL_ERROR_SSL:
            zlog_error(_c,"SSL_ERROR_SSL");
            break;
        default:
            zlog_error(_c,"default");
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
*@param[in]  sslctx ssl _context
*@param[in]  crtfile certificate file
*@param[in]  keyfile key file
*/
int LoadCertificates(SSL_CTX* sslctx,const char* crtfile,const char* keyfile)
{
    int use_cert = SSL_CTX_use_certificate_file(sslctx, crtfile , SSL_FILETYPE_PEM);
    if(use_cert!=1)
    {
        zlog_error(_c,"cert file error. Path: %s",crtfile);
        return -1;
    }
    int use_prv = SSL_CTX_use_PrivateKey_file(sslctx, keyfile, SSL_FILETYPE_PEM);
    if(use_prv!=1)
    {
        zlog_error(_c,"privatekey file error. Path: %s",keyfile);
        return -1;
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(sslctx) )
    {
        zlog_error(_c, "Private key does not match the public certificate\n");
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
    struct _sock_ev_with_ssl* client = (struct _sock_ev_with_ssl*) watcher;
    SSL *cSSL = client->cSSL;
    char *device_ip = client->device_ip;
    
    char buf[RCVBUFSIZE];
    ssize_t len;

    if(EV_ERROR & revents)
    {
      zlog_error(_c, "got invalid event");
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
    config_ip = get_config_ip(device_ip, _client_map);
    zlog_debug(_c,"The _config ip for dev_ip:%s is :%s\n", device_ip, config_ip);
    if (config_ip == NULL) {
        zlog_warn(_c, "Connection attempted from unregistered IP : %s\n", device_ip);
        return;
    }

    json_t *dev_config;
    dev_config = get_json_object_from_json(_client_map, config_ip);
    if (dev_config==NULL) {
        zlog_warn(_c, "Connection attempted from unregistered IP : %s\n", device_ip);
        return;
    }
    process_message_tcp_ssl(buf, device_ip, dev_config);
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
    struct _sock_ev_with_ssl* ev_ssl = (struct _sock_ev_with_ssl*) watcher;
    SSL *cSSL = ev_ssl->cSSL;

    struct sockaddr_in6 addr;
    socklen_t len = sizeof(addr);
    int client_fd;

    if(EV_ERROR & revents)
    {
      zlog_error(_c, "got invalid event");
      return;
    }

    // Accept client request
    client_fd = accept(watcher->fd, (struct sockaddr *)&addr, &len);

    if (client_fd < 0)
    {
      zlog_error(_c, "Error accepting connection from client");
      return;
    }

    char ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &addr.sin6_addr, ip, INET6_ADDRSTRLEN);
    char *dev_ip = get_ip(ip);
    zlog_debug(_c,"The obtained ip is %s and dev_ip is %s\n", ip, dev_ip);

    // if ((flags = fcntl(client_fd, F_GETFL, 0)) < 0 || fcntl(client_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    //     zlog_error(_c,"fcntl(2)");
    // }

    //ssl
    int rc = SSL_set_fd(cSSL, client_fd ); //connect the SSL object with a file descriptor
    if(rc==0)
        zlog_error(_c,"SSL_set_fd failed\n");
    //Here is the SSL Accept portion.  Now all reads and writes must use SSL
    int ssl_err = SSL_accept(cSSL);
    if(ssl_err<1)
    {
      //log and close down ssl    
      print_ssl_error(cSSL,ssl_err);
      ShutdownSSL(cSSL);
      return;
    }
    
    struct _sock_ev_with_ssl* client = malloc(sizeof(struct _sock_ev_with_ssl));
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
        zlog_error(_c,"Error creating TCP socket\n");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(portnum);

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    if (bind(sock, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        zlog_error(_c,"Error binding to TCP _port %d\n",portnum);
        return -1;
    }

    if (listen(sock, MAX_BACKLOG) < 0) {
        zlog_error(_c,"Error creating TCP listener on _port %d\n",portnum);
        return -1;
    }

    if ((flags = fcntl(sock, F_GETFL, 0)) < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        zlog_error(_c,"Error in fcnt in TCP collector \n");
    }
    return sock;
}

/**
*@brief Callback function which is starting tcp syslog server ssl 
*@return void*
*/
void *start_tcp_syslog_server_ssl()
{
    int fd =setup_tcp_socket(_ssl_port);
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
        zlog_error(_c, "Cannot create SSL _context");
        return NULL;
    } 
    SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE); //all this negotiation is done using ephemeral keying.
    
    int rc = LoadCertificates(sslctx,_ssl_certfile,_ssl_keyfile);
    if(rc == -1)
    {
        zlog_error(_c,"Could not start TCP SSL Server");
        return NULL;
    }
    SSL *cSSL = SSL_new(sslctx); //creates a new SSL structure which is needed to hold the _data for a TLS/SSL connection.
    if(cSSL == NULL)
    {
        zlog_error(_c, "Cannot create SSL structure");
        return NULL;
    }

    struct _sock_ev_with_ssl* ev_ssl = malloc(sizeof(struct _sock_ev_with_ssl));
    ev_ssl->cSSL = cSSL;

    ev_io_init(&ev_ssl->io, accept_cb, fd, EV_READ);
    ev_io_start(loop,&ev_ssl->io);
    zlog_info(_c,"TCP SSL Server started at _port: %d",_ssl_port);
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
        zlog_info(_c, "Error accepting _data from client");
        //perror("recv(2)");
        return -1;
    }

    if (len == 0) {
        return -1;
    }
    buf[len]='\0';
    
    /* Handle received message */
    zlog_debug(_c, "Received message = %s", buf);

    /** check for the cidr address for config_ip **/
    char *config_ip;
    config_ip = get_config_ip(device_ip, _client_map);
    zlog_debug(_c,"The _config ip for dev_ip:%s is :%s", device_ip, config_ip);
    if (config_ip == NULL) {
        zlog_warn(_c, "Connection attempted from unregistered IP : %s", device_ip);
        return -1;
    }

    json_t *dev_config;
    dev_config = get_json_object_from_json(_client_map, config_ip);
    if (dev_config==NULL) {
        zlog_warn(_c, "Connection attempted from unregistered IP : %s", device_ip);
        return -1;
    }
    process_message_tcp(buf, device_ip, dev_config);

// #ifdef BENCHMARK
    /* send message back to client */
    // if (send(sock, buf, len, 0) < 0) {
    //     perror("send(2)");
    //     return -1;
    // }
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
    struct _sock_ev_client* client = (struct _sock_ev_client*) w;
    if (echo(client->fd, client->device_ip) < 1) {
        close(client->fd);
        ev_io_stop(EV_A_ &client->io);
        AFREE(client->device_ip);
        AFREE(client);
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
    // start of the _sock_ev_serv struct
    struct _sock_ev_serv* server = (struct _sock_ev_serv*) w;
    server->socket_len = len;

    for (;;) {
        if ((client_fd = accept(server->fd, (struct sockaddr*) &addr, &len)) < 0) {
            switch (errno) {
            case EINTR:
            case EAGAIN:
                break;
            default:
                zlog_info(_c, "Error accepting connection from client \n");
                //perror("accept");
            }
            break;
        }
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr.sin6_addr, ip, INET6_ADDRSTRLEN);
        char *dev_ip = get_ip(ip);
        server->device_ip = dev_ip;

        zlog_debug(_c,"The obtained ip is %s and dev_ip is %s", ip, dev_ip);

        /** check for the cidr address for config_ip **/
        char *config_ip;
        config_ip = get_config_ip(dev_ip, _client_map);
        zlog_debug(_c,"The _config ip for dev_ip:%s is :%s", dev_ip, config_ip);
        if (config_ip == NULL) {
            zlog_debug(_c,"Connection attempted from unreigistered IP: %s", dev_ip);
            zlog_info(_c, "Connection attempted from unregistered IP : %s", dev_ip);
            AFREE(server->device_ip);            
            continue;
        }

        json_t *dev_config;
        dev_config = get_json_object_from_json(_client_map, config_ip);
        if (dev_config==NULL) {
            zlog_debug(_c,"Connection attempted from unreigistered IP: %s", dev_ip);
            zlog_info(_c, "Connection attempted from unregistered IP : %s", dev_ip);
            AFREE(server->device_ip);
            continue;
        }

        if ((flags = fcntl(client_fd, F_GETFL, 0)) < 0 || fcntl(client_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            zlog_error(_c, "fcntl(2)");
        }


        struct _sock_ev_client* client = malloc(sizeof(struct _sock_ev_client));
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
void key_destroy_cb(gpointer _data)
{
    AFREE(_data);
}

/**
*   @brief  Destroys the value
*/
void value_destroy_cb(gpointer _data)
{
    _syslog_data_t *d= (_syslog_data_t*)_data;
    AFREE(d->str);
    AFREE(d);
}

/**
*Callback function which is starting tcp syslog server,creating socket
*@return void
**/
void *start_tcp_syslog_server() {
    _TCP_CACHE = g_hash_table_new_full(g_str_hash, g_str_equal, key_destroy_cb, value_destroy_cb);
    zlog_info(_c,"TCP Server started at _port: %d",_port);
    int fd =setup_tcp_socket(_port);
    if(fd<0)
    {
        return NULL;
    }
    struct ev_loop *loop = EV_DEFAULT;
    struct _sock_ev_serv server;
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
        zlog_warn(_c,"Error getsockopt one");
    else
        zlog_info(_c, "old receive buffer size = %d", rcvbuff);
    
    if(set_rcv_buf==1)
    {
        zlog_info(_c,"setting the receive buffer to %d", new_rcvbuff);
        res = setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &new_rcvbuff, sizeof(new_rcvbuff));
    }

    if(res == -1)
        zlog_error(_c,"Error setsockopt");

    // Get buffer size
    optlen = sizeof(rcvbuff);
    res = getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuff, &optlen);

    if(res == -1)
        zlog_warn(_c,"Error getsockopt two");
    else
        zlog_info(_c,"new receive buffer size = %d", rcvbuff);
}

/**
*   @brief  Parse the recived packets on the basis of version type
*   @param[in] thread_data thread _data from buffer for parsing
*   @param[in] user_data any extra _data if needed
*   @return void
*/
void parse_data(gpointer thread_data, gpointer user_data)
{
    _data_t *_data= (_data_t *)thread_data;
    char ip[INET6_ADDRSTRLEN];
    errno=0;
    const char *rs = inet_ntop(AF_INET6, &_data->client_addr.sin6_addr, ip, INET6_ADDRSTRLEN);
    if(rs == NULL)
    {
        zlog_error(_c,"Error: %s",strerror(errno));
        return;
    }
    char *dev_ip = get_ip(ip);
    zlog_debug(_c,"The obtained ip is %s and dev_ip is %s", ip, dev_ip);
 
    char *config_ip = get_config_ip(dev_ip, _client_map);
    zlog_debug(_c,"The _config ip for dev_ip:%s is :%s", dev_ip, config_ip);
    if (config_ip == NULL) { 
       zlog_warn(_c, "Connection attempted from unregistered IP : %s", dev_ip);
        return;
    }

    json_t *dev_config = get_json_object_from_json(_client_map, config_ip);
    if (dev_config==NULL) {
        zlog_warn(_c, "Connection attempted from unregistered IP : %s", dev_ip);
        return;
    }

    process_message_udp(_data->message, dev_ip, dev_config);
    AFREE(dev_ip);
    AFREE(_data->message);
    AFREE(_data);
}

/**
*   @brief  Initializes the thread pool and mutexes for multithreading
*   @return void
*/
static void thread_init(void)
{
    if(g_thread_supported()!= TRUE)
    {
        zlog_fatal(_c,"Thread support False. Unable to run the service");
        exit(-1);
    }
    pool= g_thread_pool_new (parse_data, NULL,_no_of_threads , FALSE, NULL);
    zlog_info(_c,"Number of threads: %d",_no_of_threads);
    //max thread
    g_thread_pool_set_max_threads (pool,_no_of_threads,NULL );
    zlog_info(_c,"Max number of threads: %d",_no_of_threads);
    
    //max unused thread
    g_thread_pool_set_max_unused_threads(MAX_UNUSED_THREADS);
    zlog_info(_c,"Max unused threads: %d",MAX_UNUSED_THREADS);
    
    //max idle time
    g_thread_pool_set_max_idle_time(MAX_IDLE_TIME_MILLISECOND);
    zlog_info(_c,"Max Idle Time: %d",MAX_IDLE_TIME_MILLISECOND);

    //mutex
    g_mutex_init(&_mutex_cnt);
    g_mutex_init(&_mutex_log_counter);
    g_mutex_init(&_mutex_socket);
    g_mutex_init(&_mutex_regex);
    g_mutex_init(&_mutex_encode);
}

/**
Main function for the syslog collector get the _config_path from the argument,
*set parameters for syslog parser,
*save _config file _data in memory,
*starts the server
*/
void lib_init(char *service_name, char *zlog_conf_path) {
    
    setlocale(LC_CTYPE, "");

    int zrc;

    errno = 0;
    zrc = zlog_init(zlog_conf_path);
    // zrc = zlog_init("zlog.conf");
    if (zrc) {
        printf("Zlog init failed. Path: %s Error: %s\n",zlog_conf_path,strerror(errno));
        exit(1);
    }

    _c = zlog_get_category("lp_cat");
    if (!_c) {
        printf("Zlog: get category failed. \n");
        //zlog_fini();
        exit(1);
    }

    _bc = zlog_get_category("lp_cat_bench");
    if (!_bc) {
        printf("Zlog: get category failed for benchmark. \n");
        //zlog_fini();
        exit(1);
    }

    Py_Initialize();
    if(Py_IsInitialized() == 1)
        zlog_info(_c,"Py_IsInitialization succeed");
    else
    {
        zlog_fatal(_c, "Py_IsInitialization failed");
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
    _sender = get_collector_out_socket(service_name);

    /* set parameters for syslog parser */
    OnigErrorInfo errinfo;

    char *pattern = strdup("\\s*(?:<(?<pri>\\d{1,3})>)?\\s*(?:(?<log_time>[a-zA-Z]{3}\\s+\\d{1,2}\\s+(?<year>\\d{4}\\s+)?\\d\\d:\\d\\d:\\d\\d))?");

    int r = onig_new(&_re, (const OnigUChar *)pattern, (const OnigUChar *)(pattern + strlen(pattern)),
                        ONIG_OPTION_DEFAULT, ONIG_ENCODING_UTF8, ONIG_SYNTAX_DEFAULT, &errinfo);
    if(r!=ONIG_NORMAL)
        zlog_error(_c,"onig_new failed");
    _region = onig_region_new();
    AFREE(pattern);
    
    /* save _config file _data in memory*/
    set_config_parameters();

    zlog_debug(_c,"config_file_path  : %s\n", _config_path);
    zlog_debug(_c,"_col_type : %s\n", _col_type);
    zlog_debug(_c,"logpoint_name : %s\n", _lp_name);
    zlog_debug(_c,"_port : %d\n", _port);
}

void *start_udp_syslog_server()
{

#ifdef BENCHMARK
        if(_cnt == 0){
            struct timeval start_time;
            gettimeofday(&start_time, NULL);
            
            printf("benchmark _data: start_time = \n");
            timeval_print(&start_time);
        }        
#endif


    /* Syslog UDP Server */
    int sd, rc, n;
    struct sockaddr_in6 client_addr, server_addr;
    // char msg[RCVBUFSIZEUDP];

    sd = socket(AF_INET6, SOCK_DGRAM, 0);
    if(sd<0) {
        zlog_info(_c, "Cannot open socket for UDP connection. \n");
        //printf("cannot open socket \n");
        exit(1);
    }

    //setting max receiver buffer size  (128MB)
    set_rcv_buf(sd,pow(2,27),1);

    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_addr = in6addr_any;
    server_addr.sin6_port = htons(_port);

    rc = bind (sd, (struct sockaddr *) &server_addr,sizeof(server_addr));
    if(rc<0) {
        zlog_info(_c, "Cannot bind _port number %d\n", _port);
        //printf("cannot bind _port number %d \n", _port);
        exit(1);
    }
    zlog_info(_c, "Starting Syslog UDP Server \n");
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
        int unprocessed = g_thread_pool_unprocessed(pool);
        if(unprocessed > _queue_size)
        {
            continue;
        }
        char *msg =(char *)malloc(sizeof(char)*RCVBUFSIZEUDP);
        memset(msg, 0x0, RCVBUFSIZEUDP);

        socklen_t cliLen = (socklen_t)sizeof(client_addr);
        n = recvfrom(sd, msg, RCVBUFSIZEUDP, 0, (struct sockaddr *) &client_addr, &cliLen);

        if(n<0) {
            zlog_info(_c, "Cannot receive _data from client \n");
            AFREE(msg);
            continue;
        }

        _data_t *_data = (_data_t *)malloc(sizeof(_data_t));
        _data->n = n;
        _data->client_addr = client_addr;
        _data->message = msg;
        err = NULL;
        g_thread_pool_push (pool,_data, &err);
        if(err!=NULL)
        {
            zlog_error(_c, "Error pushing to threadpool %s", err->message);
        }
        // parse_data(_data,NULL);


    }/* end of server infinite loop */
    // AFREE(pattern);
    Py_Finalize();
    memory_cleanup();   
    return NULL;
}

void col_register_callbacks(_COLLECTOR_UDP_CB func1, _COLLECTOR_TCP_CB func2,_COLLECTOR_TCP_SSL_CB func3)
{
    _collector_udp_cb=func1;
    _collector_tcp_cb=func2;
    _collector_tcp_ssl_cb=func3;
    printf("register_callbacks\n");
}
void col_start()
{
    printf("start collectors\n");
    /* Run TCP Server in thread */
    pthread_t udp_thread, tcp_thread, tcp_ssl_thread;
    if(_collector_udp_cb)
    {
        pthread_create(&udp_thread, NULL, start_udp_syslog_server, NULL);
    }

    if(_collector_tcp_cb)
    {
        pthread_create(&tcp_thread, NULL, start_tcp_syslog_server, NULL);
    }

    if(_collector_tcp_ssl_cb)
    { 
        pthread_create(&tcp_ssl_thread, NULL, start_tcp_syslog_server_ssl, NULL);
    }
    if(_collector_udp_cb)
        pthread_join(udp_thread, NULL);
    if(_collector_tcp_cb)
        pthread_join(tcp_thread, NULL);
    if(_collector_tcp_ssl_cb)
        pthread_join(tcp_ssl_thread, NULL);
}

void col_init_library(char *_config_path_local, char *service_name, char *zlog_conf_path)
{
    _config_path=_config_path_local;
    lib_init(service_name, zlog_conf_path);
}
json_t * col_json_merge(json_t *basic, json_t *normalized_fields)
{
    json_object_set_new(basic, "_normalized_fields",normalized_fields);
    return basic;
}
void col_send_event(json_t *json_final,json_t *dev_config)
{
    const char *normalizer, *repo;
    normalizer = get_string_value_from_json(dev_config, "normalizer");
    repo = get_string_value_from_json(dev_config, "repo");
    send_event_with_mid(_sender, json_final, normalizer, repo);   
}

void col_update_json_field(json_t *event, char *field_to_update, char *append_value)
{
    json_t *json_value= json_object_get(event,field_to_update);
    const char *value = json_string_value(json_value);
    char *new_value;
    asprintf(&new_value,"%s%s",value,append_value);
    // json_decref(json_value);
    json_object_set_new(event,field_to_update,json_string(new_value));
    AFREE(new_value);
    // printf("haha\n");  
}

void col_free_syslog_data_t(_syslog_data_t *d)
{
    if(d)
    {
        AFREE(d->str);
        // AFREE(d->year);
        AFREE(d->date_time);
        AFREE(d);
    }
}

GMutex col_get_mutex_regex(void)
{
    return _mutex_regex;
}

GMutex col_get_mutex_cnt(void)
{
    return _mutex_cnt;
}

zlog_category_t *col_get_zlog_category(void)
{
    return _c;
}