#include "collector_lib.h"


void start_tcp_collector(){
tcp = 1;
count++;
}

void start_udp_collector(){
udp = 1;
count++;
}

void start_ssl_collector(){
ssl = 1;
count++;
}

//*******************************************json part*******************************************
json_t *get_json_from_config_file(char *config_path) {
	/* Read config from json file*/
    json_t *config;
    json_error_t error;

    config = json_load_file(config_path, 0, &error);

    if(!config)
    {
        printf("Error reading config: on line %d: %s\n", error.line, error.text);
        exit(0);
    }

    return config;
}

json_t *get_json_object_from_json(json_t *root, char *field)
{
	/* Read json object from json config */
	json_t *value;

	value = json_object_get(root, field);

	if(!json_is_object(value))
	{
		printf("Error parsing json object: value of %s is not a json object\n", field);
		return NULL;
	}

	return value;
}

const char *get_string_value_from_json(json_t *root, const char *field)
{
	/* Read string value from json config */
	json_t *value;

	value = json_object_get(root, field);

	if(!json_is_string(value))
	{
		printf("Error parsing json object: value of %s field is not a string\n", field);
		exit(0);
	}

	return json_string_value(value);
}


int get_integer_value_from_json(json_t *root, char *field)
{
	/* Read integer value from json config */
	json_t *value;

	value = json_object_get(root, field);

	if(!json_is_integer(value))
	{
		printf("Error parsing json object: value of %s field is not an integer\n", field);
		exit(0);
	}

	return json_integer_value(value);
}


//********************************************************************************

//************************cidr part*********************************************
char *contained_in(char *dev_ip, const char *config_ip) {
	
 	CIDR *dev_ip_cidr, *config_ip_cidr;
 	char *str_dev_ip_cidr, *str_config_ip_cidr;

 	int cflags;
	cflags=CIDR_NOFLAGS;


	if(dev_ip==NULL || strlen(dev_ip)==0 || config_ip==NULL || strlen(config_ip)==0) {
		return NULL;
	}

	/* Parse 'em both */
	dev_ip_cidr = cidr_from_str(dev_ip);
	config_ip_cidr = cidr_from_str(config_ip);

	if(dev_ip_cidr==NULL || config_ip_cidr==NULL) {
		return NULL;
	}

	str_dev_ip_cidr = cidr_to_str(dev_ip_cidr, cflags);
	str_config_ip_cidr = cidr_to_str(config_ip_cidr, cflags);


	/* Are they even the same address family? */
	if(dev_ip_cidr->proto != config_ip_cidr->proto){
		free(str_dev_ip_cidr); 
		free(str_config_ip_cidr);
		cidr_free(dev_ip_cidr);
		cidr_free(config_ip_cidr);
		
		return NULL;
	}

	/* dev_ip_cidr inside config_ip_cidr? */
	if(cidr_contains(config_ip_cidr, dev_ip_cidr)==0){
		free(str_dev_ip_cidr); 
		free(str_config_ip_cidr);
		cidr_free(dev_ip_cidr);
		cidr_free(config_ip_cidr);
		
		return strdup(config_ip);
	}

	/* config_ip_cidr inside dev_ip_cidr? */
	if(cidr_contains(dev_ip_cidr, config_ip_cidr)==0){
		free(str_dev_ip_cidr); 
		free(str_config_ip_cidr);
		cidr_free(dev_ip_cidr);
		cidr_free(config_ip_cidr);
		
		return strdup(config_ip);
	}
	return NULL;
	/* NOTREACHED */

}



char* get_config_ip(char *dev_ip, json_t *client_map) {
	const char *config_ip;

	/*	Check if dev_ip already present in the config */
	json_t *dev_config = json_object_get(client_map,dev_ip);
	if(dev_config!=NULL){
		return dev_ip;
		}

	/* if dev_ip not present in config, check for the corresponding cidr addresses */
	void *iter_cidr = json_object_iter(client_map);
	while(iter_cidr) {
	    config_ip = json_object_iter_key(iter_cidr);
	    if(contained_in(dev_ip, config_ip)) {
	    	return strdup(config_ip);
	    }
	    /* next iter_cidr */
	    iter_cidr = json_object_iter_next(client_map, iter_cidr);
	}
	return NULL;
}

//*********************************************************************************************
void *get_collector_out_socket(){
    /* returns collector_out socket*/
    int major, minor, patch;
	zmq_version (&major, &minor, &patch);

#ifdef DEBUG
	printf ("Current 0MQ version is %d.%d.%d\n", major, minor, patch);
#endif
    
    // void *context = zmq_ctx_new();      //zmq 3.3
    void *context = zmq_init(1);        //zmq 2.2

	void *sender = zmq_socket(context, ZMQ_PUSH);
	assert (sender);

    int rc = zmq_connect (sender, "tcp://localhost:5502");
	assert (rc == 0);

//  Wait for the worker to connect so that when we send a message
//  with routing envelope, it will actually match the worker.
//    sleep (1);

	return sender;
}


char *inl_get_message_id(char *dev_ip, long col_ts, long counter){
    char *mid = (char *) malloc(100);
    memset(mid, 0, 100);
    sprintf(mid, "%s|%s|%s|%010ld|%06ld", lp_name, col_type, dev_ip, col_ts, log_counter );
    return mid;
}



json_t* collector_create_event(char* mesg_line,json_t* param ){
	json_t *event;

	char *_type_ip, *_type_str, *_type_num;

	_type_ip = "device_ip";
	_type_str = "msg device_name collected_at device_ip col_type";

	_type_num = malloc(sizeof(char)* 100);
	strcpy(_type_num, "col_ts");

	long col_ts;
	time_t now;
	now = time(0);
	col_ts = (long)now;

	if(col_ts > last_col_ts){
		last_col_ts = col_ts;
		log_counter = 0;
	}

	log_counter += 1;

	char *mid;
	
	char *device_name = get_string_value_from_json(param,"device_name");
	//json_t *dev_ip = get_json_object_from_json(param,"device_ip");
	mid = inl_get_message_id(NULL, col_ts, log_counter);

	event = json_object();
    json_object_set_new(event, "msg", json_string(mesg_line));
    json_object_set_new(event, "device_name", json_string(device_name));
    //json_object_set_new(event, "device_ip", json_string(dev_ip));
    json_object_set_new(event, "mid", json_string(mid));
    json_object_set_new(event, "collected_at", json_string(lp_name));
	json_object_set_new(event, "col_ts", json_integer(col_ts));
	json_object_set_new(event, "_counter", json_integer(log_counter));
	json_object_set_new(event, "col_type", json_string(col_type));


	json_object_set_new(event, "_type_num", json_string(_type_num));
	json_object_set_new(event, "_type_str", json_string(_type_str));
    json_object_set_new(event, "_type_ip", json_string(_type_ip));
   	free(_type_num);

	#if 0
	char *json_st;
    json_st = json_dumps(event, JSON_INDENT(4));
    printf("\nEvent is: %s\n", json_st);
    free(json_st);
	#endif

	return event;

}




void send_event_with_mid(void *sender, json_t *event, const char *normalizer, const char *repo){
	/* sends event to upper layer using sender socket*/
	char *event_st;
	printf("\n\n\n\nCrashing in json_dumps after this");
	event_st = json_dumps(event, JSON_COMPACT);
	printf("\n\n\n\n\n\nEvent is = %s",event_st);
    

    int str_len = strlen(normalizer) + strlen("\n") + strlen(repo) + strlen("\n") + strlen(event_st) + 1;

    char *event_with_mid = (char *) malloc(str_len);
	memset(event_with_mid, 0, str_len);
    sprintf(event_with_mid, "%s%s%s%s%s", normalizer, "\n", repo, "\n", event_st );

    

    zmq_send(sender, event_with_mid, strlen(event_with_mid), 0);

   
    free(event_st);
    free(event_with_mid);
}



void set_rcv_buf(int sockfd, int new_rcvbuff, int set_rcv_buf)
{
    int rcvbuff;

    socklen_t optlen;
    int res = 0;

    // Get buffer size
    optlen = sizeof(rcvbuff);
    res = getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuff, &optlen);

    if(res == -1)
     printf("\n\nError getsockopt one");
    else
     printf("\n\nreceive buffer size = %d\n", rcvbuff);

    
    if(set_rcv_buf==1)
    {
        printf("\n\nsets the receive buffer to %d\n", new_rcvbuff);
        res = setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &new_rcvbuff, sizeof(new_rcvbuff));
    }

    if(res == -1)
     printf("Error setsockopt");


    // Get buffer size
    optlen = sizeof(rcvbuff);
    res = getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuff, &optlen);

    if(res == -1)
     printf("\n\nError getsockopt two");
    else
     printf("\n\nreceive buffer size = %d\n", rcvbuff);
}

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



char *get_ip(char *dev_ip) {    
	int rc;    int ip_len=strlen(dev_ip);    
	if (ip_len < 8){        
		return strdup(dev_ip);    
	}    
	char mapping_prefix[8];    
	strncpy(mapping_prefix, dev_ip, 7);    
	mapping_prefix[7]= '\0';    
	//    char *ip = NULL;    
	rc = strcmp(mapping_prefix, MAPPED_IPV4_PREFIX);        
	if (!rc && is_dot_present(dev_ip)) {        
		char *ip = (char *)malloc(sizeof(char) *(ip_len-7+1)); /*1 for terminating null character */   
		strncpy(ip, &dev_ip[7], ip_len-7);        
		ip[ip_len - 7] = '\0';        
		return ip;    
	} else{        
		return strdup(dev_ip);
	}
}


void set_config_parameters() {
	config = get_json_from_config_file(config_path);

	client_map = get_json_object_from_json(config, "client_map");
	col_type = get_string_value_from_json(config, "col_type");
	lp_name = get_string_value_from_json(config, "loginspect_name");
	port = get_integer_value_from_json(config, "port");
}

void sighup(){
    signal(SIGHUP, sighup); /* reset signal */
    set_config_parameters(); /* reload config parameters */
}


#if 0
void initialize_collector_array(){
	if(TCP){
		 g_array_append_val(array_of_collectors, "TCP");
		 printf("\nTCP\n");
		count++;
	}
	if(UDP){
		g_array_append_val(array_of_collectors, "UDP");
		printf("\nUDP\n");
		count++;
	}
	if(SSL){
		g_array_append_val(array_of_collectors, "SSL");
		printf("\nSSL\n");
		count++;
	}
}
#endif

int setup_socket(int portnum){
   int sock, flags, yes=1;
    struct sockaddr_in6 addr;

    if ((sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        printf("\nError creating TCP socket\n");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(portnum);

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    if (bind(sock, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        printf("\nError binding to TCP port %d\n",portnum);
        return -1;
    }

    if (listen(sock, MAX_BACKLOG) < 0) {
        printf("\nError creating TCP listener on port %d\n",portnum);
        return -1;
    }

    if ((flags = fcntl(sock, F_GETFL, 0)) < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        printf("\nError in fcnt in TCP collector \n");
    }
    return sock;
}



int echo(int sock, char* device_ip) {
	/* Get as function arguments*/
    char buf[RCVBUFSIZE];
    size_t len;

    if ((len = recv(sock, buf, RCVBUFSIZE, 0)) < 0) {
    	printf("\nError accepting data from client");
        return -1;
    }

    if (len == 0) {
        return -1;
    }
    buf[len]='\0';
    
    /* Handle received message */
    printf("\nReceived message = %s\n", buf);

    /** check for the cidr address for config_ip **/
    char *config_ip;
    config_ip = get_config_ip(device_ip, client_map);
    printf("\n\nThe config ip for dev_ip:%s is :%s\n", device_ip, config_ip);
    if (config_ip == NULL) {
        printf("\nConnection attempted from unregistered IP : %s\n", device_ip);
        return;
    }

    json_t *dev_config;
    dev_config = get_json_object_from_json(client_map, config_ip);
    if (dev_config==NULL) {
        printf("\n\nConnection attempted from unregistered IP : %s\n", device_ip);
        return;
    }

	void (*callback_tcp)(char*,json_t*);
   	callback_tcp = (void *)handle_tcp_data_cb;
   	/* Call the function */
   	(*callback_tcp)(buf,dev_config);
   printf("\ncallback TCP\n");
   return len;
}


void event_tcp_client_cb(EV_P_ struct ev_io *w, int revents) {
    struct sock_ev_client_tcp* client = (struct sock_ev_client_tcp*) w;
    if (echo(client->fd, client->device_ip) < 1) {
        close(client->fd);
        ev_io_stop(EV_A_ &client->io);
        free(client);
    }
}

void event_tcp_server_cb(EV_P_ struct ev_io *w, int revents) {
    int sock, flags;
    struct sockaddr_in6 addr;
    socklen_t len = sizeof(addr);

    int client_fd;
    struct sock_ev_serv_tcp* server = (struct sock_ev_serv_tcp*) w;
    server->socket_len = len;

    for (;;) {
        if ((client_fd = accept(server->fd, (struct sockaddr*) &addr, &len)) < 0) {
            switch (errno) {
            case EINTR:
            case EAGAIN:
                break;
            default:
            	printf("\nError accepting connection from client \n");
            }
            break;
        }
        char ip[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &addr.sin6_addr, ip, INET6_ADDRSTRLEN);
		char *dev_ip = get_ip(ip);
        server->device_ip = dev_ip;

        printf("\n\nThe obtained ip is %s and dev_ip is %s\n", ip, dev_ip);

        /** check for the cidr address for config_ip **/
        char *config_ip;
        config_ip = get_config_ip(dev_ip, client_map);
        printf("\n\nThe config ip for dev_ip:%s is :%s\n", dev_ip, config_ip);
        if (config_ip == NULL) {
            printf("\n\nConnection attempted from unreigistered IP: %s\n", dev_ip);
            printf("\n\nConnection attempted from unregistered IP : %s\n", dev_ip);
            continue;
        }

        json_t *dev_config;
        dev_config = get_json_object_from_json(client_map, config_ip);
        if (dev_config==NULL) {
            printf("\n\nConnection attempted from unreigistered IP: %s\n", dev_ip);
            printf("\n\nConnection attempted from unregistered IP : %s\n", dev_ip);
            continue;
        }

        if ((flags = fcntl(client_fd, F_GETFL, 0)) < 0 || fcntl(client_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            printf("\nfcntl(2)");
        }


        struct sock_ev_client_tcp* client = malloc(sizeof(struct sock_ev_client_tcp));
        client->device_ip = dev_ip;
        client->server = server;
        client->fd = client_fd;

        ev_io_init(&client->io, event_tcp_client_cb, client_fd, EV_READ);
        ev_io_start(EV_DEFAULT, &client->io);
    }
}


void ShutdownSSL(SSL *ssl){
    SSL_shutdown(ssl);
    SSL_free(ssl);
}



print_ssl_error(const SSL *ssl, int sslerr){
     int rc = SSL_get_error(ssl,sslerr);
     switch(rc){
        case SSL_ERROR_NONE:
            printf("\nSSL_ERROR_NONE");
            break;
        case SSL_ERROR_ZERO_RETURN:
            printf("\nSSL_ERROR_ZERO_RETURN");
            break;
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            printf("\nSSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE");
            break;
        case SSL_ERROR_WANT_CONNECT:
        case SSL_ERROR_WANT_ACCEPT:
            printf("\nSSL_ERROR_WANT_CONNECT,SSL_ERROR_WANT_ACCEPT");
            break;
        case SSL_ERROR_WANT_X509_LOOKUP:
            printf("\nSSL_ERROR_WANT_X509_LOOKUP");
            break;        
        case SSL_ERROR_SYSCALL:
            printf("\nSSL_ERROR_SYSCALL");
            break;
        case SSL_ERROR_SSL:
            printf("\nSSL_ERROR_SSL");
            break;
        default:
            printf("\ndefault");
            break;
     }
}

void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents){
    struct sock_ev_with_ssl* client = (struct sock_ev_with_ssl*) watcher;
    SSL *cSSL = client->cSSL;
    char *device_ip = client->device_ip;
    
    char buf[RCVBUFSIZE];
    ssize_t len;

    if(EV_ERROR & revents){
      printf("\n\ngot invalid event");
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
    printf("\nThe config ip for dev_ip:%s is :%s\n", device_ip, config_ip);
    if (config_ip == NULL) {
        printf("\nConnection attempted from unregistered IP : %s\n", device_ip);
        return;
    }

    json_t *dev_config;
    dev_config = get_json_object_from_json(client_map, config_ip);
    if (dev_config==NULL) {
        printf("\nConnection attempted from unregistered IP : %s\n", device_ip);
        return;
    }
	printf("\n\necho SSL\n\n");
	void (*callback_ssl)(char*);
   	callback_ssl = (void *)handle_ssl_data_cb;
   	/* Call the function */
   	(*callback_ssl)(buf);
	printf("\ncallback SSL\n");
}



void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{   
    int flags;
    struct sock_ev_with_ssl* ev_ssl = (struct sock_ev_with_ssl*) watcher;
    SSL *cSSL = ev_ssl->cSSL;

    struct sockaddr_in6 addr;
    socklen_t len = sizeof(addr);
    int client_fd;

    if(EV_ERROR & revents){
      printf("\ngot invalid event");
      return;
    }

    // Accept client request
    client_fd = accept(watcher->fd, (struct sockaddr *)&addr, &len);

    if (client_fd < 0){
      printf("\nError accepting connection from client");
      return;
    }

    char ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &addr.sin6_addr, ip, INET6_ADDRSTRLEN);
    char *dev_ip = get_ip(ip);
    printf("\nThe obtained ip is %s and dev_ip is %s\n", ip, dev_ip);

    //ssl
    int rc = SSL_set_fd(cSSL, client_fd ); //connect the SSL object with a file descriptor
    if(rc==0)
        printf("\nSSL_set_fd failed\n");
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





int LoadCertificates(SSL_CTX* sslctx,const char* crtfile,const char* keyfile)
{
    int use_cert = SSL_CTX_use_certificate_file(sslctx, crtfile , SSL_FILETYPE_PEM);
    if(use_cert!=1)
    {
        printf("\ncert file error. Path: %s",crtfile);
        return -1;
    }
    int use_prv = SSL_CTX_use_PrivateKey_file(sslctx, keyfile, SSL_FILETYPE_PEM);
    if(use_prv!=1)
    {
        printf("\nprivatekey file error. Path: %s",keyfile);
        return -1;
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(sslctx) )
    {
        printf("\nPrivate key does not match the public certificate\n");
        return -1;
    }
    return 0;
}




void InitializeSSL()
{
    SSL_load_error_strings(); //registers the error strings for all libcrypto functions
    SSL_library_init(); //registers the available SSL/TLS ciphers and digests
    OpenSSL_add_all_algorithms(); //adds all algorithms to the table (digests and ciphers). 
}


void *start_ssl_collector_cb()
{
    int fd =setup_socket(ssl_port);
    if(fd<0)
        return NULL;
   
    struct ev_loop *loop = ev_loop_new(EVBACKEND_EPOLL | EVFLAG_NOENV);

    InitializeSSL();
    SSL_CTX *sslctx = SSL_CTX_new( SSLv23_server_method()); //SSLv23_server_method() indicates
    //application is a server and supports 
    //Secure Sockets Layer version 2 (SSLv2), Secure Sockets Layer version 3 (SSLv3), and Transport Layer Security version 1 (TLSv1).
    if(sslctx == NULL){
        printf("\n\nCannot create SSL context");
        return NULL;
    } 
    SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE); //all this negotiation is done using ephemeral keying.
    
    int rc = LoadCertificates(sslctx,ssl_certfile,ssl_keyfile);
    if(rc == -1){
        printf("\n\n Could not start SSL ");
        return NULL;
    }
    SSL *cSSL = SSL_new(sslctx); //creates a new SSL structure which is needed to hold the data for a TLS/SSL connection.
    if(cSSL == NULL){
        printf("\n\nCannot create SSL structure");
        return NULL;
    }

    struct sock_ev_with_ssl* ev_ssl = malloc(sizeof(struct sock_ev_with_ssl));
    ev_ssl->cSSL = cSSL;

    ev_io_init(&ev_ssl->io, accept_cb, fd, EV_READ);
    ev_io_start(loop,&ev_ssl->io);
    printf("\n\nTCP SSL Server started at port: %d",ssl_port);
    ev_loop(loop, 0);

    return 0;
}


void *start_udp_collector_cb() {
   	int sd, rc, n;
	struct sockaddr_in6 client_addr, server_addr;
	sd = socket(AF_INET6, SOCK_DGRAM, 0);
	if(sd<0) {
		printf("\ncannot open socket \n");
		exit(1);
	}
	set_rcv_buf(sd,pow(2,23),1);
	
	server_addr.sin6_family = AF_INET6;
	server_addr.sin6_addr = in6addr_any;
	server_addr.sin6_port = htons(port);
	rc = bind (sd, (struct sockaddr *) &server_addr,sizeof(server_addr));
	if(rc<0) {
		printf("\ncannot bind port \n");
		exit(1);
	}
	while(1) {
		unsigned char *msg =(unsigned char *)malloc(sizeof(char)*RCVBUFSIZEUDP);
		memset(msg, 0x0, RCVBUFSIZEUDP);
	
		socklen_t cliLen = (socklen_t)sizeof(client_addr);		
		n = recvfrom(sd, msg, RCVBUFSIZEUDP, 0, (struct sockaddr *) &client_addr, &cliLen);
		printf("\nmessage received\n\n");
	
		if(n<0) {
			printf("\ncannot receive data \n");
			free(msg);
			continue;
		}
		char ip[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &client_addr.sin6_addr, ip, INET6_ADDRSTRLEN);
		char *dev_ip = get_ip(ip);
		printf("\ndev_ip = %s\n\n",dev_ip);
					
		/*check for the cidr address for config_ip */
		char *config_ip;
		config_ip = get_config_ip(dev_ip, client_map);
		printf("\nconfig_ip = %s\n\n",config_ip);
		if (config_ip == NULL) {
			printf("\nConnection attempted from unregistered IP : %s\n");
			continue;
		}
					
		json_t *dev_config;
		dev_config = get_json_object_from_json(client_map, config_ip);
		if (dev_config==NULL) {
			printf("\nConnection attempted from unregistered IP : %s\n");
			continue;
		}
		void (*callback)(unsigned char*,json_t*);
		callback = (void *)handle_udp_data_cb;	
		/* Call the function */
		(*callback)(msg,dev_config);
		printf("\ncallback UDP\n");
		free(msg);
}
}




void *start_tcp_collector_cb() {
    printf("\nTCP Server started at port: %d",port);
    int fd =setup_socket(port);
    if(fd<0)
    {
        return NULL;
    }
    struct ev_loop *loop = EV_DEFAULT;
    struct sock_ev_serv_tcp server;
    server.fd = fd;
    ev_io_init(&server.io, event_tcp_server_cb, server.fd, EV_READ);
    ev_io_start(EV_A_ &server.io);
    ev_loop(loop, 0);
    return 0;
}


void start_collector(){
    set_config_parameters();
    signal(SIGHUP,sighup);
    pthread_t udp_thread,ssl_thread,tcp_thread;
    
    if(count !=0){
        if(count == 3){
            // run in thread.
            printf("\n\nTCP UDP SSL\n\n");
            pthread_create(&udp_thread, NULL,start_udp_collector_cb, NULL);
            pthread_create(&ssl_thread, NULL,start_ssl_collector_cb, NULL);
            pthread_create(&tcp_thread, NULL,start_tcp_collector_cb, NULL);
        }else if(count == 2){
            //run in thread
            if(tcp && udp){
                pthread_create(&tcp_thread, NULL,start_tcp_collector_cb, NULL);
                pthread_create(&udp_thread, NULL,start_udp_collector_cb, NULL);
                printf("\n\nTCP and UDP");
            }else if(tcp && ssl){
                printf("\n\nTCP and SSL");
                pthread_create(&tcp_thread, NULL,start_tcp_collector_cb, NULL);
                pthread_create(&udp_thread, NULL,start_ssl_collector_cb, NULL);
            }else {
                printf("\n\nSSL and UDP");
                pthread_create(&udp_thread, NULL,start_udp_collector_cb, NULL);
                pthread_create(&ssl_thread, NULL,start_ssl_collector_cb, NULL);
            }
        }else{
            if(tcp){
                printf("\n\nTCP only\n");
                pthread_create(&tcp_thread, NULL,start_tcp_collector_cb, NULL);
            }else if(udp){
                printf("\n\nUDP only\n");
                pthread_create(&udp_thread, NULL,start_udp_collector_cb, NULL);
            }else{
                printf("\n\nSSL only\n");
                pthread_create(&ssl_thread, NULL,start_ssl_collector_cb, NULL);
            }
        }
    while(1)
        sleep(5);
        //run in main process in while loop.
    }else
    printf("\n\n No collector started\n\n");
}

