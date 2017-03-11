#include "collector_main.h"

void lplog_init()
{
    lplog_context_t *c = NULL;
    if (lplog_context_global == NULL)
        lplog_context_global=calloc(1,sizeof(lplog_context_t));
    c=lplog_context_global;
    if(c->logbuf==NULL)
        c->logbuf=calloc(MAX_LOGBUFFER_SIZE,sizeof(char));
    if(c->va_logbuf==NULL)
        c->va_logbuf=calloc(MAX_LOGBUFFER_SIZE,sizeof(char));
}

void lplog_exit()
{
    lplog_context_t *c=lplog_context_global;
    AFREE(c->logbuf);
    c->logbuf=NULL;
    AFREE(c->va_logbuf);
    c->va_logbuf=NULL;
    AFREE(c);
    c=NULL;
}

void _lplog(const char *_FILE, int _LINE, const char *_func,  char *fmt, ...) 
{
    lplog_context_t *c = lplog_context_global;
    va_list ap;
    va_start(ap,fmt);
    vsnprintf(c->va_logbuf, MAX_LOGBUFFER_SIZE, fmt, ap);
    va_end(ap);
    snprintf(c->logbuf,MAX_LOGBUFFER_SIZE,"(%s:%d:%s):",
             _FILE,_LINE,_func);
    fprintf(stderr,"%s%s\n",c->logbuf,c->va_logbuf);
}

/*! \fn  void dbg_j(json_t *json)
 *         \break use this method in gdb to debug json_t object eg (gdb)call debug_print_json(jsonobject)
 *                 \param json input json
 *                 */
void dbg_j(json_t *json)
{
        if(json!=NULL)
        {
                int type =json_typeof(json);
		if(type==JSON_STRING)
		{
			printf("json is string\n");
			printf("%s\n",json_string_value(json));
			return;
		}
                else if(type==JSON_OBJECT)
                        printf("json is object\n");
                else if (type==JSON_ARRAY)
                        printf("json is array\n");
                char * str_json =json_dumps(json,0);
                printf("%s\n",str_json);
                free(str_json);
        }
        else
        {
                printf("NULL json\n");
        }
}
//******************cidr********************

static char *contained_in(char *dev_ip, const char *config_ip) {
	
 	CIDR *dev_ip_cidr, *config_ip_cidr;
 	char *str_dev_ip_cidr, *str_config_ip_cidr;

 	int cflags;
	cflags=CIDR_NOFLAGS;


	if(dev_ip==NULL || strlen(dev_ip)==0 || config_ip==NULL || strlen(config_ip)==0) {
		// lplog("Error: Can't get cidr-block's from your input!\n");
		return NULL;
	}

	/* Parse 'em both */
	dev_ip_cidr = cidr_from_str(dev_ip);
	config_ip_cidr = cidr_from_str(config_ip);

	if(dev_ip_cidr==NULL || config_ip_cidr==NULL) {
		// lplog("Error: Can't parse cidr-blocks: '%s' and '%s'\n",dev_ip,  config_ip);
		return NULL;
	}

	str_dev_ip_cidr = cidr_to_str(dev_ip_cidr, cflags);
	str_config_ip_cidr = cidr_to_str(config_ip_cidr, cflags);

	/*
	 * OK, now we've got 'em.  Start some comparisons.
	 * Note that none of the following is an _error_; they're all
	 * answers.
	 */
#define PROTOSTR(x) (((x)->proto==CIDR_IPV4)?"IPv4":"IPv6")

	/* Are they even the same address family? */
	if(dev_ip_cidr->proto != config_ip_cidr->proto)
	{
		// lplog("Blocks are different address families:\n"
		//        "  - '%s' is %s\n"
		//        "  - '%s' is %s\n",
		//        str_dev_ip_cidr, PROTOSTR(dev_ip_cidr),
		//        str_config_ip_cidr, PROTOSTR(config_ip_cidr));
		
		free(str_dev_ip_cidr); 
		free(str_config_ip_cidr);
		cidr_free(dev_ip_cidr);
		cidr_free(config_ip_cidr);
		
		return NULL;
	}

	/* dev_ip_cidr inside config_ip_cidr? */
	if(cidr_contains(config_ip_cidr, dev_ip_cidr)==0)
	{
		// lplog("%s block '%s' is wholly contained within '%s'\n",
		// 		PROTOSTR(dev_ip_cidr), str_dev_ip_cidr, str_config_ip_cidr);

		free(str_dev_ip_cidr); 
		free(str_config_ip_cidr);
		cidr_free(dev_ip_cidr);
		cidr_free(config_ip_cidr);
		
		return strdup(config_ip);
	}

	/* config_ip_cidr inside dev_ip_cidr? */
	if(cidr_contains(dev_ip_cidr, config_ip_cidr)==0)
	{
		// lplog("%s block '%s' is wholly contained within '%s'\n",
		// 		PROTOSTR(dev_ip_cidr), str_config_ip_cidr, str_dev_ip_cidr);

		free(str_dev_ip_cidr); 
		free(str_config_ip_cidr);
		cidr_free(dev_ip_cidr);
		cidr_free(config_ip_cidr);
		
		return strdup(config_ip);
	}

	/* Otherwise, they're totally unrelated */
	// lplog("%s blocks '%s' and '%s' don't intersect.\n",
	// 		PROTOSTR(dev_ip_cidr), str_config_ip_cidr, str_dev_ip_cidr);
	return NULL;
	/* NOTREACHED */

}

char* collector_get_config_ip(char *dev_ip, json_t *client_map) {
	const char *config_ip;

	/** Check if dev_ip already present in the config **/
	void *iter_ip = json_object_iter(client_map);
	while(iter_ip) {
	    config_ip = json_object_iter_key(iter_ip);
	    if(!strcmp(dev_ip, config_ip)) {
	    	return strdup(config_ip);
	    }
	    /** next iter_ip **/
	    iter_ip = json_object_iter_next(client_map, iter_ip);
	}

	/** if dev_ip not present in config, check for the corresponding cidr addresses **/
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

void collector_send_event_with_mid(void *sender, json_t *event, const char *normalizer, const char *repo){
	/* sends event to upper layer using sender socket*/
	char *event_st;
	event_st = json_dumps(event, JSON_COMPACT);
    

    int str_len = strlen(normalizer) + strlen("\n") + strlen(repo) + strlen("\n") + strlen(event_st) + 1;

    char *event_with_mid = (char *) malloc(str_len);
	memset(event_with_mid, 0, str_len);
    sprintf(event_with_mid, "%s%s%s%s%s", normalizer, "\n", repo, "\n", event_st );

    
#ifndef BENCHMARK
    /** zmq 3.3 **/
    zmq_send(sender, event_with_mid, strlen(event_with_mid), 0);
#endif
    free(event_st);
    free(event_with_mid);
}
//**************************************
//********************create json*************

/* callback function for onigumara regex matching */
int name_callback(const OnigUChar *name, const OnigUChar *end, int ngroups, int *group_list,
					OnigRegex re, void *arg) {
	struct syslog_data *d = (struct syslog_data *)arg;

	OnigRegion *region = d->region;
	UChar *str = d->str;

	int num = onig_name_to_backref_number(re, name, end, region);

	//char *value = (char *)calloc(25, sizeof(char));
	//sprintf(value, "%.*s", region->end[num] - region->beg[num], (str + region->beg[num]));

	char *value = (char *) malloc(25);
	memset(value, 0, 25);
	sprintf(value, "%.*s", region->end[num] - region->beg[num], (str + region->beg[num]));

	if(strcmp(value, "") != 0){
		if(strcmp((char *)name, "pri") == 0)
		{
			d->pri = atoi(value);
			free(value);
		}
		else if(strcmp((char *)name, "year") == 0)
			d->year = value;
		else if(strcmp((char *)name, "log_time") == 0)
			d->date_time = value;
		else
			free(value);
	}
	else
	{
		free(value);
	}
	return 0;
}

struct syslog_data * collector_parse_syslog_message(char *message, OnigRegex re , OnigRegion *region) {
	int r = onig_search(re, (UChar *)message, (UChar *)(message + strlen(message)), (UChar *)message,
						(UChar *)(message + strlen(message)), region, ONIG_OPTION_NONE);

	struct syslog_data *d = (struct syslog_data *)malloc(sizeof(struct syslog_data));
	d->region = region;
	d->str = (UChar*)message;
	d->pri = 0;
	d->year = NULL;
	d->date_time = NULL;

	/* match found */
	if (r >= 0) {
		onig_foreach_name(re, name_callback, (void *)(d));
	}

	return d;
}

json_t *collector_create_json_object(OnigRegex re , OnigRegion *region, const char *lp_name, char *message, char *dev_ip, json_t *dev_config,
						char *mid, long col_ts, long log_counter, const char *col_type) {
	/* create an event to send to upper layer*/
	char *_type_ip, *_type_str, *_type_num;
    const char *device_name;

	_type_ip = "device_ip";
	_type_str = "msg device_name collected_at device_ip col_type mid";

	_type_num = malloc(sizeof(char)* 100);
	strcpy(_type_num, "col_ts");

    device_name = collector_get_string_value_from_json(dev_config, "device_name");

    json_t *event;

    event = json_object();
    json_object_set_new(event, "msg", json_string(message));
    json_object_set_new(event, "device_name", json_string(device_name));
    json_object_set_new(event, "device_ip", json_string(dev_ip));
    json_object_set_new(event, "mid", json_string(mid));
    json_object_set_new(event, "collected_at", json_string(lp_name));
	json_object_set_new(event, "col_ts", json_integer(col_ts));
	json_object_set_new(event, "_counter", json_integer(log_counter));
	json_object_set_new(event, "col_type", json_string(col_type));

    struct syslog_data *d;
    d = collector_parse_syslog_message(message, re, region);

	if(d->pri != 0){
		int sev, fac;
		sev = d->pri / 10;
		fac = d->pri % 10;

		json_object_set_new(event, "severity", json_integer(sev));
		json_object_set_new(event, "facility", json_integer(fac));

		strcat(_type_num, " severity facility");

	}

	if(d->date_time){
		if(d->year){
			struct tm tm;
			time_t epoch = 0;
			if (strptime(d->date_time, "%b %d %Y %H:%M:%S", &tm) != 0){
				epoch = mktime(&tm);
				json_object_set_new(event, "log_ts", json_integer((int)epoch));
				strcat(_type_num, " log_ts ");
			}
	    }
		else{
			time_t curr_time;
			time(&curr_time);
			struct tm *ltm= localtime(&curr_time);

			char *dt_with_year = (char *) malloc(50);
			memset(dt_with_year, 0, 50);
			sprintf(dt_with_year, "%d %s", 1900+ltm->tm_year, d->date_time);

			struct tm tm;
			time_t epoch = 0;
			if (strptime(dt_with_year, "%Y %b %d %H:%M:%S", &tm) != 0){
				epoch = mktime(&tm);
				json_object_set_new(event, "log_ts", json_integer((int)epoch));
				strcat(_type_num, " log_ts");
			}
			free(dt_with_year);
	    }
	}


	json_object_set_new(event, "_type_num", json_string(_type_num));
	json_object_set_new(event, "_type_str", json_string(_type_str));
    json_object_set_new(event, "_type_ip", json_string(_type_ip));
   	free(_type_num);

	if(d){
		if(d->year)
			free(d->year);
		if(d->date_time)
			free(d->date_time);
		free(d);
	}

#ifdef DEBUG
    char *json_st;
    json_st = json_dumps(event, JSON_INDENT(4));
    printf("Event is: %s\n", json_st);
    free(json_st);
#endif

    return event;
}

//***************************************************
//****************config reader***********************
json_t *collector_get_json_from_config_file(char *config_path) {
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


const char *collector_get_string_value_from_json(json_t *root,char *field)
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

int collector_get_integer_value_from_json(json_t *root, char *field)
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

json_t *collector_get_json_object_from_json(json_t *root, char *field)
{
	/* Read json object from json config */
	json_t *value;

	value = json_object_get(root, field);

	if(!json_is_object(value))
	{
		printf("Error parsing json object: value of %s is not a json object\n", field);
		zlog_info(c, "Connection attempted from unreigistered IP: %s\n", field);
		return NULL;
	}

	return value;
}
//**********************************************

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

    /* Handle received message */
#ifdef DEBUG
    printf("Received message = %s\n", buf);
    printf("The device ip obtained in event client is here : :HAH :%s\n", device_ip);
#endif
    

    /** check for the cidr address for config_ip **/
    char *config_ip;
    config_ip = collector_get_config_ip(device_ip, params.client_map);
    lplog("The config ip for dev_ip:%s is :%s\n", device_ip, config_ip);
    if (config_ip == NULL) {
        lplog("Connection attempted from unreigistered IP: %s\n", device_ip);
        zlog_info(c, "Connection attempted from unregistered IP : %s\n", device_ip);
        return -1;
    }

    json_t *dev_config;
    dev_config = collector_get_json_object_from_json(params.client_map, config_ip);
    if (dev_config==NULL) {
        lplog("Connection attempted from unreigistered IP: %s\n", device_ip);
        zlog_info(c, "Connection attempted from unregistered IP : %s\n", device_ip);
        return -1;
    }

#ifdef DEBUG
        printf("Connection from device ip = %s\n", device_ip);
#endif
    collector_parse_message_line_by_line(buf, device_ip, dev_config);

#ifdef BENCHMARK
    /* send message back to client */
	if (send(sock, buf, len, 0) < 0) {
		perror("send(2)");
		return -1;
	}
#endif
	
    return len;
}



void collector_event_client_cb(EV_P_ struct ev_io *w, int revents) {
    struct sock_ev_client* client = (struct sock_ev_client*) w;
    if (echo(client->fd, client->device_ip) < 1) {
        close(client->fd);
        ev_io_stop(EV_A_ &client->io);
        free(client);
    }
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


char *collector_get_ip(char* dev_ip) {
    int rc;
    if (strlen(dev_ip) < 8) {
        return dev_ip;
    }
    char mapping_prefix[8];
    strncpy(mapping_prefix, dev_ip, 7);
    mapping_prefix[7]= '\0';
    int ip_len = strlen(dev_ip);
    char *ip = malloc(sizeof(char) *(ip_len-7));
    rc = strcmp(mapping_prefix, MAPPED_IPV4_PREFIX);
    
    if (!rc && is_dot_present(dev_ip)) {
        strncpy(ip, &dev_ip[7], ip_len-7);
        ip[ip_len - 7] = '\0';
        return ip;
    } else {
        return dev_ip;
    }
    
}


void collector_event_server_cb(EV_P_ struct ev_io *w, int revents) {
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
			char *dev_ip = collector_get_ip(ip);
			server->device_ip = dev_ip;
	
			lplog("The obtained ip is %s and dev_ip is %s\n", ip, dev_ip);
	
			/** check for the cidr address for config_ip **/
			char *config_ip;
			config_ip = collector_get_config_ip(dev_ip, params.client_map);
			lplog("The config ip for dev_ip:%s is :%s\n", dev_ip, config_ip);
			if (config_ip == NULL) {
				lplog("Connection attempted from unreigistered IP: %s\n", dev_ip);
				zlog_info(c, "Connection attempted from unregistered IP : %s\n", dev_ip);
				continue;
			}
	
			json_t *dev_config;
			dev_config = collector_get_json_object_from_json(params.client_map, config_ip);
			if (dev_config==NULL) {
				lplog("Connection attempted from unreigistered IP: %s\n", dev_ip);
				zlog_info(c, "Connection attempted from unregistered IP : %s\n", dev_ip);
				continue;
			}
	
#ifdef DEBUG
			printf("Connection fron device ip = %s\n", dev_ip);
#endif
			if ((flags = fcntl(client_fd, F_GETFL, 0)) < 0 || fcntl(client_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
				perror("fcntl(2)");
				return;
			}
	
	
			struct sock_ev_client* client = malloc(sizeof(struct sock_ev_client));
			client->device_ip = dev_ip;
			client->server = server;
			client->fd = client_fd;
	
			// ev_io *watcher = (ev_io*)calloc(1, sizeof(ev_io));
			ev_io_init(&client->io, collector_event_client_cb, client_fd, EV_READ);
			ev_io_start(EV_DEFAULT, &client->io);
		}
	}



void *collector_start_tcp_syslog_server_cb() {
    int sock, flags, yes=1;
    struct sockaddr_in6 addr;
    struct ev_loop *loop = EV_DEFAULT;

    if ((sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)) < 0) {
    	zlog_info(c, "Error creating TCP socket \n");
        exit(0);
    }

    memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_addr = in6addr_any;
	addr.sin6_port = htons(params.port);

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    if (bind(sock, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
    	zlog_info(c, "Error binding to TCP port \n");
        exit(0);
    }

    if (listen(sock, MAX_BACKLOG) < 0) {
    	zlog_info(c, "Error creating TCP listener \n");
        exit(0);
    }

    if ((flags = fcntl(sock, F_GETFL, 0)) < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
    	zlog_info(c, "Error in fcnt in TCP collector \n");
    }

#ifdef BENCHMARK
        if(cnt == 0){
            struct timeval start_time;
            gettimeofday(&start_time, NULL);
            
            printf("benchmark data: start_time tcp = \n");
            timeval_print(&start_time);
        }        
#endif

    struct sock_ev_serv server;
    server.fd = sock;
    ev_io_init(&server.io, collector_event_server_cb, server.fd, EV_READ);
    ev_io_start(EV_A_ &server.io);

    // ev_init(&watcher, event_server);
    // ev_io_set(&watcher, sock, EV_READ);
    // ev_io_start(loop, &watcher);
    ev_loop(loop, 0);
    return 0;
}


void collector_set_config_parameters() {
	config = collector_get_json_from_config_file(config_path);

	params.client_map = collector_get_json_object_from_json(config, "client_map");
	params.col_type = collector_get_string_value_from_json(config, "col_type");
	params.lp_name = collector_get_string_value_from_json(config, "loginspect_name");
	params.port = collector_get_integer_value_from_json(config, "port");
}
char *collector_get_message_id(char *dev_ip, long col_ts, long counter){
    char *mid = (char *) malloc(100);
    memset(mid, 0, 100);
    sprintf(mid, "%s|%s|%s|%010ld|%06ld", params.lp_name, params.col_type, dev_ip, col_ts, init.log_counter );
    return mid;
}


void collector_parse_message_line_by_line(char *msg, char *dev_ip, json_t *dev_config){
	/* Split message by new line */
	char *message;
	message = strtok (msg, "\n");
	while (message != NULL)
	{
		json_t *event;

		long col_ts;
		time_t now;
		now = time(0);
		col_ts = (long)now;

		if(col_ts > init.last_col_ts)
		{
			init.last_col_ts = col_ts;
			init.log_counter = 0;
		}

		init.log_counter += 1;

		char *mid;
		mid = collector_get_message_id(dev_ip, col_ts, init.log_counter);

		const char *normalizer;
		const char *repo;
		normalizer = collector_get_string_value_from_json(dev_config, "normalizer");
		repo = collector_get_string_value_from_json(dev_config, "repo");

		event = collector_create_json_object(re, region, params.lp_name, message, dev_ip, dev_config, mid, col_ts, init.log_counter, params.col_type);

		/* send message to upper layer */
		collector_send_event_with_mid(sender, event, normalizer, repo);

#ifdef BENCHMARK
    cnt += 1;
    if(cnt % 1000 == 0)
    {
    	struct timeval end_time;
		gettimeofday(&end_time, NULL);
		printf("benchmark data: count=%u, time= ", cnt);
		timeval_print(&end_time);
    }
#endif
		free(mid);
		json_decref(event);

		message = strtok (NULL, "\n");
	}
}

