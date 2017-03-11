#include "syslog_collector.h"

void sighup() {
    signal(SIGHUP, sighup); /* reset signal */
    collector_set_config_parameters(); /* reload config parameters */
}

static void set_rcv_buf(int sockfd, int new_rcvbuff, int set_rcv_buf)
{
    int rcvbuff;

    socklen_t optlen;
    int res = 0;

    // Get buffer size
    optlen = sizeof(rcvbuff);
    res = getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuff, &optlen);

    if(res == -1)
     printf("Error getsockopt one");
    else
     printf("receive buffer size = %d\n", rcvbuff);

    // Set buffer size
    //rcvbuff = 98304*8;
    //rcvbuff = 214748364;

    
    if(set_rcv_buf==1)
    {
        printf("sets the receive buffer to %d\n", new_rcvbuff);
        res = setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &new_rcvbuff, sizeof(new_rcvbuff));
    }

    if(res == -1)
     printf("Error setsockopt");


    // Get buffer size
    optlen = sizeof(rcvbuff);
    res = getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuff, &optlen);

    if(res == -1)
     printf("Error getsockopt two");
    else
     printf("receive buffer size = %d\n", rcvbuff);
}

int main(int argc, char *argv[]){
#ifdef LPLOG
    lplog_init();
#endif

	/* check argument passed to program */
	if(argv[1] == NULL)	{
		printf("A config file is expected as argument.\n");
		exit(1);
	}

	config_path = argv[1];
	int zrc;

	zrc = zlog_init("/opt/immune/storage/col/zlog.conf");
	if (zrc) {
		printf("Zlog init failed. \n");
		exit(1);
	}

	c = zlog_get_category("lp_cat");
	if (!c) {
		printf("Zlog: get category failed. \n");
		exit(1);
	}

	/* Reload config if SIGHUP signal is received */
	signal(SIGHUP, sighup);

	/* get collector out socket */
	sender = get_collector_out_socket();

	/* set parameters for syslog parser */
    OnigErrorInfo errinfo;

    char *pattern = strdup("\\s*(?:<(?<pri>\\d{1,3})>)?\\s*(?:(?<log_time>[a-zA-Z]{3}\\s+\\d{1,2}\\s+(?<year>\\d{4}\\s+)?\\d\\d:\\d\\d:\\d\\d))?");

    int r = onig_new(&re, (const OnigUChar *)pattern, (const OnigUChar *)(pattern + strlen(pattern)),
						ONIG_OPTION_DEFAULT, ONIG_ENCODING_UTF8, ONIG_SYNTAX_DEFAULT, &errinfo);

    region = onig_region_new();


    /* save config file data in memory*/
	collector_set_config_parameters();
#ifdef DEBUG
	printf("config_file_path  : %s\n", config_path);
	printf("col_type : %s\n", params.col_type);
	printf("logpoint_name : %s\n", params.lp_name);
	printf("port : %d\n", params.port);
	printf("This is the starting of all the chaos. \n ");
#endif

	zlog_info(c, "Starting Syslog TCP Server\n");

	/* Run TCP Server in thread */
	pthread_t tcp_thread;
	pthread_create(&tcp_thread, NULL, collector_start_tcp_syslog_server_cb, NULL);

	/* Syslog UDP Server */
	int sd, rc, n, cliLen;
	struct sockaddr_in6 client_addr, server_addr;
	char msg[RCVBUFSIZEUDP];

	sd = socket(AF_INET6, SOCK_DGRAM, 0);
	if(sd<0) {
		zlog_info(c, "Cannot open socket for UDP connection. \n");
		exit(1);
	}
	//setting max receiver buffer size 8388608 (8MB)
	set_rcv_buf(sd,pow(2,23),1);

	server_addr.sin6_family = AF_INET6;
	server_addr.sin6_addr = in6addr_any;
	server_addr.sin6_port = htons(params.port);
	rc = bind (sd, (struct sockaddr *) &server_addr,sizeof(server_addr));
	if(rc<0) {
		zlog_info(c, "Cannot bind port number %d\n", params.port);
		exit(1);
	}
	zlog_info(c, "Starting Syslog UDP Server \n");
	/* server infinite loop */
	while(1) {
		memset(msg, 0x0, RCVBUFSIZEUDP);

		cliLen = sizeof(client_addr);
		n = recvfrom(sd, msg, RCVBUFSIZEUDP, 0, (struct sockaddr *) &client_addr, &cliLen);

		if(n<0) {
			zlog_info(c, "Cannot receive data from client \n");
			continue;
		}

#ifdef BENCHMARK
        if(cnt == 0){
            struct timeval start_time;
            gettimeofday(&start_time, NULL);
            
            printf("benchmark data: start_time = \n");
            timeval_print(&start_time);
        }        
#endif

		char ip[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &client_addr.sin6_addr, ip, INET6_ADDRSTRLEN);
		char *dev_ip = collector_get_ip(ip);
#ifdef DEBUG
        printf("Connection fron device ip = %s\n", dev_ip);
        printf("Received message = %s\n", msg);
#endif

		json_t *dev_config;
		dev_config = collector_get_json_object_from_json(params.client_map, dev_ip);
        if(dev_config == NULL)
            continue;
		collector_parse_message_line_by_line(msg, dev_ip, dev_config);

	}
	onig_region_free(region, 1 /* 1:free self, 0:free contents only */);
	onig_free(re);
	onig_end();

	return 0;
}






