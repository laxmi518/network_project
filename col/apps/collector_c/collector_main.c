#include "collector_main.h"


void * handle_tcp_data_cb(char* msg,json_t* param){
	json_t *event;
	const char* normalizer;
	const char* repo;
	event = collector_create_event(msg,param);

	normalizer = get_string_value_from_json(param, "normalizer");
	repo = get_string_value_from_json(param, "repo");

	send_event_with_mid(sender, event, normalizer, repo);
	
}
void * handle_udp_data_cb(char* msg,json_t* param){
	json_t *event;
	const char* normalizer;
	const char* repo;
	event = collector_create_event(msg,param);

	normalizer = get_string_value_from_json(param, "normalizer");
	repo = get_string_value_from_json(param, "repo");

	send_event_with_mid(sender, event, normalizer, repo);	
	//free(msg);
}
void * handle_ssl_data_cb(char* msg){
	printf("***************ssl data");
	printf("\n%s\n",msg);
	//free(msg);
}



int main(int argc, char **argv){
	tcp = 0;
	udp = 0;
	ssl = 0;
	count = 0;
	//g_type_init();
	array_of_collectors = g_array_new(FALSE, FALSE, sizeof(gchar*));
	
	if(argv[1] == NULL)	{
		printf("A config file is expected as argument.\n");
		exit(1);
	}
	config_path = argv[1];

	start_tcp_collector();
	start_udp_collector();
	start_ssl_collector();
	sender = get_collector_out_socket();

	start_collector();
	return 0;
}
