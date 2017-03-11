/*! \file fetcher_c/fetcher_main.c
* This file is for fetcher
* @author Swati Upadhyayai 
* @date 9/30/2013     
*/
#include "basic_fetcher.h"
#include "fetcher_lib.h"
#include <zlog.h>


zlog_category_t *c;


/**
*Callback function of thread creation, when the thread starts execution, it will come to this callback.
*@ param[in] param which contais sid information
*@return void pointer.
*/ 


void *thread_main_cb(void *param)
{
	//start of thread execution time
	json_t* sid_param = (json_t*)param;
	if(sid_param == NULL)
	{
		zlog_error(c, "parameter is null. couldn't start thread");
		return NULL;
	}
	//log file path
	config_data_t *config_data= fet_get_config_data(param);
	while(1)
	{
		FILE *fp;
		char *line = NULL;
		size_t len = 0;
		ssize_t read;
		fp = fopen(config_data->path, "rt");
		if (fp == NULL)
			zlog_error(c,"file open error");
		while ((read = getline(&line, &len, fp)) != -1){
			printf("\n%s\n", line);
			json_t *event = fet_create_basic_event(strdup(line),config_data);
			// json_t *event = fet_create_event(line,sid_param);
			fet_send_event(event, config_data);
	    }
	    zlog_debug(c,"after while");
	    // free(line);
		fclose(fp);  /* close the file prior to exiting the routine */
		// return NULL;
		sleep(config_data->fetch_interval_seconds);
	}
}


/**
* Main function, which is setting the value of config_path and calling the interface function.
*/ 

int main(int argc, char **argv)
{
	if(argv[1] == NULL)	{
		zlog_fatal(c,"A config file is expected as argument.\n");
		exit(1);
	}
	char *config_path = argv[1];
	fet_init_library(config_path,"basic_c_fetcher","/opt/immune/storage/col/zlog.conf");
	c = fet_get_zlog_category();
	fet_register_callbacks(thread_main_cb);
	fet_start();
	return 0;
 }