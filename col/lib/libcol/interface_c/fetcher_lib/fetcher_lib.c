/*! \file fetcher_lib/fetcher_lib.c
* This file is for fetcher interface,which is updating first time job compairing the new job when SIGHUP coming,
* updatinh the job if a new job is coming, deleting a job if its not in new config, creating event and sending it to upper layer
* @author Swati Upadhyaya
* @date 9/30/2013     
*/

#include "fetcher_lib.h"
#include <locale.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <Python.h>

/* Custom made C libraries */
#include "lputil.h"
#include "json_creator.h"
#include "wiring.h"
#include "encoding.h"





/** @brief mutex for log_counter */
pthread_mutex_t _mutex_log_counter;
/** @brief mutex for global vairable socket.*/
pthread_mutex_t _mutex_socket;
/** @brief mutex for encoding using pythong.*/
pthread_mutex_t _mutex_encode;
/**last time stamp  
*/
long _last_col_ts=0;
/** Number of syslog message per secone
*/
long _log_counter=0;
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
 // */
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
/**base_dir
*/
const char *_basedir;
/** Related to log
*/
zlog_category_t *_c;
zlog_category_t *_bc;


_FETCHER_CB _fetcher_cb = NULL;

GHashTable *RUNNING_JOB_HASH = NULL;


/**
*Creating message id
*@param[in]  dev_ip device ip
*@param[in]  col_ts time stamp of syslog message(in sec)
*@param[in]  counter  will count the message per sec
*@return message id
*/
__inline char *inl_get_message_id(const char *dev_ip, long col_ts, long counter){
    char *mid = (char *) malloc(100*sizeof(char));
    memset(mid, 0, 100*sizeof(char));
    sprintf(mid, "%s|%s|%s|%010ld|%06ld", _lp_name, _col_type, dev_ip, col_ts, _log_counter );
    return mid;
}

json_t * fet_create_basic_event(char *msg, config_data_t *config_data)
{
    long col_ts;
    time_t now;
    now = time(0);
    col_ts = (long)now;

    pthread_mutex_lock(&_mutex_log_counter);
    if(col_ts > _last_col_ts)
    {
        _last_col_ts = col_ts;
        _log_counter = 0;
    }

    _log_counter += 1;

    char *mid;
    mid = inl_get_message_id(config_data->device_ip, col_ts, _log_counter);
    pthread_mutex_unlock(&_mutex_log_counter);

    pthread_mutex_lock(&_mutex_encode);
    char *encoded_msg = get_encoded_msg(msg, config_data->charset);
    pthread_mutex_unlock(&_mutex_encode);
    if(encoded_msg == NULL)
    {
         return NULL;
    }
    json_t *event = create_json_object(_lp_name, encoded_msg, mid, col_ts, _col_type,config_data);

    
    AFREE(mid);
    // json_decref(event);
    AFREE(encoded_msg);
    return event;
}

void create_new_job_and_add_to_hash(const char *key, json_t *sid_info_j, gboolean kill_thread)
{
    // (*_fetcher_cb)(sid_info_j);//use thread creation instead
    pthread_t thread_id;
    int err = pthread_create(&thread_id,NULL, (*_fetcher_cb), (void*) sid_info_j);
    if(err==0)
    {
		//upon success
		_running_job_t *new_job = (_running_job_t*)malloc(sizeof(_running_job_t));
		new_job->sid_info = json_deep_copy(sid_info_j);
		// new_job->sid_info = sid_info_j;
        new_job->thread_id = thread_id;
		new_job->kill_thread = kill_thread;
		g_hash_table_insert(RUNNING_JOB_HASH, strdup(key), new_job);
	}
	else
	{
		zlog_error(_c,"can't create thread :[%s]", strerror(err));
		return;
	}
}

void reset_kill_thread_loop(gpointer key, gpointer value, gpointer user_data)
{
	_running_job_t *job = (_running_job_t *)value;
    job->kill_thread=TRUE;	
}

gboolean check_kill_thread_true_loop(gpointer key, gpointer value, gpointer user_data)
{
    _running_job_t *job = (_running_job_t *)value;
    if(job->kill_thread==TRUE)
    {
    	zlog_debug(_c,"removing job: %s thread_id %lu",(char *)key,job->thread_id);

    	//thread kill
    	int err = pthread_kill(job->thread_id,SIGKILL);
		if(err!=0)
			zlog_error(_c,"Couldn't kill thread %lu",job->thread_id);
    	//remove from hash
		return TRUE;
    }
    else
    	return FALSE;
}

void kill_removed_job_and_reset(void)
{
	zlog_debug(_c,"kill removed job and reset");
	g_hash_table_foreach_remove(RUNNING_JOB_HASH, check_kill_thread_true_loop,NULL);
	g_hash_table_foreach(RUNNING_JOB_HASH, reset_kill_thread_loop,NULL);
}

void reconfigure_jobs(void)
{
	zlog_debug(_c,"reconfigure_jobs");
	_config = get_json_from_config_file(_config_path);
	_client_map = get_json_object_from_json(_config, "client_map");
	const char *key;
	json_t *value;

	json_object_foreach(_client_map, key, value) 
	{
		_running_job_t *job = (_running_job_t*)(g_hash_table_lookup(RUNNING_JOB_HASH,key));
		if(job!=NULL)
		{
			zlog_debug(_c, "job exists for %s, check if sid_info has changed",key);
			if(json_equal(value,job->sid_info)==1)
			{
				zlog_debug(_c,"sig_info hasn't changed, do nothing");
				job->kill_thread=FALSE;
			}
			else
			{
				zlog_debug(_c,"sig_info has changed, kill old job and create new one with new info");
				// int err = pthread_kill(job->thread_id,SIGKILL);
				// if(err!=0)
				// 	zlog_error(_c,"Couldn't kill thread %d",job->thread_id);
				g_hash_table_remove(RUNNING_JOB_HASH,key);
				create_new_job_and_add_to_hash(key, value,FALSE);
			}
		}
		else
		{
			zlog_debug(_c, "job doesn't exists");
			create_new_job_and_add_to_hash(key, value,FALSE);

		}
	}
	kill_removed_job_and_reset();
#ifdef DEBUG
	printf("New value of RUNNING_JOB_HASH----------------\n");
	dbg_hash(RUNNING_JOB_HASH);
#endif
}

/**
*   @brief  Clean up all the allocated memories
*/
void memory_cleanup(void)
{
    Py_Finalize();
    zlog_debug(_c,"memory_cleanup");
    //process all thread and free up memory
    // g_thread_pool_free(pool,FALSE,TRUE); // return when all the queued task in pool has been completed
    g_hash_table_remove_all(RUNNING_JOB_HASH);
    json_decref(_config);
    free_zmq(_context, _sender); 
    // zlog_fini();
    pthread_mutex_destroy(&_mutex_log_counter);
    pthread_mutex_destroy(&_mutex_socket);
    pthread_mutex_destroy(&_mutex_encode);
}

/**
*Whenever a SIGHUP signal is there, execution comes here, this callback function call the compare job function.
*@return void
*/ 
void sig_handler(int signum) {
    
    if(signum == 2 || signum == 15) //2 = SIGINT 15 = SIGTERM
    {
        zlog_fatal(_c, "Signal received: %d",signum);
        memory_cleanup();
        zlog_debug(_c, "Memory cleanedup");
        exit(signum);
    }
    else if( signum == 1)
    {
        zlog_info(_c, "Signal received: %d (SIGHUP)",signum);
        // signal(SIGHUP,sig_handler); //reset signal
        // set_config_parameters(); /* reload _config parameters */
		// compare_new_job();
		reconfigure_jobs();
    }
}

void run_job_first_time()
{
	_config = get_json_from_config_file(_config_path);
	_client_map = get_json_object_from_json(_config, "client_map");
	_col_type = get_string_value_from_json(_config, "col_type");
    _lp_name = get_string_value_from_json(_config, "loginspect_name");
    _basedir = get_string_value_from_json(_config, "basedir");
		/* obj is a JSON object */
	const char *key;
	json_t *value;

	json_object_foreach(_client_map, key, value) 
	{
        json_t *sid = json_object();
        json_object_set_new(sid,"sid",json_string(key));
        json_object_update(value,sid);
        json_decref(sid);
		create_new_job_and_add_to_hash(key, value,TRUE);
	}
#ifdef DEBUG
	printf("Printing HASH RUNNING_JOB_HASH on first run\n");
	dbg_hash(RUNNING_JOB_HASH);
#endif
}

/**
*Function called from the main function,handling the SIGHUP signal, creating the sender,initializing the array used for storing sid config
*update the sid_info as well as thread id for the first config file.
*@return void
*/ 

void fet_start(){
	//fetcher_initilize_array();
	//fetcher_update_job_first_time();
	run_job_first_time();
	while(1)
		sleep(1);
}

/**
*   @brief  Destroys the main GHash key
*/
void key_destroy_cb(gpointer data)
{
    free(data);
}

/**
*   @brief  Destroys the main GHash value
*/
void value_destroy_cb(gpointer data)
{
	_running_job_t *job = (_running_job_t *)data;
    json_decref(job->sid_info);
    AFREE(job);
}

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
    signal(SIGHUP, sig_handler);
    signal(SIGINT, sig_handler);
    // signal(SIGTERM, sig_callback);
    // signal(SIGABRT, do_backtrace);
    // signal(SIGFPE, do_backtrace);
    // signal(SIGILL, do_backtrace);
    // signal(SIGSEGV, do_backtrace);

    /* get collector out socket */
    _sender = get_collector_out_socket(service_name);
    // set_config_parameters();
    if (pthread_mutex_init(&_mutex_log_counter, NULL) != 0)
    {
        zlog_fatal(_c, "mutex init failed");
        exit(1);
    }
    if (pthread_mutex_init(&_mutex_socket, NULL) != 0)
    {
        zlog_fatal(_c,"mutex init failed");
        exit(1);
    }
    if (pthread_mutex_init(&_mutex_encode, NULL) != 0)
    {
        zlog_fatal(_c,"mutex init failed");
        exit(1);
    }

    RUNNING_JOB_HASH = g_hash_table_new_full(g_str_hash, g_str_equal, key_destroy_cb, value_destroy_cb);

}
void fet_register_callbacks(_FETCHER_CB func1)
{
    _fetcher_cb=func1;
}

void fet_init_library(char *_config_path_local, char *service_name, char *zlog_conf_path)
{
    _config_path=_config_path_local;
    lib_init(service_name, zlog_conf_path);
}

void fet_send_event(json_t *json_final, config_data_t *config_data)
{
    send_event_with_mid(_sender, json_final, config_data->normalizer, config_data->repo);
    json_decref(json_final);
}

config_data_t * fet_get_config_data(json_t *client_map)
{
	config_data_t *config_data = (config_data_t *)malloc(sizeof(config_data_t));
    config_data->sid = get_string_value_from_json(client_map,"sid");
	config_data->device_ip = get_string_value_from_json(client_map,"device_ip");
	config_data->parser = get_string_value_from_json(client_map,"parser");
	config_data->path = get_string_value_from_json(client_map,"path");
	config_data->fetch_interval_seconds = get_integer_value_from_json(client_map,"fetch_interval_seconds");
	config_data->charset = get_string_value_from_json(client_map,"charset");
	config_data->device_name = get_string_value_from_json(client_map,"device_name");
	config_data->normalizer = get_string_value_from_json(client_map,"normalizer");
	if(config_data->normalizer==NULL)
		config_data->normalizer= "none";
	config_data->repo = get_string_value_from_json(client_map,"repo");
	return config_data;
}

zlog_category_t *fet_get_zlog_category(void)
{
    return _c;
}
const char * fet_get_basedir(void)
{
    return _basedir;
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
char *fet_trim_whitespace(char *str)
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