#ifndef COMMON_H
#define COMMON_H
/**
  A function to free a pointer,its checking pointer and then free it
*/
#define AFREE(p) { if(p) free(p); }


typedef void *(*_FETCHER_CB)(void *);
/**
  Structure for storing sid sid_info and thread id of config file
 */

typedef struct{
  json_t* sid_info;/**<  information contained in sid like normalizer,repo,log file etc */
  pthread_t thread_id;/**< id of the thread created when a new sid info is coming  */
  gboolean kill_thread;
}_running_job_t;

typedef struct {
  const char *sid;
  const char *device_ip;
  const char *parser;
  const char *path;
  int fetch_interval_seconds;
  const char *charset;
  const char *device_name;
  const char *normalizer;
  const char *repo;
}config_data_t;

#endif