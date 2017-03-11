#ifndef COLLECTOR_LIB_H
#define COLLECTOR_LIB_H
#include "config_reader.h"
#include <zlog.h>
/**
  A function to free a pointer,its checking pointer and then free it
*/
#define AFREE(p) { if(p) free(p); }


typedef void *(*_COLLECTOR_UDP_CB)(char *, char *, json_t *);

typedef void *(*_COLLECTOR_TCP_CB)(char *, char *, json_t *);

typedef void *(*_COLLECTOR_TCP_SSL_CB)(char *, char *, json_t *);

/**
  A  struct that holds syslog data.
 */
typedef struct _syslog_data {
    OnigRegion *region; /**<    Onigregion*/
    char *str;         /**<    Message*/
    int pri;            /**<    Priority of message*/
    char *year;         /**<    Year of Message*/
    char *date_time;    /**<    date and time of message*/
}_syslog_data_t;

char *col_trim_whitespace(char *str);
void col_register_callbacks(_COLLECTOR_UDP_CB func1, _COLLECTOR_TCP_CB func2,_COLLECTOR_TCP_SSL_CB func3);
void col_start();
void col_init_library(char *_config_path_local, char *service_name, char *zlog_conf_path);
json_t * col_create_basic_event(char *msg, char *dev_ip, json_t *dev_config);
json_t * col_json_merge(json_t *basic, json_t *normalized_fields);
void col_send_event(json_t *json_final,json_t *dev_config);
void col_update_json_field(json_t *json, char *field_to_update, char *update_value);
GMutex col_get_mutex_regex(void);
GMutex col_get_mutex_cnt(void);
zlog_category_t *col_get_zlog_category(void);
#endif