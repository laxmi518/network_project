#ifndef FETCHERLIB_H
#define FETCHERLIB_H

// #include "../../../../apps/fetcher_c/fetcher_main.h"
#include <pthread.h>
#include <glib.h>
#include <jansson.h>
#include <zlog.h>
#include "common.h"
#include "config_reader.h"


json_t * fet_create_basic_event(char *msg, config_data_t *config_data);
void fet_start();
void fet_register_callbacks(_FETCHER_CB func1);
void fet_init_library(char *_config_path_local, char *service_name, char *zlog_conf_path);
void fet_send_event(json_t *json_final, config_data_t *config_data);
config_data_t * fet_get_config_data(json_t *client_map);
zlog_category_t *fet_get_zlog_category(void);
const char * fet_get_basedir(void);
char *fet_trim_whitespace(char *str);

#endif
