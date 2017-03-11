#ifndef CONFIG_READER_H
#define CONFIF_READER_H
/**
*	@file config_reader.h
* 	@author ritesh, hari
* 	@date 8/22/2013
    
    Reads the config from given configuration file
*/
#include <zlog.h>
extern zlog_category_t *c;

json_t *get_json_from_config_file(char *config_path);
const char *get_string_value_from_json(json_t *root, const char *field);
int get_integer_value_from_json(json_t *root, char *field);
json_t *get_json_object_from_json(json_t *root, char *field);

#endif

