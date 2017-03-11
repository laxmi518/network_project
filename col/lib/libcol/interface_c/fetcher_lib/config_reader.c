/*! \file config_reader._c
* @author ritesh, hari
* @date 8/22/2013
    
    Reads the JSON cofig file and returns required values
*/
#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>

#include "config_reader.h"

/**
*	@brief	It will read the config from given path
*	@param[in]  config_path input to main,path of configuration file
*	@return  config(json_t * type)
*/ 
json_t *get_json_from_config_file(char *config_path) {
	/* Read config from json file*/
    json_t *config;
    json_error_t error;

    config = json_load_file(config_path, 0, &error);

    if(!config)
    {
        zlog_error(_c,"Error reading config: on line %d: %s\n", error.line, error.text);
        return NULL;
    }

    return config;
}

/**
*	@brief	Read string value from json config file,get the key value(field) from the object(root)
*	@param[in]  root json object from which key value has to be extracted
*	@param[in]  field Key 
*	@return  string (char *)
*/ 
const char *get_string_value_from_json(json_t *root, const char *field)
{
	/* Read string value from json config */
	json_t *value;

	value = json_object_get(root, field);

	if(!json_is_string(value))
	{
		zlog_error(_c,"Error parsing json object: value of %s field is not a string\n", field);
		return NULL;
	}

	return json_string_value(value);
}


/**
*	@brief	Read integer value from json config, get the key value(field) from the object(root)
*	@param[in]  root json object from which key value has to be extracted
*	@param[in]  field Key
*	@return  int value
*/ 
int get_integer_value_from_json(json_t *root, char *field)
{
	/* Read integer value from json config */
	json_t *value;

	value = json_object_get(root, field);

	if(!json_is_integer(value))
	{
		zlog_error(_c,"Error parsing json object: value of %s field is not an integer\n", field);
		return -1;
	}

	return json_integer_value(value);
}

/**
* 	@brief	Read json object from json config,get the key value(field) from the object(root)
*	@param[in]  root json object from which key value has to be extracted
*	@param[in]  field Key
*	@return  json object
*/ 
json_t *get_json_object_from_json(json_t *root, char *field)
{
	/* Read json object from json config */
	json_t *value;

	value = json_object_get(root, field);

	if(!json_is_object(value))
	{
		zlog_error(_c,"Error parsing json object: value of %s is not a json object\n", field);
		return NULL;
	}

	return value;
}
