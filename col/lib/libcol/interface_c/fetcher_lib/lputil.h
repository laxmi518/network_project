#ifndef LPLOG_H
#define LPLOG_H

#include <stdio.h>
#include <stdlib.h>

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
        {
                printf("json is object\n");
        }
        else if (type==JSON_ARRAY)
        {
                printf("json is array\n");
        }
        char * str_json =json_dumps(json,JSON_INDENT(4));
        printf("%s\n",str_json);
        free(str_json);
    }
    else
    {
            printf("NULL json\n");
    }
}

void print_pthread(pthread_t pt) {
    printf("Pthread: \t");
  unsigned char *ptc = (unsigned char*)(void*)(&pt);
  fprintf(stdout, "0x");
  size_t i;
  for (i=0; i<sizeof(pt); i++) {
    fprintf(stdout, "%02x", (unsigned)(ptc[i]));
  }
  printf("\n\n\n");
}

void dbg_hash_device_ip_loop(gpointer key, gpointer value, gpointer user_data)
{
    _running_job_t *job = (_running_job_t *)value;
    char *sid = (char *)key;
    printf("sid: %s\n", sid);
    char *json_str;
    json_str = json_dumps((json_t *)job->sid_info, JSON_INDENT(4));
    printf("sid_info: %s\n", json_str);
    free(json_str);
    // print_pthread(job->thread_id);
    // printf("thread_id: %d\n\n",job->thread_id);
    printf("thread_id: %lu\n\n",job->thread_id);
}

void dbg_hash(GHashTable *hash_table)
{
    if(hash_table==NULL)
    {
        printf("hash talbe is NULL\n");
        return;
    }
    g_hash_table_foreach (hash_table, dbg_hash_device_ip_loop,NULL);
}
#endif
