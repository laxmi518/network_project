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
                        printf("json is object\n");
                else if (type==JSON_ARRAY)
                        printf("json is array\n");
                char * str_json =json_dumps(json,JSON_INDENT(4));
                printf("%s\n",str_json);
                free(str_json);
        }
        else
        {
                printf("NULL json\n");
        }
}

#endif
