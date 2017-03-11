#ifndef LPLOG_H
#define LPLOG_H

#include <stdio.h>
#include <stdlib.h>
/*! \file lplog.h
* @author ritesh pradhan
* @date 8/22/2013
    
    Used for logging at debug level
*/

#include <stdarg.h>

#ifdef LPLOG

/**
*   @brief  A function used for printing log message
*   @param[in] _FILE file name
*   @param[in] _LINE line number
*   @param[in] _func function name
*   @param[in] fmt format
*   @return void
*/
#define lplog(...) { _lplog(__FILE__, __LINE__, __func__, ##__VA_ARGS__); }
#else
/*Doing nothing*/
#define lplog(...)
/* do nothing */
#endif


/**
  A function to free a pointer,its checking pointer and then free it
*/
#define AFREE(p) { if(p) free(p); }

/**
  A number to represent maximum log buffer size.
*/
#define MAX_LOGBUFFER_SIZE 32768


/** structure related to log message*/
struct _lplog_context {
    char *logbuf;       /**<    log buffer*/
    char *va_logbuf;    /**<    log buffer containing file name function name line number */
};

/** This is the typedef for the structure _lplog_context*/
typedef struct _lplog_context lplog_context_t;

/** Global structure pointer variableof type lplog_context_t */
lplog_context_t *lplog_context_global=NULL;

/**
*   @brief  It will initilize lplog_context_t structure variables,allocate memory to variables
*   @return void
*/
void lplog_init()
{
    lplog_context_t *c = NULL;
    if (lplog_context_global == NULL)
        lplog_context_global=calloc(1,sizeof(lplog_context_t));
    c=lplog_context_global;
    if(c->logbuf==NULL)
        c->logbuf=calloc(MAX_LOGBUFFER_SIZE,sizeof(char));
    if(c->va_logbuf==NULL)
        c->va_logbuf=calloc(MAX_LOGBUFFER_SIZE,sizeof(char));
}

/**
*   @brief  It will free the memory pointed by the variables of lplog_context_t structure.
*   @return void
*/
void lplog_exit()
{
    lplog_context_t *c=lplog_context_global;
    AFREE(c->logbuf);
    c->logbuf=NULL;
    AFREE(c->va_logbuf);
    c->va_logbuf=NULL;
    AFREE(c);
    c=NULL;
}

/**
*   @brief  Used for printing log message
*   @param[in] _FILE file name
*   @param[in] _LINE line number
*   @param[in] _func function name
*   @param[in] fmt format
*   @return void
*/
void _lplog(const char *_FILE, int _LINE, const char *_func,  char *fmt, ...) 
{
    lplog_context_t *c = lplog_context_global;
    va_list ap;
    va_start(ap,fmt);
    vsnprintf(c->va_logbuf, MAX_LOGBUFFER_SIZE, fmt, ap);
    va_end(ap);
    snprintf(c->logbuf,MAX_LOGBUFFER_SIZE,"(%s:%d:%s):",
             _FILE,_LINE,_func);
    fprintf(stderr,"%s%s\n",c->logbuf,c->va_logbuf);
}

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
                char * str_json =json_dumps(json,0);
                printf("%s\n",str_json);
                free(str_json);
        }
        else
        {
                printf("NULL json\n");
        }
}

#endif
