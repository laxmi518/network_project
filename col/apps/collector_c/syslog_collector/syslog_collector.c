#include "syslog_collector.h"

GRegex *regex;
GRegex *regex_new;
/** @brief mutex for regex */
GMutex mutex_regex;
/** @brief mutex for epoch */
GMutex mutex_epoch;
/** Related to log*/
zlog_category_t *c;
/** @brief hash table to store message without new line character at end */
GHashTable *TCP_CACHE = NULL;

time_t last_epoch_ts=0;
char last_epoch_str[50];

_syslog_data_t * create_new_syslog_data_t(char *str)
{
    _syslog_data_t *d = (_syslog_data_t *)malloc(sizeof(_syslog_data_t));
    d->str = strdup(str);
    d->pri = 0;
    d->year = NULL;
    d->date_time = NULL;
    return d;
}

/** 
*   @brief  Check regex  syslog  message return NULL if not match
*   @param[in]  message Incoming message
*   @param[in]  re regex object
*   @param[in]  region Onigregion
*   @return struct syslog_data *
*/ 

_syslog_data_t * get_syslog_data_t_from_message(GRegex *regex, char *message) {

    GMatchInfo *match_info;
    _syslog_data_t *d = create_new_syslog_data_t(message);
    g_mutex_lock(&mutex_regex);
    g_regex_match (regex, message, 0, &match_info);
    gchar *pri = g_match_info_fetch_named (match_info,"pri");
    // printf("date: %s\n",date);

    if(pri!=NULL){
        zlog_debug(c,"pri: %s\n", pri);
        d->pri = atoi(pri);
    }
    else
    {
        AFREE(d->str);
        AFREE(d);
        g_match_info_free (match_info);
        g_mutex_unlock(&mutex_regex);
        return NULL;        
    }
    gchar *date = g_match_info_fetch_named (match_info,"date");
    if(date)
    {
        d->date_time = date;
    }
    g_free (pri);
    g_match_info_free (match_info);
    g_mutex_unlock(&mutex_regex);
    return d;
}

json_t *get_normalized_fields_from_syslog_data_t(_syslog_data_t *d, json_t *event, json_t *dev_config, const char *parser)
{
    json_t *normalized_fields = json_object();

    /* use regex only if parser is SyslogParser or NewSyslogParser*/
    if( (strcmp(parser,"SyslogParser")==0) || (strcmp(parser,"NewSyslogParser")==0) ) 
    {
        if(d->pri != 0)
        {
            int sev, fac;
            fac = d->pri / 8;
            sev = d->pri % 8;

            json_object_set_new(normalized_fields, "severity", json_integer(sev));
            json_object_set_new(normalized_fields, "facility", json_integer(fac));

            col_update_json_field(event,"_type_num"," severity facility");

        }
        if(d->date_time)
        {
            g_mutex_lock(&mutex_epoch);
            if(strcmp(d->date_time,last_epoch_str)==0)
            {
                json_object_set_new(normalized_fields, "log_ts", json_integer((int)last_epoch_ts));
                col_update_json_field(event,"_type_num"," log_ts");
            }
            else
            {
                time_t curr_time;
                time(&curr_time);
                struct tm *ltm= localtime(&curr_time);

                char *dt_with_year = (char *) malloc(50);
                memset(dt_with_year, 0, 50);
                sprintf(dt_with_year, "%d %s", 1900+ltm->tm_year, d->date_time);

                struct tm tm;
                time_t epoch = 0;
                if (strptime(dt_with_year, "%Y %b %d %H:%M:%S", &tm) != 0){
                    epoch = mktime(&tm);
                    json_object_set_new(normalized_fields, "log_ts", json_integer((int)epoch));
                    // strcat(_type_num, " log_ts");
                    col_update_json_field(event,"_type_num"," log_ts");
                }
                free(dt_with_year);
                strcpy(last_epoch_str,d->date_time);
                last_epoch_ts = epoch;
            }
            g_mutex_unlock(&mutex_epoch);
        }
    }
    else
    {
        zlog_debug(c,"LineParser");
    }
    return normalized_fields;
}

void process_token(_syslog_data_t *data,char *dev_ip, json_t *dev_config, const char *parser)
{
    json_t *basic = col_create_basic_event(data->str, dev_ip, dev_config);
    json_t *normalized_fields = get_normalized_fields_from_syslog_data_t(data,basic, dev_config, parser);
    json_t *json_final = col_json_merge(basic,normalized_fields);
    col_send_event(json_final,dev_config);
#ifdef DEBUG
    char *json_str;
    json_str = json_dumps(json_final, JSON_INDENT(4));
    zlog_debug(c,"Event is packet: %s", json_str);
    free(json_str);
#endif
    json_decref(json_final);
    col_free_syslog_data_t(data);
}

void * handle_udp_data_cb(char* msg_full, char *dev_ip, json_t* dev_config){
    zlog_debug(c, "udp data received");
    const char *parser = get_string_value_from_json(dev_config, "parser");
    char *token;
    char *remaining_str=NULL;
    if(strcmp(parser,"LineParser")==0)
    {
        zlog_debug(c, "LineParser");
        token = strtok_r(msg_full, "\n", &remaining_str);
        while (token != NULL)
        {   
            if(token[0]==' ')
            {
                token = col_trim_whitespace(token);
                if(strcmp(token,"")==0)
                {
                    token = strtok_r(NULL, "\n", &remaining_str);
                    continue;
                }
            }
            _syslog_data_t *data = create_new_syslog_data_t(token);
            process_token(data,dev_ip,dev_config,parser);
            token = strtok_r(NULL, "\n", &remaining_str);
        }
    }
    else if(strcmp(parser,"SyslogParser")==0)
    {
        zlog_debug(c, "SyslogParser");
        token = strtok_r(msg_full, "\n", &remaining_str);
        while (token != NULL)
        {   
            if(token[0]==' ')
            {
                token = col_trim_whitespace(token);
                if(strcmp(token,"")==0)
                {
                    token = strtok_r(NULL, "\n", &remaining_str);
                    continue;
                }
            }
            //SyslogParser
            _syslog_data_t *data = get_syslog_data_t_from_message(regex,token);
            if(data==NULL){
                //no match just send the str
                data = create_new_syslog_data_t(token);
            }
            process_token(data,dev_ip,dev_config,parser);
            token = strtok_r(NULL, "\n", &remaining_str);
        }

    }
    else
    {
        //NewSyslogParser
        zlog_debug(c, "NewSyslogParser");
        _syslog_data_t *data_store =NULL;
        token = strtok_r(msg_full, "\n", &remaining_str);
        while (token != NULL)
        {   
            if(token[0]==' ')
            {
                token = col_trim_whitespace(token);
                if(strcmp(token,"")==0)
                {
                    token = strtok_r(NULL, "\n", &remaining_str);
                    continue;
                }
            }
        
            _syslog_data_t *data = get_syslog_data_t_from_message(regex_new,token);
            if(data==NULL)
            {
                //no match
                zlog_debug(c,"no match");
                if(data_store==NULL)
                {
                    zlog_debug(c,"data store doesn't exists, creating new one");
                    data_store = create_new_syslog_data_t(token);   
                }
                else
                {
                    zlog_debug(c,"data store exists, appending token: (%s) to data_store->str: (%s)",token,data_store->str);
                    char *new_value=NULL;
                    asprintf(&new_value,"%s%s",data_store->str,token);
                    free(data_store->str);
                    data_store->str = new_value;
                }
            }
            else
            {
                //match
                zlog_debug(c,"match");
                if(data_store==NULL)
                {
                    zlog_debug(c,"data store doesn't exists, assigning matched value to data_store");
                    data_store=data;
                }
                else
                {
                    zlog_debug(c,"data store exists, sending data from data_store and storing the current token: (%s) to data_store",token);
                    process_token(data_store,dev_ip,dev_config,parser);
                    data_store=data;
                }
            }
            if(strcmp(remaining_str,"")==0)
            {
                zlog_debug(c,"last token received, send content of data_store");
                process_token(data_store,dev_ip,dev_config,parser);
            }
            token = strtok_r(NULL, "\n", &remaining_str);
        }
    }
}

/**
*   @brief  Destroys the key
*/
void key_destroy_cb(gpointer _data)
{
    AFREE(_data);
}

/**
*   @brief  Destroys the value
*/
void value_destroy_cb(gpointer _data)
{
    // _syslog_data_t *d= (_syslog_data_t*)_data;
    // AFREE(d->str);
    // AFREE(d);
}
void *handle_tcp_and_ssl_data_cb(char *msg_full,char*dev_ip, json_t *dev_config)
{
    const char *parser = get_string_value_from_json(dev_config, "parser");
    char *token;
    char *remaining_str=NULL;
    if(strcmp(parser,"NewSyslogParser")==0)
    {
        zlog_debug(c, "NewSyslogParser");
        int len = strlen(msg_full);
        token = strtok_r(msg_full, "\n", &remaining_str);
        while(token != NULL)
        {
            _syslog_data_t *data = get_syslog_data_t_from_message(regex_new,token);
            //dbg_hash(TCP_CACHE);
            if(data==NULL)
            {
                zlog_debug(c,"no match");
                _syslog_data_t *data_store = (_syslog_data_t *)g_hash_table_lookup(TCP_CACHE, dev_ip);
                if(data_store==NULL)
                {
                    zlog_debug(c,"no prior pattern exists, ignoring the message");
                    AFREE(data);
                    token = strtok_r(NULL, "\n", &remaining_str);
                    continue;
                }   
                else
                {
                    zlog_debug(c,"Prior pattern exists(no current no match), appending token: (%s) to data_store->str: (%s)",token,data_store->str);
                    char *new_str=NULL;
                    asprintf(&new_str,"%s%s",data_store->str,token);
                    free(data_store->str);
                    data_store->str = new_str;
                    if(strlen(data_store->str)>10000)
                    {
                        zlog_warn(c, "Message too big(more than 10000 len). Stop Looking for pattern and send msg");
                        process_token(data_store,dev_ip,dev_config, parser);
                        g_hash_table_remove(TCP_CACHE,dev_ip);
                    }
                    // g_hash_table_insert(TCP_MESSAGE_CACHE,strdup(dev_ip),data_store);
                } 
            }
            else
            {
                zlog_debug(c,"match");
                _syslog_data_t *data_store = (_syslog_data_t *)g_hash_table_lookup(TCP_CACHE, dev_ip);
                if(data_store!=NULL)
                {
                    zlog_debug(c,"prior pattern exists. sending data: %s and clearing cache and adding new syslog_data to CACHE",data_store->str);
                    // zlog_debug(c,"d-",d->);
                    process_token(data_store,dev_ip,dev_config, parser);
                    g_hash_table_remove(TCP_CACHE,dev_ip);
                    g_hash_table_insert(TCP_CACHE,strdup(dev_ip),data);
                }
                else
                {
                    zlog_debug(c,"prior pattern doesn't exists, inserting new token in the CACHE");
                    g_hash_table_insert(TCP_CACHE,strdup(dev_ip),data);
                }
            }
            token = strtok_r(NULL, "\n", &remaining_str);
        }
#ifdef DEBUG
        dbg_hash(TCP_CACHE);
#endif 
    }
    else
    {
        zlog_debug(c, "SyslogParser or LineParser");
        char *msg_concat;
        _syslog_data_t *value = (_syslog_data_t*)g_hash_table_lookup(TCP_CACHE, dev_ip);
        if(value!=NULL)//if the hash has device ip, append the value to msg
        {
            zlog_debug(c,"concatenating: str1: %s and str2: %s",value->str,msg_full);

            asprintf(&msg_concat,"%s%s",value->str,msg_full);
            col_free_syslog_data_t(value);
            g_hash_table_remove(TCP_CACHE,dev_ip);
            // msg_full=msg_concat;
        }
        if(value==NULL)
        {
            asprintf(&msg_concat,"%s",msg_full);
            // msg_full=msg_concat;
        }
        int len = strlen(msg_concat);
        char last_char = msg_concat[len-1];
        token = strtok_r(msg_concat, "\n", &remaining_str);
        while (token != NULL)
        {
            if(token[0]==' ')
            {
                token = col_trim_whitespace(token);
                if(strcmp(token,"")==0)
                {
                    zlog_debug(c,"blank msg received. ignoring");
                    token = strtok_r(NULL, "\n", &remaining_str);
                    continue;
                }
            }
            if(len>10000)
            {
                zlog_warn(c, "Message too big(more than 10000 len). Stop looking for new line and process msg");
                _syslog_data_t *data1 = create_new_syslog_data_t(token);
                process_token(data1, dev_ip,dev_config, parser);        
                g_hash_table_remove(TCP_CACHE,dev_ip);
                token = strtok_r(NULL, "\n", &remaining_str);
                continue;
            }
            if(strcmp(remaining_str,"")==0)
            {
                if(last_char=='\n')
                {
                    //new line is the last character. do nothing
                    zlog_debug(c, "last character is new line");
                }
                else
                {
                    zlog_debug(c, "last character is not new line. storing the token: (%s)",token);
                    //new line not received
                    _syslog_data_t *data = create_new_syslog_data_t(token);            
                    g_hash_table_insert(TCP_CACHE,strdup(dev_ip),data);
                    token = strtok_r(NULL, "\n", &remaining_str);
                    continue;
                }
            }
            _syslog_data_t *d=NULL;
            if(strcmp(parser,"LineParser")==0){
                zlog_debug(c,"LineParser");
                d = create_new_syslog_data_t(token);
            }
            else{
                zlog_debug(c,"SyslogParser");
                d = get_syslog_data_t_from_message(regex,token);
                if(d==NULL)
                {
                    d = create_new_syslog_data_t(token);
                }
            }
            process_token(d, dev_ip,dev_config, parser);    
            token = strtok_r(NULL, "\n", &remaining_str);
        }
        AFREE(msg_concat);
#ifdef DEBUG
        dbg_hash(TCP_CACHE);
#endif 
    }
}

void * handle_tcp_data_cb(char* msg_full, char *dev_ip, json_t* dev_config){
    zlog_debug(c,"tcp data received");
    handle_tcp_and_ssl_data_cb(msg_full,dev_ip, dev_config);
}

void * handle_ssl_data_cb(char* msg_full, char *dev_ip, json_t* dev_config){
    zlog_debug(c,"ssl data received");
    handle_tcp_and_ssl_data_cb(msg_full,dev_ip, dev_config);
}

int main(int argc, char *argv[])
{
    if(argv[1] == NULL) {
        printf("A config file is expected as argument.");
        exit(1);
    }
    char *config_path = argv[1];

    col_init_library(config_path,"syslog_collector_c", "/opt/immune/storage/col/zlog_syslog.conf");
    col_register_callbacks(handle_udp_data_cb, handle_tcp_data_cb,handle_ssl_data_cb);
    mutex_regex = col_get_mutex_regex();
    mutex_epoch = col_get_mutex_cnt();
    c = col_get_zlog_category();

    //setup regex for syslogparser and newsyslog parser

    TCP_CACHE = g_hash_table_new_full(g_str_hash, g_str_equal, key_destroy_cb, value_destroy_cb);

    // char *pattern = "\\s*(?:<(?<pri>\\d{1,3})>)?";

    char *pattern = "\\s*(?:<(?<pri>\\d{1,3})>)?\\s*(?<date>[a-zA-Z]{3}\\s+\\d{1,2}\\s+\\d\\d:\\d\\d:\\d\\d)?";

    regex = g_regex_new (pattern, 0, 0, NULL);

    char *pattern_new = "\\s*(\\d{1,5})?\\s*(?:<(?<pri>\\d{1,3})>)";

    regex_new = g_regex_new (pattern_new, 0, 0, NULL);
   
    col_start();
    printf("I never reach here\n");
}