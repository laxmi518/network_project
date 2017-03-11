
/**
*   @file netflow_collector.c
*   @author Ritesh
*   @brief Netflow Collector for analyzing Netflow Packets  
*/

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <math.h>
#include <sys/resource.h>
#include <errno.h>
#include <execinfo.h>

/* External Libraries */
#include <libcidr.h>
#include <glib.h>
#include <jansson.h>
#include <zlog.h>

/* Custom made */
#include "value_string.h"
#include "netflow_common.h"
#include "netflow_v5_v7.h"
#include "netflow_v9_v10.h"
#include "protocol_name.h"
#include "json_creator.h"
#include "seek_get_bytes.h"

/* Custome library from clib */
#include "../../lib/clib/lputil.h"
#include "../../lib/clib/cidr.h"
#include "../../lib/clib/wiring.h"
#include "../../lib/clib/config_reader.h"


//********************************MACROS**********************************
/** 
*   @def GET_FLOWSET_ID(p, len) 
*   @brief Obtain the flowset id of that flowset given @a p and @a len
*   @param p void pointer

    Returns 2 bytes info from p

*   @def GET_FLOWSET_LENGTH(p, len) 
*   @brief Obtain the flowset length of that flowset given @p p and @len len
*   @param p void pointer

    Returns 2 bytes info from p + 2

**/
#define GET_FLOWSET_ID(p, len)  (get_ntohs(p, 0, len))
#define GET_FLOWSET_LENGTH(p, len) (get_ntohs(p, 2, len))

/** 
*   @def GET_TEMPLATE_ID(p, len)
*   @brief Obtain the template id of that template flowset given @a p and @a len
*   @param p void pointer

    Returns 2 bytes info from p

*   @def GET_TEMPLATE_COUNT(p, len)
*   @brief Obtain the template count of that template flowset given @p p and @len len
*   @param p void pointer
    
    Returns 2 bytes info from p + 2

**/
#define GET_TEMPLATE_ID(p, len) (get_ntohs(p, 0, len))
#define GET_TEMPLATE_COUNT(p, len) (get_ntohs(p, 2, len))

/** 
*   @def GET_OPTION_TEMPLATE_ID(p, len)
*   @brief Obtain the template id of that option template flowset given @a p and @a len
*   @param p void pointer

    Returns 2 bytes info from p

*   @def GET_OPTION_TEMPLATE_OPTION_SCOPE_LENGTH(p, len)
*   @brief Obtain the option template scope length of that option template flowset given @p p and @len len
*   @param p void pointer

    Returns 2 bytes info from p + 2
    
*   @def GET_OPTION_TEMPLATE_OPTION_LENGTH(p, len)
*   @brief Obtain the option length of that option template flowset given @p p and @len len
*   @param p void pointer

    Returns 2 bytes info from p + 4

**/
#define GET_OPTION_TEMPLATE_ID(p, len)  (get_ntohs(p, 0, len))
#define GET_OPTION_TEMPLATE_OPTION_SCOPE_LENGTH(p, len) (get_ntohs(p, 2, len))
#define GET_OPTION_TEMPLATE_OPTION_LENGTH(p, len)   (get_ntohs(p, 4, len))

/**
*   @def MAPPED_IPV4_PREFIX
*   @brief prefix part of the IPV4 address mapped to IPV6

**/
#define MAX_CACHE_SIZE 100000
#define MAPPED_IPV4_PREFIX "::ffff:"

/**
*   @def MAX_THREADS
*   @brief Max threads used

*   @def MAX_UNUSED_THREADS
*   @brief Max threads unused

*   @def MAX_IDLE_TIME_MILLISECOND
*   @brief idle time in millisecond

**/
#define MAX_THREADS 4
#define MAX_UNUSED_THREADS 10
#define MAX_IDLE_TIME_MILLISECOND 10000


//****************************GLOBALS****************************************

/** @brief Create a zlog_category type for category matching. */
zlog_category_t *c;
zlog_category_t *bc;

long last_col_ts   = 0; /**< time stamp  */
long log_counter = 0;   /**< Number of syslog message per secone */
int config_changed = 0;

/** 
*   @defgroup  global_config Global config variables
*   @brief Global variables read from config file.
*   @{
*/
char *config_path;  /**< configuration file path which is an input file(example-config.json path). */
json_t *config;     /**< json object containing different device ip */
json_t *client_map;
const char *col_type;   /**< collection type(netflowc) */
const char *lp_name;    /**< LogPoint name */
int port          = 9001;   /**< port number */
static int no_of_threads = 4;   
static int queue_size    = 10000;
/** @}*/ 

static GThreadPool *pool;   /**< @brief Rrepresents thread pools from glib. */


GMutex mutex_cnt;   /**< @brief mutex for global vairable cnt while benchmarking.*/
GMutex mutex_hash_main; /**< @brief mutex for TEMPLATE_CACHE.*/
GMutex mutex_socket;    /**< @brief mutex for zmq socket.*/
GMutex mutex_log_counter;   /**< @brief mutex for global vairable log_counter and last_col_ts.*/


void *context;  /**< @brief zmq context.*/
void *sender = NULL;    /**< @brief zmq_sender.*/

#ifdef PROFILE
    #define BENCHMARK 1;
#endif

#ifdef BENCHMARK
    unsigned int cnt=0;
#endif


static const int LIST_OF_IPV4[] = { 8, 12, 15, 47, 130, 225, 226, 40001, 40002 };   /**< @brief List of field type containing IPV4 addresses.*/
static const int LIST_OF_IPV6[] = {27, 28, 62, 63, 131, 281, 282, 40057, 40058 };   /**< @brief List of field type containing IPV6 addresses.*/

static GHashTable *NETFLOW_FIELD_TYPES = NULL;  /**< @brief GHashTable for storing field_type and length.*/

GHashTable *v9_TEMPLATE_CACHE = NULL;   /**< @brief GHashTable for storing all the information of all the received v9 templates.*/
GHashTable *v9_TEMPLATE_REC_LEN = NULL; /**< @brief GHashTable for storing length of corresponding v9 templates.*/

GHashTable *v10_TEMPLATE_CACHE = NULL;  /**< @brief GHashTable for storing all the information of all the received v10 templates.*/
GHashTable *v10_TEMPLATE_REC_LEN = NULL;    /**< @brief GHashTable for storing length of corresponding v10 templates.*/

/** 
*   @typedef template_template_list_t 
*   @brief contains template_id, field_count and pointer for each template data.
*/

// typedef struct template_template_list_s {
//     int template_id;    ///< template id 
//     int field_count;    ///< Numbers of fields in that template
//     gpointer *each_data;    ///< pointer for each template data 
// } template_template_list_t;

/** 
*   @struct data_t 
*   @brief Contains binary message and its length.
*/
typedef struct data {
    int n;      /**< Length of the reveived message. */
    struct sockaddr_in6 client_addr;    /**< Client address. */
    unsigned char *message;     /**< Binary message. */
} data_t;


/** 
*   @fn int init_symbols(void)
*   @brief  Initializes the necessary NETFLOW_FIELD_TYPES HashTable with field_type and values.
*/
int init_symbols(void) {
    /* Fill the NETFLOW_FIELD_TYPES with corresponding info */
   // if (NETFLOW_FIELD_TYPES != NULL) return 1;
    int field_id;
    field_id = 0;
    while ( v9_v10_template_types[field_id].strptr ) {
        /* put each fields in NETFLOW_FIELD_TYPE */
        uint32_t j = v9_v10_template_types[field_id].value;
        g_hash_table_insert(NETFLOW_FIELD_TYPES, GINT_TO_POINTER(j), strdup(v9_v10_template_types[field_id].strptr));
        field_id++;
    }
    return 1;
} // End of InitSymbols

/** 
*   @brief  Check if "." is present in dev_ip. If it's present it returns 1(IPV4 case) otherwise 0(IPV6 case)
*   @param[in]  dev_ip  ip address.
*   @return     1 if true else return 0
*/
gboolean is_dot_present(char *dev_ip) {
    int ip_len = strlen(dev_ip);
    int i;
    for (i=ip_len-1; i>=0; i--) {
        if ('.' == dev_ip[i]) {
            return 1;
        }
    }
    return 0;
}

/**
*   @brief  Checking for IPV4/IPV6, it checks against MAPPED_IPV4_PREFIX if it's present 
*   @param[in]  dev_ip device ip.
*   @return  Corresponding IPV4/IPV6
*/ 
char *get_ip(char *dev_ip) {
    int rc;
    int ip_len=strlen(dev_ip);
    if (ip_len < 8) {
        return strdup(dev_ip);
    }
    char mapping_prefix[8];
    strncpy(mapping_prefix, dev_ip, 7);
    mapping_prefix[7]= '\0';
    //    char *ip = NULL;
    rc = strcmp(mapping_prefix, MAPPED_IPV4_PREFIX);
    
    if (!rc && is_dot_present(dev_ip)) {
        char *ip = (char *)malloc(sizeof(char) *(ip_len-7+1));//1 for terminating null character
        strncpy(ip, &dev_ip[7], ip_len-7);
        ip[ip_len - 7] = '\0';
        return ip;
    } else {
        return strdup(dev_ip);
    }
    
}

/**
*   @brief  Sets the paramaters like client_map,time stamp,loginpoint name, port etc.
*   @return void
*/
void set_config_parameters() {
    config = get_json_from_config_file(config_path);
    
	client_map = get_json_object_from_json(config, "client_map");
	col_type = get_string_value_from_json(config, "col_type");
	lp_name = get_string_value_from_json(config, "loginspect_name");
	port = get_integer_value_from_json(config, "port");
    no_of_threads = get_integer_value_from_json(config, "no_of_threads");
    queue_size = get_integer_value_from_json(config, "queue_size");
}

/**
*   @brief  Create message id
*   @param[in]  dev_ip device ip
*   @param[in]  col_ts time stamp of netflow message(in sec)
*   @param[in]  counter  counts the message per sec
*   @return mid
*/
char *inl_get_message_id(char *dev_ip){
    
    /* increasing log_counter and update col_ts */
    long col_ts;
    time_t now;
    now = time(0);
    col_ts = (long)now;
    
    g_mutex_lock(&mutex_log_counter);
    if(col_ts > last_col_ts)
    {
        last_col_ts = col_ts;
        log_counter = 0;
    }
    log_counter += 1;
    
    char *mid;
    //char *mid = (char *) malloc(100);
    //memset(mid, 0, 100);
    asprintf(&mid, "%s|%s|%s|%010ld|%06ld", lp_name, col_type, dev_ip, col_ts, log_counter);
    g_mutex_unlock(&mutex_log_counter);
    return mid;
}

/* @brief   Prints the v5 binary data in hexadecimal format */
void print_string(received_data_v5_t *pkt) {
    zlog_debug(c,"Printing pkt");
    int i;
    for (i=0; i<(sizeof(pkt->str) + 1); i++) {
        zlog_debug(c,": %02x", ((unsigned char *)(pkt->str))[i]);
    }
    // putchar('\n');
}

/** 
*   @brief  Form string from binary data and return it.
*   @param[in]  msg     Bianry data.
*   @param[in]  len     Length of msg.
*   @return     Returns hexadecimal string of binary data.
*/
char *get_raw_msg(unsigned char *msg, int len) {
    /* puts("Making raw data for version 9");   */
    char *total_raw = malloc(sizeof(char)*(len * 2 + 1));
    char *total_raw_temp=total_raw;
    memset(total_raw_temp, 0, sizeof(char)*(len * 2 + 1));
    int i;
    for(i=0;i<len;i++)
    {
        sprintf(total_raw_temp, "%02x", msg[i]);
        total_raw_temp+=2;
    }
    total_raw[len*2]='\0';
    // printf("\n");
    return total_raw;
}

/** 
*   @brief  Check if the gievn field type is in LIST_OF_IPV4.
*   @param[in]  template_field_type         uint16 value as field type.
*   @return     Returns 1 if field_type is present in LIST_OF_IPV4 else returns 0.
*/
gboolean check_is_ipv4(uint16_t template_field_type) {
    gboolean found = 0;
    int i;
    for (i = 0; i < sizeof(LIST_OF_IPV4)/sizeof(*LIST_OF_IPV4); i++)
    {
        if (LIST_OF_IPV4[i] == template_field_type) {
            found = 1;
            break;
        }
    }
    return found;
}

/** 
*   @brief  Return the record length required for each template.
*   @param[in]  packet_info         Packet information
*   @param[in]  template_id         Template id for the corresponding template 
*   @param[in]  data_record_len         Length of the data for that template_id
*   @return     Returns length of each record with in data flowset
*/
uint16_t get_each_record_length(packet_info_t *packet_info, uint16_t template_id, uint16_t data_record_len) {
    packet_info_t *info = (packet_info_t *)packet_info;
    
    GHashTable *TEMPLATE_REC_LEN = NULL;
    if (info->version == 9) {
        TEMPLATE_REC_LEN = v9_TEMPLATE_REC_LEN;
    } else if (info->version == 10) {
        TEMPLATE_REC_LEN = v10_TEMPLATE_REC_LEN;
    }
    g_mutex_lock(&mutex_hash_main);
    uint16_t record_length = (uint16_t)GPOINTER_TO_INT(g_hash_table_lookup((GHashTable *) g_hash_table_lookup(TEMPLATE_REC_LEN, info->device_ip), GINT_TO_POINTER(template_id)));
    g_mutex_unlock(&mutex_hash_main);
    zlog_debug(c,"THe length of each record should be : %d", record_length);
    return record_length;
    
}

/** 
*   @brief  Parse v9 and v10 records and creates the final event
*   @param[in]  data_flowset         data flowset pointer
*   @param[in]  template_id_field_type_length_list         GList containing field_type and its length 
*   @param[in]  template_id         template id
*   @param[in]  data_flowset_length         Length of the data flowset for that template_id
*   @param[in]  info         Packet information
*   @param[in]  v9_v10_header_event         Json event containing v9/v10 header fields
*/
static void parse_v9_v10_records(void *data_flowset, GList *template_id_field_type_length_list, int template_id, int data_flowset_length, packet_info_t *info, json_t *v9_v10_header_event)
{
    GList *template_id_field_type_length_list_local =template_id_field_type_length_list;
    data_flowset_length -=4;
    uint16_t each_record_length;
    each_record_length = get_each_record_length(info, template_id, data_flowset_length);

    uint16_t record_count;
    record_count = (uint16_t)(data_flowset_length / each_record_length);
    zlog_debug(c,"There are %d record(s) in this flowset", record_count);

    void *single_data;
    int record_index = 0;
    int field_tuple_count = g_list_length(template_id_field_type_length_list)/2;
    //printf("field tuple count = %d template id= %d record_count = %d\n",field_tuple_count, template_id, record_count);
    
    char *_type_str = malloc(sizeof(char) * MAX_TYPE_LEN * (field_tuple_count+1)+128);
    char *_type_num = malloc(sizeof(char) * MAX_TYPE_LEN * (field_tuple_count+1)+128);
    char *_type_ip = malloc(sizeof(char) * MAX_TYPE_LEN * (field_tuple_count+1)+128);

    for(record_index = 0; record_index < record_count; record_index++) {
        template_id_field_type_length_list_local = g_list_first(template_id_field_type_length_list);

        zlog_debug(c,"%d th record of data", record_index);
        single_data =  data_flowset + record_index * each_record_length;
        /* create a new json event to store the retirieved fields, value */
        json_t *field_value_event;
        field_value_event = json_object(); //needs to be freed
        
        //char *_type_str = "";
        //char *_type_num = "";
        //char *_type_ip = "";
   
        memset(_type_str,0,sizeof(char) * MAX_TYPE_LEN * (field_tuple_count+1) + 128);
        memset(_type_num,0,sizeof(char) * MAX_TYPE_LEN * (field_tuple_count+1) + 128);
        memset(_type_ip,0,sizeof(char) * MAX_TYPE_LEN * (field_tuple_count+1) + 128);
        
        long col_ts;
        time_t now;
        now = time(0);
        col_ts = (long)now;

        char* dev_ip = info->device_ip;
        char *mid = inl_get_message_id(dev_ip);
        zlog_debug(c,"v9_v10 last append mid is :%s", mid);
        
        int i = 0;
        int count;
        for (count=0; count<field_tuple_count; count++) {
            //dbg_list(template_id_field_type_length_list_local);
            uint16_t template_field_type =(uint16_t)GPOINTER_TO_INT(template_id_field_type_length_list_local->data);
            template_id_field_type_length_list_local = g_list_next(template_id_field_type_length_list_local);
            uint16_t template_field_len =(uint16_t)GPOINTER_TO_INT(template_id_field_type_length_list_local->data);
            if(count!=field_tuple_count-1) 
                template_id_field_type_length_list_local = g_list_next(template_id_field_type_length_list_local);
            
            /** retrieve each fields' value  and insert it to event**/
            char *field_type = (char *)(g_hash_table_lookup(NETFLOW_FIELD_TYPES, GINT_TO_POINTER(template_field_type)));

            long double field=0;
            char addr6[INET6_ADDRSTRLEN];
            switch (template_field_len) {
                case 1:
                    field = get_unit(single_data, i , each_record_length);
                    json_object_set_new(field_value_event, field_type, json_integer(field));
                    //asprintf(&_type_num, "%s %s", _type_num, field_type);
                    strcat(_type_num,field_type);
                    strcat(_type_num," ");
                    break;
                    
                case 2:
                    field = get_ntohs(single_data, i , each_record_length);
                    json_object_set_new(field_value_event, field_type, json_integer(field));
                    //asprintf(&_type_num, "%s %s", _type_num, field_type);
                    strcat(_type_num,field_type);
                    strcat(_type_num," ");
                    break;
                    
                case 3:
                    field = get_ntoh24(single_data, i , each_record_length);
                    json_object_set_new(field_value_event, field_type, json_integer(ntohs(field)));
                    //asprintf(&_type_num, "%s %s", _type_num, field_type);
                    strcat(_type_num,field_type);
                    strcat(_type_num," ");
                    break;
                    
                case 4:
                    field = get_ntohl(single_data, i , each_record_length);
                    gboolean is_ipv4 = check_is_ipv4(template_field_type);

                    if (is_ipv4) {
                        uint32_t ip = GUINT32_FROM_BE(field);
                        char buff[INET6_ADDRSTRLEN];

                        g_mutex_lock(&mutex_hash_main);
                        inet_ntop(AF_INET, &ip, buff, INET6_ADDRSTRLEN);

                        json_object_set_new(field_value_event, field_type, json_string(buff));
                        g_mutex_unlock(&mutex_hash_main);
                        
                        //asprintf(&_type_str, "%s %s", _type_str, field_type);
                        //asprintf(&_type_ip, "%s %s", _type_ip, field_type);
                        strcat(_type_str,field_type);
                        strcat(_type_str," ");
                        strcat(_type_ip,field_type);
                        strcat(_type_ip," ");
                    } else {
                        json_object_set_new(field_value_event, field_type, json_integer(field));
                        //asprintf(&_type_num, "%s %s", _type_num, field_type);
                        strcat(_type_num,field_type);
                        strcat(_type_num," ");
                    }
                    break;
                    
                case 8:
                    field = get_ntoh64(single_data, i , each_record_length);
                    json_object_set_new(field_value_event, field_type, json_integer(field));
                    //asprintf(&_type_num, "%s %s", _type_num, field_type);
                    strcat(_type_num,field_type);
                    strcat(_type_num," ");
                    break;
                    
                case 16:
                    inet_ntop(AF_INET6, single_data, addr6, INET6_ADDRSTRLEN);
                    zlog_debug(c,"the string for ipv6 is :%s", addr6);
                    json_object_set_new(field_value_event, field_type, json_string(addr6));
                    //asprintf(&_type_str, "%s %s", _type_str, field_type);
                    //asprintf(&_type_ip, "%s %s", _type_ip, field_type);
                    strcat(_type_str,field_type);
                    strcat(_type_str," ");
                    strcat(_type_ip,field_type);
                    strcat(_type_ip," ");
                    break;
                    
                default:
                    break;
            }
            /* move the offset by template_field_len */
            i += template_field_len;
            
        } /* for (count=0; count< field_count; count++ ) */
        
        /* Send the retrieved v9 packet to upper layer as a whole overview */
        
        /* Insert msgfilling to the json field_value_event */
       // json_object_set_new(field_value_event, "_type_num", json_string(_type_num) );
       // json_object_set_new(field_value_event, "_type_str", json_string(_type_str) );
       // json_object_set_new(field_value_event, "_type_ip", json_string(_type_ip) );

        char *_type_num_header=NULL;
        if (info->version == 9) {
            _type_num_header = "version count sys_uptime unix_secs sequence source_id template_id col_ts";
        } else if (info->version == 10) {
            _type_num_header = "version ipfix_length unix_secs sequence source_id template_id col_ts";
        }
        char *_type_str_header = "msg device_name device_ip collected_at col_type";
        // char *_type_num_header = "version count sys_uptime unix_secs sequence source_id template_id col_ts";
        char *_type_ip_header = "device_ip";

        // asprintf(&_type_str, "%s %s", _type_str, _type_str_header);
        // asprintf(&_type_num, "%s %s", _type_num, _type_num_header);
        // asprintf(&_type_ip, "%s %s", _type_ip, _type_ip_header);
        strcat(_type_str,_type_str_header);
        strcat(_type_num,_type_num_header);
        strcat(_type_ip,_type_ip_header);
        g_mutex_lock(&mutex_log_counter);
        json_t *v9_v10_msgfill_event = json_pack("{s:s, s:s, s:s, s:i, s:i, s:s, s:s}", \
            "_type_str", _type_str, "_type_num", _type_num, "_type_ip", _type_ip, \
            "col_ts", col_ts, "_counter", log_counter, "col_type", col_type, "mid", mid);
        g_mutex_unlock(&mutex_log_counter);
        json_t *normalized_fields = json_object_get(v9_v10_header_event,"_normalized_fields");
        json_object_set_new(normalized_fields,"template_id",json_integer(template_id));
        json_object_update(normalized_fields, field_value_event);
        json_object_update(v9_v10_header_event,  v9_v10_msgfill_event);
        
        
        /* update the log counter and receive mid accordingly */
        const char *normalizer, *repo;
        normalizer = get_string_value_from_json(info->dev_config, "normalizer");
        repo = get_string_value_from_json(info->dev_config, "repo");

        send_event_with_mid(sender, v9_v10_header_event, normalizer, repo);
#ifdef DEBUG
    char *json_st;
    json_st = json_dumps(v9_v10_header_event, JSON_INDENT(4));
    zlog_debug(c,"Data is: %s", json_st);
    free(json_st);
#endif

        zlog_debug(c,"msg sent to upper layer");
        AFREE(mid);
        json_decref(v9_v10_msgfill_event);
        json_decref(field_value_event);
        
    }
    AFREE(_type_str);
    AFREE(_type_ip);
    AFREE(_type_num);        
}

/** 
*   @brief  Parse v9 and v10 flowsets 
*   @param[in]  data_flowset         data flowset pointer
*   @param[in]  data_flowset_length         Length of the data flowset for that template_id
*   @param[in]  info         Packet information
*   @param[in]  v9_v10_header_event         Json event containing v9/v10 header fields
*/
static void parse_v9_v10_flowset(void *data_flowset, int data_flowset_length, packet_info_t *info, json_t *v9_v10_header_event) {
    // zlog_debug(c,"Parsing v9 records TEMPLATE and DATA for :%s\n", info->device_ip);
    // char *device_ip = info->device_ip;
    
    /*  if device_ip in TEMPLATE_CACHE process for each template_id within that device_ip */
    
    // zlog_debug(c,"Size of TEMPLATE table: %d \n ", g_hash_table_size(TEMPLATE_CACHE));
    int template_id;
    uint32_t            size_left;
    void                *data_record;
    
    template_id = GET_FLOWSET_ID(data_flowset, data_flowset_length);
    size_left = data_flowset_length - 4;    // -4 for data flowset header -> id and length
    
    /*  map input buffer as a byte array */
    data_record  = data_flowset + 4;    // skip flowset header
    
    if ( size_left < 4 ) {
        zlog_warn(c,"Corrupt data flowset? Pad bytes: %u, table record_size: %u",
                   size_left, data_flowset_length);
        return;
    }
    
    GHashTable *TEMPLATE_CACHE=NULL;
    
    if (info->version == 9) {
        TEMPLATE_CACHE = v9_TEMPLATE_CACHE;
    } else if (info->version == 10) {
        TEMPLATE_CACHE = v10_TEMPLATE_CACHE;
    }
    
    g_mutex_lock(&mutex_hash_main);
    GHashTable *template_id_field_type_length_list_dict;
   
    template_id_field_type_length_list_dict = (GHashTable *)(g_hash_table_lookup(TEMPLATE_CACHE, info->device_ip));   

    if (template_id_field_type_length_list_dict == NULL) {
        zlog_info(c,"Could not find the device %s in TEMPLATE_CACHE", info->device_ip);
        g_mutex_unlock(&mutex_hash_main);
    } else {

        GList *template_id_field_type_length_list;
        template_id_field_type_length_list = (GList *)(g_hash_table_lookup(template_id_field_type_length_list_dict, GINT_TO_POINTER(template_id)));
        if(template_id_field_type_length_list==NULL)
        {
            zlog_info(c,"Count not find the template id %d in TEMPLATE_CACHE", template_id);
            g_mutex_unlock(&mutex_hash_main);
        }
        else
        {
            
            GList *template_id_field_type_length_list_cpy = g_list_copy (template_id_field_type_length_list);
            g_mutex_unlock(&mutex_hash_main); 
            parse_v9_v10_records(data_record,template_id_field_type_length_list_cpy,template_id,data_flowset_length, info , v9_v10_header_event);   
            g_list_free(template_id_field_type_length_list_cpy);
        }
    }  
}


/**
*   @brief  Destroys the template GHash key
*/
void template_hash_key_destroy_cb(gpointer data)
{
    //printf("destroy key: %s\n",(char*)data);
}


/**
*   @brief  Destroys the template GHash key
*/
void template_hash_value_destroy_cb(gpointer data)
{
    //dbg_list((GList *)data);
    g_list_free ((GList *)data);
}


/**
*   @brief  Destroys the template_len GHash key
*/
void template_len_hash_key_destroy_cb(gpointer data)
{
    //nothing
}

/**
*   @brief  Destroys the template_hash GHash key
*/
void template_len_value_destroy_cb(gpointer data)
{
    //nothing
}

/** 
*   @brief  Process v9/v10 templates and update the template_field_type_length_list and TEMPLATE_CACHE
*   @param[in]  v9_v10_event         json event containing header fields
*   @param[in]  template_flowset         template flowset pointer (Binary template flowset) 
*   @param[in]  template_size_left         size of template flowset
*   @param[in]  info         Packet information
*/
static void process_v9_v10_templates(json_t *v9_v10_event, void *template_flowset, int template_size_left, packet_info_t *info) {
//    zlog_debug(c,"Processing v9 templates\n");
    void *template;
    uint16_t	template_id, field_count, field_type, field_length;
    uint32_t	size_left, template_size;
    size_left = GET_FLOWSET_LENGTH(template_flowset, template_size_left) - 4;   // -4 for flowset header -> id and length
	template  = template_flowset + 4;       // the template description begins at offset 4
    
	// process all templates in flowset, as long as any bytes are left
	template_size = 0;

    /** make temporary hash tables and use according to versions **/
    GHashTable *TEMPLATE_CACHE;
    GHashTable *TEMPLATE_REC_LEN;

    if (info->version == 9) {
        zlog_debug(c,"Version recived is 9");
        TEMPLATE_CACHE = v9_TEMPLATE_CACHE;
        TEMPLATE_REC_LEN = v9_TEMPLATE_REC_LEN;
    } else if (info->version == 10) {
        zlog_debug(c,"Version recived is 10");
        TEMPLATE_CACHE = v10_TEMPLATE_CACHE;
        TEMPLATE_REC_LEN = v10_TEMPLATE_REC_LEN;
    }
    
    /*
    each_template_dict = list of (key,val)  ==>    {template_id:[(field_type, length)]}
    */

    while (size_left) {
        template = template + template_size;
        
        template_id = GET_TEMPLATE_ID(template, size_left);
		field_count = GET_TEMPLATE_COUNT(template, size_left);
		template_size = 4 + 4 * field_count;	// id + count = 4 bytes, and 2 x 2 bytes for each entry
        
        // zlog_debug(c,"\n[%u] Template ID: %u\n", "exporter->exporter_id", template_id);
        // zlog_debug(c,"template size: %u count: %u\n", template_size, field_count);
        
        /* msgfillig and sending template data to upper layer. */
        long col_ts;
        time_t now;
        now = time(0);
        col_ts = (long)now;

        char* mid;
        char* dev_ip = info->device_ip;
        mid = inl_get_message_id(dev_ip);
        zlog_debug(c,"v9 v10 inside mid is :%s", mid);
        
        char *_type_num=NULL;
        if (info->version == 9) {
            _type_num = "version count sys_uptime unix_secs sequence source_id template_id template_length col_ts";
        } else if (info->version == 10) {
            _type_num = "version ipfix_length unix_secs sequence source_id template_id template_length col_ts";
        }
        char *_type_str = "msg device_name device_ip collected_at col_type";
        char *_type_ip = "device_ip";
        json_error_t error;

        g_mutex_lock(&mutex_log_counter);
        json_t *v9_v10_template_event = json_pack_ex(&error,0,
            "{s:s,s:s, s:s, s:i, s:i, s:s, s:s}", \
            "_type_str", _type_str, "_type_num", _type_num, "_type_ip", _type_ip, \
            "col_ts", col_ts, "_counter", log_counter, "col_type", col_type, "mid", mid);
        g_mutex_unlock(&mutex_log_counter);
        
        if(v9_v10_template_event==NULL)
        {
            zlog_error(c, "Error: %d:%d: %s", error.line, error.column, error.text);
        }

        free(mid);

        json_t *normalized_fields = json_object_get(v9_v10_event,"_normalized_fields");
        json_object_set_new(normalized_fields,"template_id",json_integer(template_id));
        json_object_set_new(normalized_fields,"field_count",json_integer(field_count));
        json_object_set_new(normalized_fields,"template_length",json_integer(template_size));
        
        json_object_update(v9_v10_template_event, v9_v10_event);
        
        const char *normalizer, *repo;
        normalizer = get_string_value_from_json(info->dev_config, "normalizer");
        repo = get_string_value_from_json(info->dev_config, "repo");
        send_event_with_mid(sender, v9_v10_template_event, normalizer, repo);
        
#ifdef DEBUG
        char *json_st;
        json_st = json_dumps(v9_v10_template_event, JSON_INDENT(4));
        zlog_debug(c,"Event is packet: %s", json_st);
        free(json_st);
#endif
        json_decref(v9_v10_template_event);
        
        
        
        if ( size_left < template_size ) {
			zlog_warn(c, "process_v9_v10: [%s] buffer size error: expected %u available %u",
                   "exporter->exporter_id", template_size, size_left);
			size_left = 0;
			continue;
		}
        
        /* Create a template_template_list = [(temp_id, fi_count, each_data[4:])]
        and template_data_dict = {temp_id: each_data[4:]}   */
        
        GList *template_field_type_length_list = NULL;
        int count = 1;
        int each_size_left = template_size - 4;
        gpointer each_data = template + 4; //move 4 bytes ahead (skip template_id and field_count
        int rec_length = 0;
        for(count=1; count<= field_count; count++) {
            /*Parse the template_field_type and its length
            and append to template_field_type_data_list */
            field_type = get_ntohs(each_data, 0, each_size_left);
            field_length = get_ntohs(each_data, 2, each_size_left);
            
            rec_length += field_length;
            //zlog_debug(c,"Count : %d, Testing filed type : %d and lenght %d \n", count ,field_type, field_length);
            
            template_field_type_length_list = g_list_prepend(template_field_type_length_list, GINT_TO_POINTER(field_type));
            template_field_type_length_list = g_list_prepend(template_field_type_length_list, GINT_TO_POINTER(field_length));
            
            each_data += 4; //increase the pointer by 4 for field and type
            each_size_left -= 4; //decrease the lenght of each_data
            
        }
        template_field_type_length_list = g_list_reverse(template_field_type_length_list);
        
    
        /* Update the TEMPLATE_CACHE and destroy the current hash table */
        zlog_debug(c,"Inserting :%s in TEMPLATE_CACHE", info->device_ip);
        g_mutex_lock (&mutex_hash_main);
        GHashTable *t_template_id_field_type_length_list_dict = NULL;
        t_template_id_field_type_length_list_dict = (GHashTable *)(g_hash_table_lookup(TEMPLATE_CACHE, info->device_ip));
        
        GHashTable *t_template_rec_length = NULL;   //For rec_length
        t_template_rec_length = (GHashTable *)(g_hash_table_lookup(TEMPLATE_REC_LEN, info->device_ip));
        
        
        if (t_template_id_field_type_length_list_dict == NULL) { //insert new record

            GHashTable *each_template_id_list_dict = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, template_hash_value_destroy_cb);
    
            GHashTable *template_rec_length = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    
            zlog_debug(c,"Inserting template_id: %d: device_ip: %s", template_id, info->device_ip);
            //template
            g_hash_table_insert(each_template_id_list_dict, GINT_TO_POINTER(template_id), template_field_type_length_list);
            g_hash_table_insert(TEMPLATE_CACHE, strdup(info->device_ip), each_template_id_list_dict);
            
            //template record length
            g_hash_table_insert(template_rec_length, GINT_TO_POINTER(template_id),  GINT_TO_POINTER(rec_length));
            g_hash_table_insert(TEMPLATE_REC_LEN , strdup(info->device_ip), template_rec_length);
            
        } else { //update existing record
            /* Iterate through each template and append it to each_template_id_list_dict */
            zlog_debug(c,"device :%s is already found; appending template :%d", info->device_ip, template_id);

            g_hash_table_insert(t_template_id_field_type_length_list_dict, GINT_TO_POINTER(template_id), template_field_type_length_list);
            g_hash_table_insert(t_template_rec_length, GINT_TO_POINTER(template_id),  GINT_TO_POINTER(rec_length));

        } /* end inserting template_id : list   */
        g_mutex_unlock(&mutex_hash_main);
        size_left -= template_size;
    }
}

/** 
*   @brief  Process v9/v10 option templates, update the TEMPLATE_CACHE and TEMPLATE_REC_LEN
*   @param[in]  v9_v10_event         json event containing header fields
*   @param[in]  option_template_flowset         option template flowset pointer (Binary template flowset) 
*   @param[in]  template_size_left         size of option template flowset
*   @param[in]  info         Packet information
*/
static void process_v9_v10_option_templates(json_t* v9_v10_event, void *option_template_flowset, int template_size_left, packet_info_t *info) {
    zlog_debug(c,"Processing v9 option templates");
    void        *option_template;
    uint16_t	option_template_id, option_field_type;
    uint16_t    option_scope_field_count, option_total_field_count;     //v10
    uint16_t    option_scope_field_length, option_field_length;   //v9
    uint32_t	size_left, option_template_size;
    
    /* make temporary hash tables and use according to versions */
    GHashTable *TEMPLATE_CACHE;
    GHashTable *TEMPLATE_REC_LEN;
    if (info->version == 9) {
        zlog_debug(c,"Version recived is 9 ");
        TEMPLATE_CACHE = v9_TEMPLATE_CACHE;
        TEMPLATE_REC_LEN = v9_TEMPLATE_REC_LEN;
    } else if (info->version == 10) {
        zlog_debug(c,"Version recived is 1");
        TEMPLATE_CACHE = v10_TEMPLATE_CACHE;
        TEMPLATE_REC_LEN = v10_TEMPLATE_REC_LEN;
    }
    
    
    size_left = GET_FLOWSET_LENGTH(option_template_flowset, template_size_left) - 6;   // -4 for flowset header -> id and length
	option_template  = option_template_flowset + 4;       // the template description begins at offset 4
    
    // process all templates in flowset, as long as any bytes are left
	option_template_size = 0;
    
    while (size_left) {
        option_template = option_template + option_template_size;
        option_template_id = GET_OPTION_TEMPLATE_ID(option_template, size_left);
        
        // option_template_size = ((option_template_size / 4) +  1 ) * 4;


        /* msgfillig and sending option template data to upper layer. */
        long col_ts;
        time_t now;
        now = time(0);
        col_ts = (long)now;

        char* mid;
        char* dev_ip = info->device_ip;
        mid = inl_get_message_id(dev_ip);
        zlog_debug(c,"v9 v10 inside mid is :%s", mid);
        

        json_t *v9_v10_template_event=NULL;
        json_error_t error;
        
        if(info->version == 9) {
            option_scope_field_length = GET_OPTION_TEMPLATE_OPTION_SCOPE_LENGTH(option_template, size_left);
            option_field_length = GET_OPTION_TEMPLATE_OPTION_LENGTH(option_template, size_left);
        
            option_total_field_count = (uint16_t) ((option_scope_field_length + option_field_length) / 4);
            
            /** for msg filling 9*/
            char *_type_str = "msg device_name device_ip collected_at col_type";
            char *_type_num = "version count sys_uptime unix_secs sequence source_id option_template_id option_scope_field_length option_field_length option_total_field_count col_ts";
            char *_type_ip = "device_ip";
            

            g_mutex_lock(&mutex_log_counter);
            v9_v10_template_event = json_pack_ex(&error,0,\
                "{s:s,s:s, s:s, s:i, s:i, s:s, s:s}", \
                "_type_str", _type_str, "_type_num", _type_num, "_type_ip", _type_ip, \
                "col_ts", col_ts, "_counter", log_counter, "col_type", col_type, "mid", mid);
            g_mutex_unlock(&mutex_log_counter);

            if(v9_v10_template_event==NULL)
            {
                zlog_error(c, "Error: %d:%d: %s", error.line, error.column, error.text);
            }

            free(mid);

            json_t *normalized_fields = json_object_get(v9_v10_event,"_normalized_fields");
            json_object_set_new(normalized_fields,"option_template_id",json_integer(option_template_id));
            json_object_set_new(normalized_fields,"option_scope_field_length",json_integer(option_scope_field_length));
            json_object_set_new(normalized_fields,"option_field_length",json_integer(option_field_length));
            json_object_set_new(normalized_fields,"option_total_field_count",json_integer(option_total_field_count));


        }
        else if (info->version == 10) {
            option_total_field_count = GET_OPTION_TEMPLATE_OPTION_SCOPE_LENGTH(option_template, size_left);
            option_scope_field_count = GET_OPTION_TEMPLATE_OPTION_LENGTH(option_template, size_left);
            

            /* for msg filling 10*/
            char *_type_str = "msg device_name device_ip collected_at col_type";
            char *_type_num = "version ipfix_length unix_secs sequence source_id option_template_id option_scope_field_count option_total_field_count col_ts";
            char *_type_ip = "device_ip";

            g_mutex_lock(&mutex_log_counter);
            v9_v10_template_event = json_pack_ex(&error,0,\
                "{s:s,s:s, s:s, s:i, s:i, s:s, s:s}", \
                "_type_str", _type_str, "_type_num", _type_num, "_type_ip", _type_ip, \
                "col_ts", col_ts, "_counter", log_counter, "col_type", col_type, "mid", mid);
            g_mutex_unlock(&mutex_log_counter);

            if(v9_v10_template_event==NULL)
            {
                zlog_error(c, "Error: %d:%d: %s", error.line, error.column, error.text);
            }

            free(mid);

            json_t *normalized_fields = json_object_get(v9_v10_event,"_normalized_fields");
            json_object_set_new(normalized_fields,"option_template_id",json_integer(option_template_id));
            json_object_set_new(normalized_fields,"option_scope_field_count",json_integer(option_scope_field_count));
            json_object_set_new(normalized_fields,"option_total_field_count",json_integer(option_total_field_count));
        }
        
        
        /* sending the opetion template to upper layer */
        json_object_update(v9_v10_template_event, v9_v10_event);
        


        const char *normalizer, *repo;
        normalizer = get_string_value_from_json(info->dev_config, "normalizer");
        repo = get_string_value_from_json(info->dev_config, "repo");

        option_template_size = 6 + 4 * option_total_field_count;    // id + count + option = 6 bytes, and 2 x 2 bytes for each entry

        send_event_with_mid(sender, v9_v10_template_event, normalizer, repo);

#ifdef DEBUG
        char *json_st;
        json_st = json_dumps(v9_v10_template_event, JSON_INDENT(4));
        zlog_debug(c,"TETETE Event is packet: %s", json_st);
        free(json_st);
#endif
        
        json_decref(v9_v10_template_event);
        
        // zlog_debug(c,"\n[%u] OPTION Template ID: %u", "exporter->exporter_id", option_template_id);
		zlog_debug(c,"template size: %u count: %u", option_template_size, option_total_field_count);
        
        if ( size_left < option_template_size ) {
			zlog_debug(c,"process_v10: [%s] buffer size error: expected %u available %u",
                   "exporter->exporter_id", option_template_size, size_left);
			size_left = 0;
			continue;
		}
        
        /*  Create a template_template_list = [(temp_id, fi_count, each_data[4:])]
        and template_data_dict = {temp_id: each_data[4:]} */
        
        GList *option_template_field_type_length_list = NULL;
        int count = 1;
        int each_size_left = option_template_size - 6;
        gpointer each_data = option_template + 6; //move 4 bytes ahead (skip template_id and field_count
        int option_rec_length = 0;
        for(count=1; count<= option_total_field_count; count++) {
            /* Parse the template_field_type and its length
            and append to template_field_type_data_list */
            // GList *option_each_field_length_tuple = NULL;
            option_field_type = get_ntohs(each_data, 0, each_size_left);
            option_field_length = get_ntohs(each_data, 2, each_size_left);
            
            option_rec_length += option_field_length;
            zlog_debug(c,"option_Count : %d, option_Testing filed type : %d and lenght %d \n", count ,option_field_type, option_field_length);
            
            option_template_field_type_length_list = g_list_prepend(option_template_field_type_length_list, GINT_TO_POINTER(option_field_type));
            option_template_field_type_length_list = g_list_prepend(option_template_field_type_length_list,  GINT_TO_POINTER(option_field_length));
            
            // option_template_field_type_length_list = g_list_append(option_template_field_type_length_list, option_each_field_length_tuple);
            
            each_data += 4; //increase the pointer by 4 for field and type
            each_size_left -= 4; //decrease the lenght of each_data
               
        }
        option_template_field_type_length_list = g_list_reverse(option_template_field_type_length_list);
        
        g_mutex_lock (&mutex_hash_main);
        /* Update the TEMPLATE_CACHE and destroy the current hash table */
        zlog_debug(c,"option_Inserting :%s in TEMPLATE_CACHE", info->device_ip);
        GHashTable *t_option_template_id_field_type_length_list_dict = NULL;
        t_option_template_id_field_type_length_list_dict = (GHashTable *)(g_hash_table_lookup(TEMPLATE_CACHE, info->device_ip));
        
        GHashTable *t_option_template_rec_length = NULL;   //For rec_length
        t_option_template_rec_length = (GHashTable *)(g_hash_table_lookup(TEMPLATE_REC_LEN, info->device_ip));
        
        if (t_option_template_id_field_type_length_list_dict == NULL) { //insert new record


            //
            GHashTable *each_option_template_id_list_dict = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, template_hash_value_destroy_cb);
    
            GHashTable *option_template_rec_length = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    
            zlog_debug(c,"Inserting option template_id: %d: device_ip: %s", option_template_id, info->device_ip);
            //template
            g_hash_table_insert(each_option_template_id_list_dict, GINT_TO_POINTER(option_template_id), option_template_field_type_length_list);
            g_hash_table_insert(TEMPLATE_CACHE, strdup(info->device_ip), each_option_template_id_list_dict);
            
            //template record length
            g_hash_table_insert(option_template_rec_length, GINT_TO_POINTER(option_template_id),  GINT_TO_POINTER(option_rec_length));
            g_hash_table_insert(TEMPLATE_REC_LEN , strdup(info->device_ip), option_template_rec_length);

            
        } else { //update existing record
            /* Iterate through each template and append it to each_template_id_list_dict */
            
            zlog_debug(c,"device :%s is already found; appending template :%d\n", info->device_ip, option_template_id);
            //zlog_debug(c,"option_before inserting");
            
            g_hash_table_insert(t_option_template_id_field_type_length_list_dict, GINT_TO_POINTER(option_template_id), option_template_field_type_length_list);
            g_hash_table_insert(t_option_template_rec_length, GINT_TO_POINTER(option_template_id),GINT_TO_POINTER(option_rec_length));
            
        } /* end inserting template_id : list */
        g_mutex_unlock(&mutex_hash_main);
        /* At last decrease the size_left */
        size_left -= option_template_size;
    }
}


/** 
*   @brief  Returns the well parsed v9 header
*   @param[in]  flowset     flowset pointer (Binary flowset)
*   @return  v9_header as netflow_v9_header_t type
*/
static netflow_v9_header_t * get_v9_header(void *flowset)
{
    netflow_v9_header_t *v9_header = (netflow_v9_header_t *) flowset;
    v9_header->version = ntohs(v9_header->version);
    v9_header->count = ntohs(v9_header->count);
    v9_header->sys_uptime = ntohl(v9_header->sys_uptime);
    v9_header->unix_secs = ntohl(v9_header->unix_secs);
    v9_header->sequence = ntohl(v9_header->sequence);
    v9_header->source_id = ntohl(v9_header->source_id);
    
    /* testing header
    zlog_debug(c,"Version : %u\n", v9_header->version);
    zlog_debug(c,"  Number of exported flows: %u\n", v9_header->count);
    zlog_debug(c,"  Uptime                  : %u ms\n", v9_header->sys_uptime);
    zlog_debug(c,"  Epoch                   : %u\n", v9_header->unix_secs);
    zlog_debug(c,"  Sequence                : %u\n", v9_header->sequence);
    zlog_debug(c,"  Source ID               : %u\n", v9_header->source_id);
    */
    return v9_header;
}

/** 
*   @brief  Returns msgfilled v9 header event
*   @param[in]  v9_event     v9 header event without msgfilling (field types)
*   @param[in]  _raw_msg_b     base64 encoded bnary string 
*   @param[in]  info     Packet information
*   @return  msgfilled v9 header json event
*/
static json_t *generate_v9_msgfill_header_event(json_t *v9_event, void *_raw_msg_b,  packet_info_t *info)
{
    long col_ts;
    time_t now;
    now = time(0);
    col_ts = (long)now;

    char* dev_ip = info->device_ip;
    char *mid = inl_get_message_id(dev_ip);
    zlog_debug(c,"v9 inside mid is :%s", mid);

//        v9_msgfill_event = json_object();
    char *_type_str = "msg device_name device_ip collected_at col_type";
    char *_type_num = "version count sys_uptime unix_secs sequence source_id col_ts";
    char *_type_ip = "device_ip";

    g_mutex_lock(&mutex_log_counter);
    json_t *v9_msgfill_event = json_pack("{s:s, s:s, s:s, s:{s:s}, s:i, s:i, s:s, s:s}", \
        "_type_str", _type_str, "_type_num", _type_num, "_type_ip", _type_ip, "_to_preserve", "_p__raw_msg_b", _raw_msg_b, \
        "col_ts", col_ts, "_counter", log_counter, "col_type", col_type, "mid", mid);
    g_mutex_unlock(&mutex_log_counter);


    json_object_update(v9_msgfill_event, v9_event);

    free(mid);
    return v9_msgfill_event;
}

/** 
*   @brief  Returns the  well parsed v10 header
*   @param[in]  flowset     flowset pointer (Binary flowset)
*   @return  v10_header as netflow_v10_header_t type
*/
static netflow_v10_header_t * get_v10_header(void *flowset)
{
    netflow_v10_header_t *v10_header = (netflow_v10_header_t *) flowset;
        
    v10_header->version = ntohs(v10_header->version);
    v10_header->ipfix_length = ntohs(v10_header->ipfix_length);
    v10_header->unix_secs = ntohl(v10_header->unix_secs);
    v10_header->sequence = ntohl(v10_header->sequence);
    v10_header->source_id = ntohl(v10_header->source_id);
    
    /* testing header */
     zlog_debug(c,"Version : %u", v10_header->version);
     zlog_debug(c,"  Length of exported flows: %u", v10_header->ipfix_length);
     zlog_debug(c,"  Epoch                   : %u", v10_header->unix_secs);
     zlog_debug(c,"  Sequence                : %u", v10_header->sequence);
     zlog_debug(c,"  Source ID               : %u", v10_header->source_id);
     //**/
    return v10_header;
}

/** 
*   @brief  Returns msgfilled v10 header event
*   @param[in]  v10_event     v10 header event without msgfilling (field types)
*   @param[in]  _raw_msg_b     base64 encoded bnary string 
*   @param[in]  info     Packet information
*   @return  msgfilled v10 header json event
*/
static json_t *generate_v10_msgfill_header_event(json_t *v10_event, void *_raw_msg_b,  packet_info_t *info)
{
    long col_ts;
    time_t now;
    now = time(0);
    col_ts = (long)now;

    char* mid;
    char* dev_ip = info->device_ip;
    mid = inl_get_message_id(dev_ip);
    zlog_debug(c,"v10 inside mid is :%s", mid);
        
    /** for msgfilling and updating **/
    // v9_msgfill_event = json_object();
    char *_type_str = "msg device_name device_ip collected_at col_type";
    char *_type_num = "version ipfix_length unix_secs sequence source_id col_ts";
    char *_type_ip = "device_ip";

    g_mutex_lock(&mutex_log_counter);
    json_t *v10_msgfill_event = json_pack("{s:s, s:s, s:s, s:{s:s}, s:i, s:i, s:s, s:s}", \
        "_type_str", _type_str, "_type_num", _type_num, "_type_ip", _type_ip, "_to_preserve", "_p__raw_msg_b", _raw_msg_b, \
        "col_ts", col_ts, "_counter", log_counter, "col_type", col_type, "mid", mid);
    g_mutex_unlock(&mutex_log_counter);

    json_object_update(v10_msgfill_event, v10_event);
    
    free(mid);    
    return v10_msgfill_event;
}

/** 
*   @brief  Process v9/v10 packets 
*   @param[in]  _raw_msg_b     base64 encoded binary string 
*   @param[in]  flowset     v9/v10 packet pointer (Binary packet)
*   @param[in]  info     Packet information
*/
static void process_v9_v10(char *_raw_msg_b, void *flowset, packet_info_t *info) {
    
//    zlog_debug(c,"Parsing v9, v10 data\n");  
    if (info->version == 9) {
        //send header info
        void *flowset_header;
        size_t size_left;
        size_left = info->len;
        
        if (size_left <= NETFLOW_V9_HEADER_LENGTH) {
            zlog_debug(c,"process_v9_v10: Too little data for v9 packets");
        }
        
        /*parse the header */
        
        /* Send the received packects info to upper layer along with _p__raw_msg_b */
        netflow_v9_header_t *v9_header = get_v9_header(flowset);
        json_t *v9_event =create_json_object_packet(v9_header, info);
        json_t *v9_msgfill_event = generate_v9_msgfill_header_event(v9_event, _raw_msg_b, info);
        
        /* Send the retrieved v9 packet to upper layer as a whole overview */
        
        const char *normalizer, *repo;
        normalizer = get_string_value_from_json(info->dev_config, "normalizer");
        repo = get_string_value_from_json(info->dev_config, "repo");

        send_event_with_mid(sender, v9_msgfill_event, normalizer, repo);
#ifdef DEBUG
        char *json_st;
        json_st = json_dumps(v9_msgfill_event, JSON_INDENT(4));
        zlog_debug(c,"V9 Template Event is: %s", json_st);
        free(json_st);
#endif
        json_decref(v9_msgfill_event);
        
        /* After Header */
        flowset_header = (void *) v9_header + NETFLOW_V9_HEADER_LENGTH;
        size_left -= NETFLOW_V9_HEADER_LENGTH;
        
        uint32_t flowset_length, flowset_id;
        
        /* iterate over all flowsets in export packet, while there are bytes left   */
        flowset_length = 0;
        while (size_left) {
            flowset_header = flowset_header + flowset_length;
            flowset_id 		= GET_FLOWSET_ID(flowset_header, size_left);
            flowset_length 	= GET_FLOWSET_LENGTH(flowset_header, size_left);
            
            zlog_debug(c,"Flowset id : %d and Flowset Length: %d", flowset_id, flowset_length);
            
            if ( flowset_length < 4) {
                /* 	this should never happen, as 4 is an empty flowset
                 and smaller is an illegal flowset anyway ...
                 if it happends, we can't determine the next flowset, so skip the entire export packet
                 */
                zlog_warn(c,"flowset length error. is too short for a flowset");
                return;
            }
            
            if ( flowset_length > size_left ) {
                zlog_warn(c,"flowset length error: size_left: %zd flowset_length: %u",size_left,flowset_length);
                size_left = 0;
                continue;
            }
            switch (flowset_id) {
                    
                case FLOWSET_ID_V9_DATA_TEMPLATE:
                    /*  process the netflow template and save on the basis of exporter  */
                    process_v9_v10_templates(v9_event, flowset_header, flowset_length, info);
                    break;
                    
                case FLOWSET_ID_V9_OPTIONS_TEMPLATE:
                    /*  process the netflow option template as per exporter */
                    process_v9_v10_option_templates(v9_event, flowset_header, flowset_length, info);
                    break;
                    
                default: {
                    if ( flowset_id < FLOWSET_ID_DATA_MIN || flowset_id > FLOWSET_ID_DATA_MAX) {
                        zlog_warn(c,"Invalid flowset id: %u", flowset_id);
                    }
                    parse_v9_v10_flowset(flowset_header, flowset_length, info, v9_event);
                    break;                          
				}
            }
            // next flowset
            size_left -= flowset_length;
            
        } //End of while
        json_decref(v9_event);
        /* Parse the v9 data with updated DATA and TEMPLATE CACHE */        
    }
    else if (info->version == 10) {
        void *flowset_header;
        size_t size_left;
        size_left = info->len;
        
        if (size_left <= NETFLOW_V10_HEADER_LENGTH) {
            zlog_debug(c, "Too little data for 10 packets");
        }
        
        /*parse the header */
        netflow_v10_header_t *v10_header = get_v10_header(flowset);
        json_t *v10_event =create_json_object_packet(v10_header, info);
        json_t *v10_msgfill_event = generate_v10_msgfill_header_event(v10_event, _raw_msg_b, info);
        
        /* Send the retrieved v10 packet to upper layer as a whole overview */
        
        const char *normalizer, *repo;
        normalizer = get_string_value_from_json(info->dev_config, "normalizer");
        repo = get_string_value_from_json(info->dev_config, "repo");
        
        send_event_with_mid(sender, v10_msgfill_event, normalizer, repo);
#ifdef DEBUG
        char *json_st;
        json_st = json_dumps(v10_msgfill_event, JSON_INDENT(4));
        zlog_debug(c,"V10 Template Event is: %s", json_st);
        free(json_st);
#endif
        json_decref(v10_msgfill_event);
        
        /* After Header */
        flowset_header = (void *) v10_header + NETFLOW_V10_HEADER_LENGTH;
        size_left -= NETFLOW_V10_HEADER_LENGTH;
        
        uint32_t flowset_length, flowset_id;
        
        /* iterate over all flowsets in export packet, while there are bytes left */
        flowset_length = 0;
        while (size_left) {
            flowset_header = flowset_header + flowset_length;
            flowset_id 		= GET_FLOWSET_ID(flowset_header, size_left);
            flowset_length 	= GET_FLOWSET_LENGTH(flowset_header, size_left);
            
            zlog_debug(c,"Flowset id : %d and Flowset Length: %d", flowset_id, flowset_length);
            
            if ( flowset_length < 4) {
                /* 	this should never happen, as 4 is an empty flowset
                 and smaller is an illegal flowset anyway ...
                 if it happends, we can't determine the next flowset, so skip the entire export packet
                 */
                zlog_warn(c, "flowset length error. is too short for a flowset");
                return;
            }
            if ( flowset_length > size_left ) {
                zlog_warn(c, "flowset length error: size_left: %zd flowset_length: %d",size_left,flowset_length);
                size_left = 0;
                continue;
            }
            
            switch (flowset_id) {
                    
                case FLOWSET_ID_V10_DATA_TEMPLATE:
                    /*  process the netflow template and save on the basis of exporter */
                    process_v9_v10_templates(v10_event, flowset_header, flowset_length, info);
                    break;
                    
                case FLOWSET_ID_V10_OPTIONS_TEMPLATE:
                    /*  process the netflow option template as per exporter */
                    process_v9_v10_option_templates(v10_event, flowset_header, flowset_length, info);
                    break;
                    
                default: {
                    if ( flowset_id < FLOWSET_ID_DATA_MIN || flowset_id > FLOWSET_ID_DATA_MAX) {
                        zlog_warn(c,"Invalid flowset id: %u", flowset_id);
                    }
                    parse_v9_v10_flowset(flowset_header, flowset_length, info, v10_event);
                    break;
				}
            }       
            // next flowset
            size_left -= flowset_length;
            
        } //End of while
        json_decref(v10_event);
    }
}

/** 
*   @brief  Process v5 packets 
*   @param[in]  message     v5 packet 
*   @param[in]  info     Packet nformation
*   @param[in]  dev_ip     device_ip
*   @param[in]  dev_config     config for corresponding device_ip
*   @param[in]  _raw_msg_b     base64 encoded bnary string
*/
static void netflow_parse_v5(unsigned char *message, packet_info_t *info, char *dev_ip, json_t *dev_config, char *_raw_msg_b)
{
    zlog_debug(c,"Parsing v5 data");
	int flow;
	single_flowset_v5_t single_flow;
    
    netflow_v5hdr_t *hdr = (netflow_v5hdr_t *) message;
	netflow_v5rec_t *rec = NULL;
    
	hdr->flowcount = ntohs(hdr->flowcount);
	hdr->uptime = ntohl(hdr->uptime);
	hdr->unix_ts = ntohl(hdr->unix_ts);
	hdr->unix_tns = ntohl(hdr->unix_tns);
	hdr->sequence = ntohl(hdr->sequence);
	hdr->samp_interval = ntohs(hdr->samp_interval) & ~0xc000;
    
    // zlog_debug(c,"  Number of exported flows: %u\n", hdr->flowcount);
    // zlog_debug(c,"  Uptime                  : %u ms\n", hdr->uptime);
    // zlog_debug(c,"  Epoch                   : %u.%u\n", hdr->unix_ts, hdr->unix_tns);
    // zlog_debug(c,"  Sequence                : %u\n", hdr->sequence);
    // zlog_debug(c,"  Sequence                : %u\n", hdr2->sequence);
    // zlog_debug(c,"  Samplerate              : %u\n", hdr->samp_interval);
    // print_string(pkt);
    
    const char *normalizer, *repo, *device_name;
    normalizer = get_string_value_from_json(dev_config, "normalizer");
    repo = get_string_value_from_json(dev_config, "repo");
    device_name = get_string_value_from_json(dev_config, "device_name");
	for (flow = 0, rec = (netflow_v5rec_t *) (message + sizeof(netflow_v5hdr_t));
	     flow < hdr->flowcount; flow++, rec++)
	{        
		rec->src_port = ntohs(rec->src_port);
		rec->dst_port = ntohs(rec->dst_port);
        
		rec->packets = ntohl(rec->packets);
		rec->bytes = ntohl(rec->bytes);
        
		rec->first_ts = ntohl(rec->first_ts); // / 1000;
		rec->last_ts = ntohl(rec->last_ts); // / 1000;
        rec->snmp_in = ntohs(rec->snmp_in);
        rec->snmp_out = ntohs(rec->snmp_out);
        rec->src_asn = ntohs(rec->src_asn);
        rec->dst_asn = ntohs(rec->dst_asn);
        /* encoding the input binary packet */
        single_flow = (single_flowset_v5_t) {
            .hdr_v5 = hdr,
            .rec_v5 = rec,
            ._p__raw_msg_b = _raw_msg_b,
        };
        
        long col_ts;
        time_t now;
        now = time(0);
        col_ts = (long)now;

        char *mid;
		mid = inl_get_message_id(dev_ip);
        
// #ifdef LPLOG
//                zlog_debug(c,"Flow %d\n", flow);
//                zlog_debug(c,"Source: %s %d\n", srcbuf, rec->src_port);
//                zlog_debug(c,"Destination: %s %d\n", dstbuf, rec->dst_port);
//                zlog_debug(c,"(%d bytes, %d packets)\n",rec->bytes, rec->packets);
//                zlog_debug(c,"Proto: %d, Flag: %d\n",rec->proto, rec->tcp_flags);
// #endif
        
        json_t *event = create_json_object_from_single_struct_v5(&single_flow, lp_name, dev_ip, mid, dev_config, col_ts, log_counter, col_type, device_name);
        
        send_event_with_mid(sender, event, normalizer, repo);
 
		free(mid);
		json_decref(event);
    }
    
}

/**
*   @brief  It will set the max receive buffer size 
*   @param[in] sockfd socket file descriptor
*   @param[in] new_rcvbuff new buffer size to set
*   @param set_rcv_buf 1
*/
static void set_rcv_buf(int sockfd, int new_rcvbuff, int set_rcv_buf)
{
    int rcvbuff;

    socklen_t optlen;
    int res = 0;

    // Get buffer size
    optlen = sizeof(rcvbuff);
    res = getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuff, &optlen);

    if(res == -1)
        zlog_warn(c,"Error getsockopt one");
    else
        zlog_info(c, "old receive buffer size: %d", rcvbuff);
    
    if(set_rcv_buf==1)
    {
        zlog_info(c,"setting the receive buffer to %d", new_rcvbuff);
        res = setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &new_rcvbuff, sizeof(new_rcvbuff));
    }

    if(res == -1)
        zlog_error(c,"Error setsockopt");

    // Get buffer size
    optlen = sizeof(rcvbuff);
    res = getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuff, &optlen);

    if(res == -1)
        zlog_warn(c,"Error getsockopt two");
    else
        zlog_info(c,"new receive buffer size: %d", rcvbuff);
}

// /**
// *   @brief  It will write the backtrace to the log file 
// *   @param[in] sig  signal received
// */
// void do_backtrace(int sig) {
//     void *array[10];
//     size_t size;
//     size = backtrace(array, 10);
//     // print out all the frames to stderr
//     fprintf(stderr, "Error: signal %d:\n", sig);
//     char **str=backtrace_symbols(array,size);
//     backtrace_symbols_fd(array, size, 2); //2 is for stderr
//     int i;
//     zlog_fatal(c, "Signal received: %d",sig);
//     for (i = 0; i < size; i++) {
//     //printf("%s\n", str[i]);
//         zlog_fatal(c, "%s", str[i]);
//     }
//     free(str);
//     exit(sig);
// }

/** 
*   @brief  Handle SIGHUP/SIGINT signal, reload the config parameter
*   @param[in]  signum  signals
*/
void sig_callback(int signum) {
    
    if(signum == 2 || signum == 15) //2 = SIGINT 15 = SIGTERM
    {
        zlog_fatal(c, "Signal received: %d",signum);
        exit(signum);
    }
    else if( signum == 1)
    {
        zlog_debug(c, "Signal received: %d (SIGHUP)",signum);
        signal(SIGHUP,sig_callback); //reset signal
        set_config_parameters(); /* reload config parameters */
    }
}

/**
*   @brief  Parse the recived packets on the basis of version type
*   @param[in] thread_data thread data from buffer for parsing
*   @param[in] user_data any extra data if needed
*   @return void
*/
void parse_data(gpointer thread_data, gpointer user_data)
{
    data_t *data= (data_t *)thread_data;
    char ip[INET6_ADDRSTRLEN];
    errno=0;
    const char *rs = inet_ntop(AF_INET6, &data->client_addr.sin6_addr, ip, INET6_ADDRSTRLEN);
    if(rs == NULL)
    {
        zlog_error(c,"Error: %s",strerror(errno));
        return;
    }
    char *dev_ip = get_ip(ip);
    zlog_debug(c,"The obtained ip is %s and dev_ip is %s", ip, dev_ip);
 
    char *config_ip = get_config_ip(dev_ip, client_map);
    zlog_debug(c,"The config ip for dev_ip:%s is :%s", dev_ip, config_ip);
    if (config_ip == NULL) { 
       zlog_warn(c, "Connection attempted from unregistered IP : %s", dev_ip);
        return;
    }

    json_t *dev_config = get_json_object_from_json(client_map, config_ip);
    if (dev_config==NULL) {
        zlog_warn(c, "Connection attempted from unregistered IP : %s", dev_ip);
        return;
    }

    packet_info_t *info;
    info = (packet_info_t *)malloc(sizeof(packet_info_t));
    info->len = (size_t) data->n;
    info->ts.tv_sec = time(NULL);
    info->device_ip = dev_ip;
    info->dev_config = dev_config;
    info->lp_name = lp_name;
    
    uint16_t *version_r = (uint16_t *)data->message;
    info->version = ntohs(*version_r);
    
    // char *_raw_msg_b = get_raw_msg(data->message, info->len);
    char *_raw_msg_b = g_base64_encode(data->message, info->len);

    if (info->version == 5)
    {
        netflow_parse_v5(data->message, info, info->device_ip, info->dev_config, _raw_msg_b);
    }
    else if (info->version == 9 || info->version == 10)
    {
        process_v9_v10(_raw_msg_b, data->message, info);
    }
    else
    {
        zlog_warn(c,"Not the correct VERSION type.");
    }

    //cleanup
    AFREE(info->device_ip);
    //AFREE(info->dev_config);
    AFREE(info);
    g_free(_raw_msg_b);
    AFREE(data->message);
    AFREE(data);
}


/**
*   @brief  Initializes the thread pool and mutexes for multithreading
*   @return void
*/
static void thread_init(void)
{
    if(g_thread_supported()!= TRUE)
    {
        zlog_fatal(c,"Thread support False. Unable to run the service");
        exit(-1);
    }
    pool= g_thread_pool_new (parse_data, NULL,no_of_threads , FALSE, NULL);
    zlog_info(c,"Number of threads: %d",no_of_threads);
    //max thread
    g_thread_pool_set_max_threads (pool,no_of_threads,NULL );
    zlog_info(c,"Max number of threads: %d",no_of_threads);
    
    //max unused thread
    g_thread_pool_set_max_unused_threads(MAX_UNUSED_THREADS);
    zlog_info(c,"Max unused threads: %d",MAX_UNUSED_THREADS);
    
    //max idle time
    g_thread_pool_set_max_idle_time(MAX_IDLE_TIME_MILLISECOND);
    zlog_info(c,"Max Idle Time: %d",MAX_IDLE_TIME_MILLISECOND);

    //mutex
    g_mutex_init(&mutex_cnt);
    g_mutex_init(&mutex_hash_main);
    g_mutex_init(&mutex_log_counter);
    g_mutex_init(&mutex_socket);
}

/**
*   @brief  Destroys the main GHash key
*/
void main_hash_key_destroy_cb(gpointer data)
{
    //printf("destroy key: %s\n",(char*)data);
    free(data);
}

/**
*   @brief  Destroys the main GHash value
*/
void main_hash_value_destroy_cb(gpointer data)
{
    g_hash_table_destroy(data);
}

/**
*   @brief  Destroys the field type GHash key
*/
void field_type_hash_value_destroy_cb(gpointer data)
{
    free(data);
}

/**
*   @brief  Clean up all the allocated memories
*/
void memory_cleanup(void)
{
    //process all thread and free up memory
    g_thread_pool_free(pool,FALSE,TRUE); // return when all the queued task in pool has been completed
    json_decref(config);
    g_hash_table_destroy(v9_TEMPLATE_CACHE);
    g_hash_table_destroy(v9_TEMPLATE_REC_LEN);
    g_hash_table_destroy(v10_TEMPLATE_CACHE);
    g_hash_table_destroy(v10_TEMPLATE_REC_LEN);
    g_hash_table_destroy(NETFLOW_FIELD_TYPES);
#ifdef LPLOG
    lplog_exit();
#endif
    free_zmq(context, sender); 
    zlog_fini();
    g_mutex_clear(&mutex_cnt);
    g_mutex_clear(&mutex_hash_main);
    g_mutex_clear(&mutex_log_counter);
    g_mutex_clear(&mutex_socket);
}


/**
*   @brief  Main function for the netflow collector get the config_path from the argument,
*   Set parameters for netflow parser,
*   Save config file data in memory,
*   Starts the server
*/
int main(int argc, char *argv[]) {

    //Init lplog
#ifdef LPLOG 
    lplog_init();
#endif
    //logging using zlog
    int zrc;
    zrc = zlog_init("/opt/immune/storage/col/zlog_netflow.conf");
    if (zrc) {
        fprintf(stderr,"Zlog init failed. \n");
        exit(-1);
    }

    c = zlog_get_category("lp_cat");
    if (!c) {
        fprintf(stderr,"Zlog: get category failed. \n");
        exit(-1);
    }

    bc = zlog_get_category("lp_cat_bench");
    if (!bc) {
        fprintf(stderr,"Zlog: get category failed for netflow benchmarker logging. \n");
        exit(-1);
    }
    /* Glib  version */
    zlog_info(c,"GLib Version: %d.%d.%d\n", glib_major_version, glib_minor_version, glib_micro_version);
    
    v9_TEMPLATE_CACHE = g_hash_table_new_full(g_str_hash, g_str_equal, main_hash_key_destroy_cb, main_hash_value_destroy_cb);
    v9_TEMPLATE_REC_LEN = g_hash_table_new_full(g_str_hash, g_str_equal, main_hash_key_destroy_cb, main_hash_value_destroy_cb);
    
    v10_TEMPLATE_CACHE = g_hash_table_new_full(g_str_hash, g_str_equal, main_hash_key_destroy_cb, main_hash_value_destroy_cb);
    v10_TEMPLATE_REC_LEN = g_hash_table_new_full(g_str_hash, g_str_equal, main_hash_key_destroy_cb, main_hash_value_destroy_cb);
    
    
    NETFLOW_FIELD_TYPES = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, field_type_hash_value_destroy_cb);
    
    /* Initialize all the required symbols
     * Update the required hash tables to use
     */
    init_symbols();
    /* check argument passed to program */
	if(argv[1] == NULL)	{
        zlog_fatal(c, "A config file is expected as argument.");
		exit(-1);
	}
    
	config_path = argv[1];

    /* handle signals */
    signal(SIGHUP, sig_callback);
    signal(SIGINT, sig_callback);
    // signal(SIGTERM, sig_callback);
    // signal(SIGABRT, do_backtrace);
    // signal(SIGFPE, do_backtrace);
    // signal(SIGILL, do_backtrace);
    // signal(SIGSEGV, do_backtrace);

    sender = get_collector_out_socket("netflow_c_collector");
    
    /* save config file data in memory*/
	set_config_parameters();
    
	int sd, rc, n;
	struct sockaddr_in6 client_addr, server_addr;
    
    
    /* UDP COLLECTOR */ /*socket creation */
	sd = socket(AF_INET6, SOCK_DGRAM, 0);
	if(sd<0) {
		//zlog_info(c, "Cannot open socket for UDP connection. \n");
		zlog_fatal(c,"cannot open socket");
		exit(-1);
	}
    /* setting max buffer size 8388608 (8MB) */
    set_rcv_buf(sd,pow(2,23),1);

	server_addr.sin6_family = AF_INET6;
	server_addr.sin6_addr = in6addr_any;
	server_addr.sin6_port = htons(port);
    
	rc = bind (sd, (struct sockaddr *) &server_addr,sizeof(server_addr));
	if(rc<0) {
		//zlog_info(c, "Cannot bind port number %d\n", port);
		zlog_fatal(c,"Cannot bind port number %d", port);
		exit(1);
	}
    
    zlog_info(c, "Starting Netflow UDP Server");

    thread_init();
    GError *err=NULL;
#ifdef BENCHMARK
        if(cnt == 0){
            printf("%d\n", cnt);
            struct timeval start_time;
            gettimeofday(&start_time, NULL);
            
            printf("benchmark data: start_time = ");
            timeval_print(&start_time);
        }
        
 #endif
    /* server infinite loop */
    while(1) {
        int unprocessed = g_thread_pool_unprocessed(pool);
        if(unprocessed > queue_size)
        {
            continue;
        }
        unsigned char *msg =(unsigned char *)malloc(sizeof(char)*RCVBUFSIZEUDP);
        memset(msg, 0, RCVBUFSIZEUDP);
        socklen_t cliLen = (socklen_t)sizeof(client_addr);
        errno = 0;
        n = recvfrom(sd, msg, RCVBUFSIZEUDP, 0, (struct sockaddr *) &client_addr, &cliLen);
        
        if(n<0) {
            zlog_warn(c, "Cannot receive data %s",strerror(errno));
            free(msg);
            continue;
        }
        //collect data to be passed to each thread
        data_t *data = (data_t *)malloc(sizeof(data_t));
        data->n = n;
        data->client_addr = client_addr;
        data->message = msg;
        err = NULL;
        g_thread_pool_push (pool, data, &err);
        if(err!=NULL)
        {
            zlog_error(c, "Error pushing to threadpool %s", err->message);
        }
        // parse_data(data,NULL);
// #ifdef BENCHMARK
//         g_mutex_lock (&mutex_cnt);
//         cnt += 1;
//         if(cnt % 1000 == 0)
//         {
//         	struct timeval end_time;
// 			gettimeofday(&end_time, NULL);
//             int unprocessed = g_thread_pool_unprocessed(pool);
// 			printf("benchmark data: count=%u, unprocessed = %d time= ", cnt, unprocessed);
// 			timeval_print(&end_time);
//             //print_statistics();
//         }
//         g_mutex_unlock(&mutex_cnt);
// #endif
        
	}/* end of server infinite loop */

    zlog_debug(c,"Cleaning Up!");
    memory_cleanup();
    
	return EXIT_SUCCESS;
}
