
/**
  A  struct that holds syslog data.
 */
struct syslog_data {
    OnigRegion *region; /**<    Onigregion*/
    char *str;         /**<    Message*/
    int pri;            /**<    Priority of message*/
    char *year;         /**<    Year of Message*/
    char *date_time;    /**<    date and time of message*/
};

struct syslog_data * get_syslog_data_from_message(OnigRegex re_arg,OnigRegion *region_arg, char *message);

struct syslog_data * get_syslog_data_from_message_r(OnigRegex re_arg,OnigRegion *region_arg, char *message);

json_t *create_json_object(const char *lp_name, char *message, char *dev_ip, json_t *dev_config,
						char *mid, long col_ts, const char *col_type,struct syslog_data *d);

char *get_message_id(const char *col_type, const char *lp_name, char *dev_ip,
						long double col_ts, long double counter);
