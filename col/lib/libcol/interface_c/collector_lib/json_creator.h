#ifndef JSON_CREATOR_H
#define JSON_CREATOR_H

#include "collector_lib.h"
extern zlog_category_t *_c; 		/**< Extern: for using zlog */
extern GMutex _mutex_log_counter; 	/**< Extern: Mutex for _log_counter */
extern long _log_counter;			/**< Extern: _log_counter */
json_t *create_json_object(const char *lp_name, char *message, char *dev_ip, json_t *dev_config,
						char *mid, long col_ts, const char *col_type);
#endif