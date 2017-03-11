
#ifndef NETFLOW_COMMON_H
#define NETFLOW_COMMON_H

/**
*   @file netflow_common.h
*   @author Ritesh
*   @brief Netflow common information  
*/


#include <jansson.h>

#define MAX_BACKLOG 1024	/**<	Maximum size for backlog */
#define RCVBUFSIZE 4096		/**<	Receive  buffer size */
#define RCVBUFSIZEUDP 8192	/**<	Receive buffer size UDP */

/**
*	@brief Structure contaning common information for packet
*/
typedef struct packet_info {
    uint16_t version;				/**< 	Version of the packet */
    char *device_ip;				/**< 	Device ip (char *) */
    unsigned int device_int_ip;		/**< 	Device ip (int) */
    json_t *dev_config;				/**< 	Config for device */
    const char *lp_name;			/**< 	Logpoint name */
    size_t len;						/**< 	Total len of packet */
    struct timeval ts;				/**< 	Time stamp of the received packet (seconds) */
} packet_info_t;

#endif
