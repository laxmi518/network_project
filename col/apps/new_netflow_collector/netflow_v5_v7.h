#ifndef NETFLOW_V5_V7_H
#define NETFLOW_V5_V7_H

/**
*   @file netflow_v5_v7.h
*   @author Ritesh
*   @brief Header for v5 and v7
*/

#include "value_string.h"

#define NETFLOW_V5_HEADER_LENGTH 24     /**<  Header length for v5 packets. */
#define NETFLOW_V5_RECORD_LENGTH 48     /**<  Each Record length for v5. */
#define NETFLOW_V5_MAX_RECORDS	 30     /**<  Maximum records allowed in each packet. */

#define NETFLOW_V7_HEADER_LENGTH 24     /**<  Header length for v7 packets. */
#define NETFLOW_V7_RECORD_LENGTH 52     /**<  Each Record length for v7. */
#define NETFLOW_V7_MAX_RECORDS   28     /**<  Maximum records allowed in each packet. */

/** 
* @brief  Structure for v5 header
*/
typedef struct netflow_v5_header {
	uint16_t version;
	uint16_t flowcount;
	uint32_t uptime;
	uint32_t unix_ts;
	uint32_t unix_tns;
	uint32_t sequence;
	uint8_t engine_type;
	uint8_t engine_id;
	uint16_t samp_interval;
} netflow_v5hdr_t;

/** 
* @brief  Structure for v5 records
*/
typedef struct netlfow_v5_record {
	struct in_addr src;
	struct in_addr dst;
	struct in_addr nexthop;
    uint16_t snmp_in;
	uint16_t snmp_out;
	uint32_t packets;
	uint32_t bytes;
	uint32_t first_ts;
	uint32_t last_ts;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t pad1;
    uint8_t tcp_flags;
	uint8_t proto;
	uint8_t tos;
	uint16_t src_asn;
	uint16_t dst_asn;
	uint8_t src_mask;
	uint8_t dst_mask;
	uint16_t pad2;
} netflow_v5rec_t;


/** 
* @brief  Structure for single v5 flowset
*/
typedef struct single_flowset_v5 {
    netflow_v5hdr_t *hdr_v5;
    netflow_v5rec_t *rec_v5;
    char *_p__raw_msg_b;
} single_flowset_v5_t;

/** 
* @brief  Structure for received v5 data
*/
typedef struct _received_data_v5 {
    char str[NETFLOW_V5_HEADER_LENGTH + NETFLOW_V5_RECORD_LENGTH];
} received_data_v5_t;


/**   @brief  Array for sampling mode */
static const value_string v5_sampling_mode[] = {
    {0, "No sampling mode configured"},
    {1, "Packet Interval sampling mode configured"},
    {2, "Random sampling mode configured"},
    {0, NULL}
};

/** 
* @brief  Structure for v7 header
*/
typedef struct netflow_v7_header {
  uint16_t  version;
  uint16_t  count;
  uint32_t  SysUptime;
  uint32_t  unix_secs;
  uint32_t  unix_nsecs;
  uint32_t  flow_sequence;
  uint32_t  reserved;
} netflow_v7_header_t;

/** 
* @brief  Structure for v7 records
*/
typedef struct netflow_v7_record {
  uint32_t  srcaddr;
  uint32_t  dstaddr;
  uint32_t  nexthop;
  uint16_t  input;
  uint16_t  output;
  uint32_t  dPkts;
  uint32_t  dOctets;
  uint32_t  First;
  uint32_t  Last;
  uint16_t  srcport;
  uint16_t  dstport;
  uint8_t   flags;
  uint8_t   tcp_flags;
  uint8_t   prot;
  uint8_t   tos;
  uint16_t  src_as;
  uint16_t  dst_as;
  uint8_t   src_mask;
  uint8_t   dst_mask;
  uint16_t  pad;
  uint32_t  router_sc;
} netflow_v7_record_t;


/*
 * Extension map for v5/v7
 *
 * Required extensions:
 *
 *       4 byte byte counter
 *       | 4byte packet counter
 *       | | IPv4 
 *       | | |
 * xxxx x0 0 0
 *
 * Optional extensions:
 *
 * 4	: 2 byte input/output interface id
 * 6	: 2 byte src/dst as
 * 8	: srcmask/dst mask dst tos = 0, dir = 0
 * 9	: IPv4 next hop
 */

#endif
