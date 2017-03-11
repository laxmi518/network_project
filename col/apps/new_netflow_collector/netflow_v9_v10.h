#ifndef NETFLOW_V9_V10_H
#define NETFLOW_V9_V10_H

/**
*   @file netflow_v9_v10.h
*   @author Ritesh
*   @brief for v9 and v10 information
*/

#include "value_string.h"

/**
*   @brief  Structure for v9 header 
*/
typedef struct netflow_v9_header {
	uint16_t   version;
	uint16_t  count;
	uint32_t  sys_uptime;
	uint32_t  unix_secs;
	uint32_t  sequence;
	uint32_t  source_id;
} netflow_v9_header_t;

#define NETFLOW_V9_HEADER_LENGTH sizeof(netflow_v9_header_t)    /**< Length of v9 header */
#define NETFLOW_V9_MAX_RECORDS	 30                             /**< Maximum allowed records in a packet */

/**
*   @brief  Structure for v10 header 
*/
typedef struct netflow_v10_header {
	uint16_t  version;
	uint16_t  ipfix_length;
	uint32_t  unix_secs;
	uint32_t  sequence;
	uint32_t  source_id;
} netflow_v10_header_t;

#define NETFLOW_V10_HEADER_LENGTH sizeof(netflow_v10_header_t)  /**< Length of v10 header */

/*
 * Flowset (template) ID's
 */

#define FLOWSET_ID_V9_DATA_TEMPLATE         0                   /**< id=0 => v9 data template */
#define FLOWSET_ID_V9_OPTIONS_TEMPLATE      1                   /**< id=1 => v9 option template */
#define FLOWSET_ID_V10_DATA_TEMPLATE        2                   /**< id=2 => v10 data template */
#define FLOWSET_ID_V10_OPTIONS_TEMPLATE     3                   /**< id=3 => v10 option template */
#define FLOWSET_ID_RESERVED_MIN             4                   /**< Reserved minimum template id */
#define FLOWSET_ID_RESERVED_MAX           255                   /**< Reserved maximum template id */
#define FLOWSET_ID_DATA_MIN               256                   /**< Reserved minimum data id */
#define FLOWSET_ID_DATA_MAX             65535                   /**< Reserved minimum data id */

#define NTOP_BASE 57472u                /* nprobe >= 5.5.6 */

/** @brief Array contating range of flowset ids */
static const range_string rs_flowset_ids[] = {
    { FLOWSET_ID_V9_DATA_TEMPLATE    , FLOWSET_ID_V9_DATA_TEMPLATE    , "Data Template (V9)"             },
    { FLOWSET_ID_V9_OPTIONS_TEMPLATE , FLOWSET_ID_V9_OPTIONS_TEMPLATE , "Options Template(V9)"           },
    { FLOWSET_ID_V10_DATA_TEMPLATE   , FLOWSET_ID_V10_DATA_TEMPLATE   , "Data Template (V10 [IPFIX])"    },
    { FLOWSET_ID_V10_OPTIONS_TEMPLATE, FLOWSET_ID_V10_OPTIONS_TEMPLATE, "Options Template (V10 [IPFIX])" },
    { FLOWSET_ID_RESERVED_MIN        , FLOWSET_ID_RESERVED_MAX        , "(Reserved)"                     },
    { FLOWSET_ID_DATA_MIN            , FLOWSET_ID_DATA_MAX            , "(Data)"                         },
    { 0,           0,          NULL                   }
};

/* Max number of entries/scopes per template */
/* Space is allocated dynamically so there isn't really a need to
 bound this except to cap possible memory use.  Unfortunately if
 this value is too low we can't decode any template with more than
 v9_tmplt_max_fields fields in it.  The best compromise seems
 to be to make v9_tmplt_max_fields a user preference.
 A value of 0 will be unlimited.
 */

#define V9_TMPLT_MAX_FIELDS_DEF   60                            /**< Max v9 fields allowed */
// static uint v9_tmplt_max_fields = V9_TMPLT_MAX_FIELDS_DEF;

/** @brief Structure for option template flowset */
typedef struct option_template_flowset_s {
	uint16_t  	flowset_id;
	uint16_t  	length;
	uint16_t	template_id;
	uint16_t	option_scope_length;
	uint16_t	option_length;
	struct {
		uint16_t  type;
		uint16_t  length;
	} record[1];
} option_template_flowset_t;

// /** @brief Structure for option template flowset */
// typedef struct _v9_v10_tmplt_entry {
//     uint16_t      type;
//     uint16_t      length;
//     uint32_t      pen;
//     const char *pen_str;
// } v9_v10_tmplt_entry_t;


// typedef enum {
//     TF_SCOPES=0,
//     TF_ENTRIES,
//      /*  START IPFIX VENDOR FIELDS */ 
//     TF_PLIXER,
//     TF_NTOP,
//     TF_NO_VENDOR_INFO
// } v9_v10_tmplt_fields_type_t;

#define TF_NUM 2
#define TF_NUM_EXT 5   /* includes vendor fields */

#define MAX_TYPE_LEN 48     /**< Maximum length of the field_type string */

/** 
*   @brief Array for the field_id: field_type
*/
static const value_string v9_v10_template_types[] = {
    {   1, "bytes" },
    {   2, "packets" },
    {   3, "flows" },
    {   4, "protocol" },
    {   5, "source_tos" },
    {   6, "TCP_flags" },
    {   7, "source_port" },
    {   8, "source_address" },
    {   9, "source_mask" },
    {  10, "input_SNMP" },
    {  11, "destination_port" },
    {  12, "destination_address" },
    {  13, "destination_mask" },
    {  14, "output_SNMP" },
    {  15, "next_hop_address" },
    {  16, "source_as" },
    {  17, "destination_as" },
    {  18, "BGP_next_hop" },
    {  19, "multicast_destination_packets" },
    {  20, "multicast_destination_octects" },
    {  21, "last_switched" },
    {  22, "first_switched" },
    {  23, "out_bytes" },
    {  24, "out_packets" },
    {  25, "min_ip_packet_length" },
    {  26, "max_ip_packet_length" },
    {  27, "source_address" },
    {  28, "destination_address" },
    {  29, "source_mask" },
    {  30, "destination_mask" },
    {  31, "flow_label" },
    {  32, "ICMP_type" },
    {  33, "IGMP_type" },
    {  34, "sampling_interval" },
    {  35, "sampling_algorithm" },
    {  36, "flow_active_timeout" },
    {  37, "flow_inactive_timeout" },
    {  38, "engine_type" },
    {  39, "engine_id" },
    {  40, "total_bytes_exported" },
    {  41, "total_packets_exported" },
    {  42, "total_flows_exported" },
    {  44, "source_prefix" },
    {  45, "destination_prefix" },
    {  46, "MPLS_top_label_type" },
    {  47, "MPLS_top_label_address" },
    {  48, "flow_sampler_id" },
    {  49, "flow_sampler_mode" },
    {  50, "flow_sampler_random_interval" },
    {  51, "flow_class" },
    {  52, "min_ttl" },
    {  53, "max_ttl" },
    {  54, "IPv4_id" },
    {  55, "destination_tos" },
    {  56, "source_mac" },
    {  57, "destination_mac" },
    {  58, "source_VLAN" },
    {  59, "destination_VLAN" },
    {  60, "ip_protocol_version" },
    {  61, "direction" },
    {  62, "next_hop_address" },
    {  63, "BGP_next_hop" },
    {  64, "option_headers" },
    {  70, "MPLS_label_1" },
    {  71, "MPLS_label_2" },
    {  72, "MPLS_label_3" },
    {  73, "MPLS_label_4" },
    {  74, "MPLS_label_5" },
    {  75, "MPLS_label_6" },
    {  76, "MPLS_label_7" },
    {  77, "MPLS_label_8" },
    {  78, "MPLS_label_9" },
    {  79, "MPLS_label_10" },
    {  80, "destination_mac" },
    {  81, "source_mac" },
    {  82, "interface_name" },
    {  83, "interface_description" },
    {  84, "sampler_name" },
    {  85, "bytes_total" },
    {  86, "packets_total" },
    {  88, "fragment_offset" },
    {  89, "forwarding_status" },
    {  90, "VPN_route_distinguisher" },
    {  91, "MPLS_top_label_prefix_length" },
    {  92, "source_traffic_index" },
    {  93, "destination_traffic_index" },
    {  94, "application_description" },
    {  95, "application_id" },
    {  96, "application_name" },
    {  98, "postip_diff_serv_code_point" },
    {  99, "multicast_replication_factor" },
    { 128, "destination_as_peer" },
    { 129, "source_as_peer" },
    { 130, "exporter_address" },
    { 131, "exporter_address" },
    { 132, "dropped_bytes" },
    { 133, "dropped_packets" },
    { 134, "dropped_bytes_total" },
    { 135, "dropped_packets_total" },
    { 136, "flow_end_reason" },
    { 137, "common_properties_id" },
    { 138, "observation_point_id" },
    { 139, "ICMP_type_code" },
    { 140, "MPLS_top_label_address" },
    { 141, "line_card_id" },
    { 142, "port_id" },
    { 143, "metering_process_id" },
    { 144, "flow_exporter" },
    { 145, "template_id" },
    { 146, "wlan_channel_id" },
    { 147, "wlan_SSID" },
    { 148, "flow_id" },
    { 149, "observation_domain_id" },
    { 150, "flow_start_seconds" },
    { 151, "flow_end_seconds" },
    { 152, "flow_start_milliseconds" },
    { 153, "flow_end_milliseconds" },
    { 154, "flow_start_microseconds" },
    { 155, "flow_end_microseconds" },
    { 156, "flow_start_nanoseconds" },
    { 157, "flow_end_nanoseconds" },
    { 158, "flow_start_delta_microseconds" },
    { 159, "flow_end_delta_microseconds" },
    { 160, "system_init_time_milliseconds" },
    { 161, "flow_duration_milliseconds" },
    { 162, "flow_duration_microseconds" },
    { 163, "observed_flow_total_count" },
    { 164, "ignored_packet_total_count" },
    { 165, "ignored_octet_total_count" },
    { 166, "not_sent_flow_total_count" },
    { 167, "not_sent_packet_total_count" },
    { 168, "not_sent_octet_total_count" },
    { 169, "destination_prefix" },
    { 170, "source_prefix" },
    { 171, "post_octet_total_count" },
    { 172, "post_packet_total_count" },
    { 173, "flow_key_indicator" },
    { 174, "post_multicast_packet_total_count" },
    { 175, "post_multicast_octet_total_count" },
    { 176, "ICMP_type" },
    { 177, "ICMP_code" },
    { 178, "ICMP_type" },
    { 179, "ICMP_code" },
    { 180, "UDP_source_port" },
    { 181, "UDP_destination_port" },
    { 182, "TCP_source_port" },
    { 183, "TCP_destination_port" },
    { 184, "TCP_sequence_number" },
    { 185, "TCP_ack_number" },
    { 186, "TCP_window_size" },
    { 187, "TCP_ungernt_pointer" },
    { 188, "TCP_header_length" },
    { 189, "ip_header_length" },
    { 190, "total_length" },
    { 191, "payload_length" },
    { 192, "ip_TTL" },
    { 193, "next_header" },
    { 194, "MPLS_paylod_length" },
    { 195, "ip_DSCP" },
    { 196, "ip_predence" },
    { 197, "ip_fragment_flags" },
    { 198, "bytes_squared" },
    { 199, "bytes_squared_permanent" },
    { 200, "MPLS_top_label_TTL" },
    { 201, "MPLS_label_stack_octets" },
    { 202, "MPLS_label_stack_depth" },
    { 203, "MPLS_top_label-export" },
    { 204, "ip_payload_length" },
    { 205, "UDP_length" },
    { 206, "is_multicast" },
    { 207, "ip_header_words" },
    { 208, "ip_option_map" },
    { 209, "TCP_option_map" },
    { 210, "padding_octets" },
    { 211, "collector_address" },
    { 212, "collector_address" },
    { 213, "collector_interface" },
    { 214, "collector_protocol_version" },
    { 215, "collector_transport_protocol" },
    { 216, "collector_transport_port" },
    { 217, "exporter_transport_port" },
    { 218, "TCP_SYN_total_count" },
    { 219, "TCP_FIN_total_count" },
    { 220, "TCP_RST_total_count" },
    { 221, "TCP_PSH_total_count" },
    { 222, "TCP_ACK_total_count" },
    { 223, "TCP_URG_total_count" },
    { 224, "ip_total_length" },
    { 225, "post_NAT_source_address" },
    { 226, "post_NAT_destination_address" },
    { 227, "post_NAPT_source_transport_port" },
    { 228, "post_NAPT_destination_transport_port" },
    { 229, "NAT_originating_address_realm" },
    { 230, "NAT_event" },
    { 231, "initiator_octets" },
    { 232, "responder_octets" },
    { 233, "firewall_event" },
    { 234, "ingress_VRF_id" },
    { 235, "egress_VRF_id" },
    { 236, "VRF_name" },
    { 237, "post_MPLS_top_label_export" },
    { 238, "TCP_window_scale" },
    { 239, "biflow_direction" },
    { 240, "ethernet_header_length" },
    { 241, "ethernet_payload_length" },
    { 242, "ethernet_total_length" },
    { 243, "dot1q_vlan_id" },
    { 244, "dot1q_priority" },
    { 245, "dot1q_customer_vlan_id" },
    { 246, "dot1q_customer_priority" },
    { 247, "metro_EVC_id" },
    { 248, "metro_EVC_type" },
    { 249, "pseudo-wire_id" },
    { 250, "pseudo_wire_type" },
    { 251, "pseudo_wire_control_word" },
    { 252, "ingress_physical_interface" },
    { 253, "egress_physical_interface" },
    { 254, "post_dot1q_vlan_id" },
    { 255, "post_dot1q_customer_vlan_id" },
    { 256, "ethernet_type" },
    { 257, "post_ip_precedence" },
    { 258, "collection_time_milliseconds" },
    { 259, "export_sctp_stream_id" },
    { 260, "max_export_seconds" },
    { 261, "max_flow_end_seconds" },
    { 262, "message_MD5_checksum" },
    { 263, "message_scope" },
    { 264, "min_export_seconds" },
    { 265, "min_flow_start_seconds" },
    { 266, "opaque_octets" },
    { 267, "session_scope" },
    { 268, "max_flow_end_microseconds" },
    { 269, "max_flow_end_milliseconds" },
    { 270, "max_flow_end_nanoseconds" },
    { 271, "min_flow_start_nicroseconds" },
    { 272, "min_flow_start_milliseconds" },
    { 273, "min_flow_start_nanoseconds" },
    { 274, "collector_certificate" },
    { 275, "exporter_certificate" },
    { 301, "selection_sequence_id" },
    { 302, "selector_id" },
    { 303, "information_element_id" },
    { 304, "selector_algorithm" },
    { 305, "sampling_packet_interval" },
    { 306, "sampling_packet_space" },
    { 307, "sampling_time_interval" },
    { 308, "sampling_time_space" },
    { 309, "sampling_size" },
    { 310, "sampling_population" },
    { 311, "sampling_probability" },
    { 313, "ip_section_header" },
    { 314, "ip_section_payload" },
    { 316, "MPLS_label_stack_section" },
    { 317, "MPLS_playload_packet_section" },
    { 318, "selector_id_total_packets_observed" },
    { 319, "selector_id_total_packets_selected" },
    { 320, "absolute_error" },
    { 321, "relative_error" },
    { 322, "observation_time_seconds" },
    { 323, "observation_time_milliseconds" },
    { 324, "observation_time_microseconds" },
    { 325, "observation_time_nanoseconds" },
    { 326, "digest_hash_value" },
    { 327, "hash_ip_payload_offset" },
    { 328, "hash_ip_payload_size" },
    { 329, "hash_output_range_min" },
    { 330, "hash_output_range_max" },
    { 331, "hash_selected_range_min" },
    { 332, "hash_selected_range_max" },
    { 333, "hash_digest_output" },
    { 334, "hash_initialiser_value" },
    { 335, "selector_name" },
    { 336, "upper_CI_limit" },
    { 337, "lower_CI_limit" },
    { 338, "confidence_level" },
    { 339, "information_element_data_type" },
    { 340, "information_element_description" },
    { 341, "information_element_name" },
    { 342, "information_element_range_begin" },
    { 343, "information_element_range_end" },
    { 344, "information_element_semantics" },
    { 345, "information_element_units" },
    { 346, "private_enterprise_number" },
    /* Ericsson NAT Logging */
    { 24628, "NAT_log_field_idx_context_id" },
    { 24629, "NAT_log_field_idx_context_name" },
    { 24630, "NAT_log_field_idx_assign_ts_sec" },
    { 24631, "NAT_log_field_idx_unassign_ts_sec" },
    { 24632, "NAT_log_field_idx_int_address" },
    { 24633, "NAT_log_field_idx_ext_address" },
    { 24634, "NAT_log_field_idx_ext_port_first" },
    { 24635, "NAT_log_field_idx_ext_port_last" },
    /* Cisco ASA5500 Series NetFlow */
    { 33000, "ingress_ACL_id" },
    { 33001, "egress_ACL_id" },
    { 33002, "FW_ext_event" },
    /* medianet performance monitor */
    { 37000, "packets_dropped" },
    { 37003, "byte_rates" },
    { 37004, "application_media_bytes" },
    { 37006, "application_media_byte_rate" },
    { 37007, "application_media_packets" },
    { 37009, "application_media_packet_rate" },
    { 37011, "application_media_event" },
    { 37012, "monitor_event" },
    { 37013, "timestamp_interval" },
    { 37014, "transport_packets_expected" },
    { 37016, "transport_round_trip_time" },
    { 37017, "transport_event_packet_loss" },
    { 37019, "transport_packets_lost" },
    { 37021, "transport_packets_lost_rate" },
    { 37022, "transport_RTP_ssrc" },
    { 37023, "transport_RTP_jitter_mean" },
    { 37024, "transport_RTP_jitter_min" },
    { 37025, "transport_RTP_jitter_max" },
    { 37041, "transport_RTP_payload_type" },
    { 37071, "transport_bytes_out_of_order" },
    { 37074, "transport_packets_out_of_order" },
    { 37083, "transport_TCP_windows_size_min" },
    { 37084, "transport_TCP_windows_size_max" },
    { 37085, "transport_TCP_window_ssize_mean" },
    { 37086, "transport_TCP_maximum_segment_size" },
    { 40000, "AAA_username" },
    { 40001, "post_NAT_source_address" },
    { 40002, "post_NAT_destination_address" },
    { 40003, "post_NAPT_source_port" },
    { 40004, "post_NAPT_destination_port" },
    { 40005, "firewall_event" },
    /* v9 nTop extensions. */
    /** commented for time  
    {  80 + NTOP_BASE, "FRAGMENTS" },
    {  82 + NTOP_BASE, "CLIENT_NW_DELAY_SEC" },
    {  83 + NTOP_BASE, "CLIENT_NW_DELAY_USEC" },
    {  84 + NTOP_BASE, "SERVER_NW_DELAY_SEC" },
    {  85 + NTOP_BASE, "SERVER_NW_DELAY_USEC" },
    {  86 + NTOP_BASE, "APPL_LATENCY_SEC" },
    {  87 + NTOP_BASE, "APPL_LATENCY_USEC" },
    {  98 + NTOP_BASE, "ICMP_FLAGS" },
    { 101 + NTOP_BASE, "SRC_IP_COUNTRY" },
    { 102 + NTOP_BASE, "SRC_IP_CITY" },
    { 103 + NTOP_BASE, "DST_IP_COUNTRY" },
    { 104 + NTOP_BASE, "DST_IP_CITY" },
    { 105 + NTOP_BASE, "FLOW_PROTO_PORT" },
    { 106 + NTOP_BASE, "TUNNEL_ID" },
    { 107 + NTOP_BASE, "LONGEST_FLOW_PKT" },
    { 108 + NTOP_BASE, "SHORTEST_FLOW_PKT" },
    { 109 + NTOP_BASE, "RETRANSMITTED_IN_PKTS" },
    { 110 + NTOP_BASE, "RETRANSMITTED_OUT_PKTS" },
    { 111 + NTOP_BASE, "OOORDER_IN_PKTS" },
    { 112 + NTOP_BASE, "OOORDER_OUT_PKTS" },
    { 113 + NTOP_BASE, "UNTUNNELED_PROTOCOL" },
    { 114 + NTOP_BASE, "UNTUNNELED_IPV4_SRC_ADDR" },
    { 115 + NTOP_BASE, "UNTUNNELED_L4_SRC_PORT" },
    { 116 + NTOP_BASE, "UNTUNNELED_IPV4_DST_ADDR" },
    { 117 + NTOP_BASE, "UNTUNNELED_L4_DST_PORT" },
    { 120 + NTOP_BASE, "DUMP_PATH" },
    { 130 + NTOP_BASE, "SIP_CALL_ID" },
    { 131 + NTOP_BASE, "SIP_CALLING_PARTY" },
    { 132 + NTOP_BASE, "SIP_CALLED_PARTY" },
    { 133 + NTOP_BASE, "SIP_RTP_CODECS" },
    { 134 + NTOP_BASE, "SIP_INVITE_TIME" },
    { 135 + NTOP_BASE, "SIP_TRYING_TIME" },
    { 136 + NTOP_BASE, "SIP_RINGING_TIME" },
    { 137 + NTOP_BASE, "SIP_OK_TIME" },
    { 138 + NTOP_BASE, "SIP_BYE_TIME" },
    { 139 + NTOP_BASE, "SIP_RTP_SRC_IP" },
    { 140 + NTOP_BASE, "SIP_RTP_SRC_PORT" },
    { 141 + NTOP_BASE, "SIP_RTP_DST_IP" },
    { 142 + NTOP_BASE, "SIP_RTP_DST_PORT" },
    { 150 + NTOP_BASE, "RTP_FIRST_SSRC" },
    { 151 + NTOP_BASE, "RTP_FIRST_TS" },
    { 152 + NTOP_BASE, "RTP_LAST_SSRC" },
    { 153 + NTOP_BASE, "RTP_LAST_TS" },
    { 154 + NTOP_BASE, "RTP_IN_JITTER" },
    { 155 + NTOP_BASE, "RTP_OUT_JITTER" },
    { 156 + NTOP_BASE, "RTP_IN_PKT_LOST" },
    { 157 + NTOP_BASE, "RTP_OUT_PKT_LOST" },
    { 158 + NTOP_BASE, "RTP_OUT_PAYLOAD_TYPE" },
    { 159 + NTOP_BASE, "RTP_IN_MAX_DELTA" },
    { 160 + NTOP_BASE, "RTP_OUT_MAX_DELTA" },
    { 165 + NTOP_BASE, "L7_PROTO" },
    { 180 + NTOP_BASE, "HTTP_URL" },
    { 181 + NTOP_BASE, "HTTP_RET_CODE" },
    { 182 + NTOP_BASE, "HTTP_REFERER" },
    { 183 + NTOP_BASE, "HTTP_UA" },
    { 184 + NTOP_BASE, "HTTP_MIME" },
    { 185 + NTOP_BASE, "SMTP_MAIL_FROM" },
    { 186 + NTOP_BASE, "SMTP_RCPT_TO" },
    { 195 + NTOP_BASE, "MYSQL_SERVER_VERSION" },
    { 196 + NTOP_BASE, "MYSQL_USERNAME" },
    { 197 + NTOP_BASE, "MYSQL_DB" },
    { 198 + NTOP_BASE, "MYSQL_QUERY" },
    { 199 + NTOP_BASE, "MYSQL_RESPONSE" },
     **/ //commented for time being
    { 0, NULL }
};

/** Array for the field_id: field_type */
static const value_string v10_template_types_plixer[] = {
    { 100, "client_ip_v4" },
    { 101, "client_hostname" },
    { 102, "partner_name" },
    { 103, "server_hostname" },
    { 104, "server_ip_v4" },
    { 105, "recipient_address" },
    { 106, "event_id" },
    { 107, "msgid" },
    { 108, "priority" },
    { 109, "recipient_report_status" },
    { 110, "number_recipients" },
    { 111, "origination_time" },
    { 112, "encryption" },
    { 113, "service_version" },
    { 114, "linked_msgid" },
    { 115, "message_subject" },
    { 116, "sender_address" },
    { 117, "date_time" },
    { 118, "client_ip_v6" },
    { 119, "server_ip_v6" },
    { 120, "source_context" },
    { 121, "connector_id" },
    { 122, "source_component" },
    { 124, "related_recipient_address" },
    { 125, "reference" },
    { 126, "return_path" },
    { 127, "message_info" },
    { 128, "directionality" },
    { 129, "tenant_id" },
    { 130, "original_client_ip_v4" },
    { 131, "original_server_ip_v4" },
    { 132, "custom_data" },
    { 133, "internal_message_id" },
    { 0, NULL }
};

/** Array for the ntop field_id: field_type */
static const value_string v10_template_types_ntop[] = {
    {  80, "FRAGMENTS" },
    {  82, "CLIENT_NW_DELAY_SEC" },
    {  83, "CLIENT_NW_DELAY_USEC" },
    {  84, "SERVER_NW_DELAY_SEC" },
    {  85, "SERVER_NW_DELAY_USEC" },
    {  86, "APPL_LATENCY_SEC" },
    {  87, "APPL_LATENCY_USEC" },
    {  98, "ICMP_FLAGS" },
    { 101, "SRC_IP_COUNTRY" },
    { 102, "SRC_IP_CITY" },
    { 103, "DST_IP_COUNTRY" },
    { 104, "DST_IP_CITY" },
    { 105, "FLOW_PROTO_PORT" },
    { 106, "TUNNEL_ID" },
    { 107, "LONGEST_FLOW_PKT" },
    { 108, "SHORTEST_FLOW_PKT" },
    { 109, "RETRANSMITTED_IN_PKTS" },
    { 110, "RETRANSMITTED_OUT_PKTS" },
    { 111, "OOORDER_IN_PKTS" },
    { 112, "OOORDER_OUT_PKTS" },
    { 113, "UNTUNNELED_PROTOCOL" },
    { 114, "UNTUNNELED_IPV4_SRC_ADDR" },
    { 115, "UNTUNNELED_L4_SRC_PORT" },
    { 116, "UNTUNNELED_IPV4_DST_ADDR" },
    { 117, "UNTUNNELED_L4_DST_PORT" },
    { 120, "DUMP_PATH" },
    { 130, "SIP_CALL_ID" },
    { 131, "SIP_CALLING_PARTY" },
    { 132, "SIP_CALLED_PARTY" },
    { 133, "SIP_RTP_CODECS" },
    { 134, "SIP_INVITE_TIME" },
    { 135, "SIP_TRYING_TIME" },
    { 136, "SIP_RINGING_TIME" },
    { 137, "SIP_OK_TIME" },
    { 138, "SIP_BYE_TIME" },
    { 139, "SIP_RTP_SRC_IP" },
    { 140, "SIP_RTP_SRC_PORT" },
    { 141, "SIP_RTP_DST_IP" },
    { 142, "SIP_RTP_DST_PORT" },
    { 150, "RTP_FIRST_SSRC" },
    { 151, "RTP_FIRST_TS" },
    { 152, "RTP_LAST_SSRC" },
    { 153, "RTP_LAST_TS" },
    { 154, "RTP_IN_JITTER" },
    { 155, "RTP_OUT_JITTER" },
    { 156, "RTP_IN_PKT_LOST" },
    { 157, "RTP_OUT_PKT_LOST" },
    { 158, "RTP_OUT_PAYLOAD_TYPE" },
    { 159, "RTP_IN_MAX_DELTA" },
    { 160, "RTP_OUT_MAX_DELTA" },
    { 165, "L7_PROTO" },
    { 180, "HTTP_URL" },
    { 181, "HTTP_RET_CODE" },
    { 182, "HTTP_REFERER" },
    { 183, "HTTP_UA" },
    { 184, "HTTP_MIME" },
    { 185, "SMTP_MAIL_FROM" },
    { 186, "SMTP_RCPT_TO" },
    { 195, "MYSQL_SERVER_VERSION" },
    { 196, "MYSQL_USERNAME" },
    { 197, "MYSQL_DB" },
    { 198, "MYSQL_QUERY" },
    { 199, "MYSQL_RESPONSE" },
    { 0, NULL }
};

/** Array for the scope field_id: field_type */
static const value_string v9_scope_field_types[] = {
    { 1, "system" },
    { 2, "interface" },
    { 3, "Line_card" },
    { 4, "netflow_cache" },
    { 5, "template" },
    { 0, NULL }
};

/** Array for the sampler field_id: field_type */
static const value_string v9_sampler_mode[] = {
    { 0, "Deterministic" },
    { 1, "Unknown" },  /* "Time-Based" ?? */
    { 2, "Random" },
    { 0, NULL }
};

/** Array for the direction field_id: field_type */
static const value_string v9_direction[] = {
    { 0, "Ingress" },
    { 1, "Egress" },
    { 0, NULL }
};

#define FORWARDING_STATUS_UNKNOWN 0     /**<    Unknown Forwarding status */
#define FORWARDING_STATUS_FORWARD 1     /**<    Forward Forwarding status */
#define FORWARDING_STATUS_DROP    2     /**<    Drop Forwarding status */
#define FORWARDING_STATUS_CONSUME 3     /**<    Consume Forwarding status */

/** Array for the forwarding status */
static const value_string v9_forwarding_status[] = {
    { FORWARDING_STATUS_UNKNOWN, "Unknown"},  /* Observed on IOS-XR 3.2 */
    { FORWARDING_STATUS_FORWARD, "Forward"},  /* Observed on 7200 12.4(9)T */
    { FORWARDING_STATUS_DROP,    "Drop"},     /* Observed on 7200 12.4(9)T */
    { FORWARDING_STATUS_CONSUME, "Consume"},  /* Observed on 7200 12.4(9)T */
    { 0, NULL }
};

static const value_string v9_forwarding_status_unknown_code[] = {
    {   0, NULL }
};

static const value_string v9_forwarding_status_forward_code[] = {
    {   0, "Forwarded (Unknown)" },
    {   1, "Forwarded Fragmented" },
    {   2, "Forwarded not Fragmented" },
    {   0, NULL }
};

static const value_string v9_forwarding_status_drop_code[] = {
    {   0, "Dropped (Unknown)" },
    {   1, "Drop ACL Deny" },
    {   2, "Drop ACL drop" },
    {   3, "Drop Unroutable" },
    {   4, "Drop Adjacency" },
    {   5, "Drop Fragmentation & DF set" },
    {   6, "Drop Bad header checksum" },
    {   7, "Drop Bad total Length" },
    {   8, "Drop Bad Header Length" },
    {   9, "Drop bad TTL" },
    {  10, "Drop Policer" },
    {  11, "Drop WRED" },
    {  12, "Drop RPF" },
    {  13, "Drop For us" },
    {  14, "Drop Bad output interface" },
    {  15, "Drop Hardware" },
    {   0, NULL }
};

static const value_string v9_forwarding_status_consume_code[] = {
    {   0, "Consumed (Unknown)" },
    {   1, "Terminate Punt Adjacency" },
    {   2, "Terminate Incomplete Adjacency" },
    {   3, "Terminate For us" },
    {   0, NULL }
};

static const value_string v9_firewall_event[] = {
    { 0, "Default (ignore)"},
    { 1, "Flow created"},
    { 2, "Flow deleted"},
    { 3, "Flow denied"},
    { 4, "Flow alert"},
    { 0, NULL }
};

static const value_string v9_extended_firewall_event[] = {
    {    0, "ignore"},
    { 1001, "Flow denied by an ingress ACL"},
    { 1002, "Flow denied by an egress ACL"},
    { 1003, "Flow denied by security appliance"},
    { 1004, "Flow denied (TCP flow beginning with not TCP SYN)"},
    { 0, NULL }
};

static const value_string engine_type[] = {
    { 0, "RP"},
    { 1, "VIP/Linecard"},
    { 2, "PFC/DFC" },
    { 0, NULL }
};

static const value_string v9_flow_end_reason[] = {
    { 0, "Unknown"},
    { 1, "Idle timeout"},
    { 2, "Active timeout" },
    { 3, "End of Flow detected" },
    { 4, "Forced end" },
    { 5, "Lack of resources" },
    { 0, NULL }
};

static const value_string v9_biflow_direction[] = {
    { 0, "Arbitrary"},
    { 1, "Initiator"},
    { 2, "ReverseInitiator" },
    { 3, "Perimeter" },
    { 0, NULL }
};

static const value_string selector_algorithm[] = {
    { 0, "Reserved"},
    { 1, "Systematic count-based Sampling"},
    { 2, "Systematic time-based Sampling"},
    { 3, "Random n-out-of-N Sampling"},
    { 4, "Uniform probabilistic Sampling"},
    { 5, "Property match Filtering"},
    { 6, "Hash based Filtering using BOB"},
    { 7, "Hash based Filtering using IPSX"},
    { 8, "Hash based Filtering using CRC"},
    { 0, NULL }
};


static const value_string performance_monitor_specials[] = {
    { 0xFFFFFFFF, "Not Measured"},
    { 0xFFFF, "Not Measured"},
    { 0xFF, "Not Measured"},
    { 0, NULL }
};


#endif
