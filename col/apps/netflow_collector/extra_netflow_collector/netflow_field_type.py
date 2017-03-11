#!/usr/bin/python2.6
"""
8: "source_address_ipv4"
12: "destination_address_ipv4"
15: "next_hop_ipv4"
27: "source_address_ipv6"
28: "destination_address_ipv6"
47:"MPLS_toplevel_IP_ipv4"
62:"next_hop_ipv6",
63:"bgp_next_hop_ipv6",
130:"exporter_address",
131:"exporter_address",
225:"post_NAT_source_address_ipv4", 40001:"post_NAT_source_address_ipv4",
226:"post_NAT_destination_address_ipv4", 40002:"post_NAT_destination_address_ipv4",
281:"post_NAT_source_address_ipv6", 40057:"post_NAT_source_address_ipv6",
282:"post_NAT_destination_address_ipv6", 40058:"post_NAT_destination_address_ipv6",
"""

FIELDS = {1: "bytes_count", 2: "packet_count", 4:"protocol", 5: "types_of_service", 6: "tcp_flag", 7: "source_port", \
          8: "source_address",9: "source_mask", 10: "input_interface_index", 11: "destination_port", \
          12: "destination_address",13: "destination_mask", 14: "output_interface_index", 15: "next_hop", \
          16: "source_as", 17: "destination_as", 21: "last_switched", 22: "first_switched", \
          27: "source_address", 28: "destination_address", \
          29: "source_IPv6_mask",
          30: "destination_IPv6_mask",
          32: "ICMP_type",
          34: "sampling_interval", 35: "sampling_algorithm",
          38:"engine_type",
            39:"engine_ID",
            46:"MPLS_toplevel_type",
            47:"MPLS_toplevel_IP",
            58:"vlan_ingress",
            59:"vlan_egress",
            60: "protocol_version" ,
            61:"flow_direction",
            62:"next_hop",
            63:"bgp_next_hop",
            85:"octets",
            86:"packets",
            130:"exporter_address",
            131:"exporter_address",
            136:"flow_end_reason",
            139:"ICMP_type_IPv6",
            144:"exporter_id",
            148:"flow_ID",
            152:"flow_start_ms",
            153:"flow_end_ms",
            160:"system_init_ms",
            176:"ICMP_type",
            177:"ICMP_code",
            178:"ICMP_type",
            179:"ICMP_code",
            180:"UDP_source_port",
            181:"UDP_destination_port",
            182:"TCP_source_port",
            183:"TCP_destination_port",
            214:"export_protocol_version",
            215:"export_transport_protocol",
            224:"ip_total_length", 40000:"ip_total_length",
            225:"post_NAT_source_address", 40001:"post_NAT_source_address",
            226:"post_NAT_destination_address", 40002:"post_NAT_destination_address",
            227:"post_NAPT_source_port", 40003:"post_NAPT_source_port",
            228:"post_NAPT_destination_port", 40004:"post_NAPT_destination_port",
            229:"NAT_originating_realm", 40005:"NAT_originating_realm",
            230:"NAT_event", 40006: "NAT_event",
            233:"firewall_event",
            234:"ingress_VRFID",
            235:"egress_VRFID",

            323:"observation_time_ms",
            
            281:"post_NAT_source_address", 40057:"post_NAT_source_address",
            282:"post_NAT_destination_address", 40058:"post_NAT_destination_address",
            
            
            }

