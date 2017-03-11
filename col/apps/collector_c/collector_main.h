#ifndef COLLECTOR_H
#define COLLECTOR_H

#include <stdio.h>
#include <jansson.h>
#include <glib.h>

#include "../../lib/libcol/interface_c/collector_lib/collector_lib.h"

long last_col_ts;
int log_counter;
void* sender;

void* handle_tcp_data_cb (char* msg,json_t* param);
void* handle_udp_data_cb (char* msg,json_t* param);
void* handle_ssl_data_cb (char* msg);








#endif

