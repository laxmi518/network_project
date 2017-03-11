#ifndef BENCHMARKER_H
#define BENCHMARKER_H

#include <zlog.h>
extern zlog_category_t *_bc;

void initialize_benchamrker(char *service_name);
void start_benchmarker_processing();
int benchmarker_zmq_send(void *sender, char *event_with_mid);

#endif