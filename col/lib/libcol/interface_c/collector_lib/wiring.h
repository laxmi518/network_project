#ifndef WIRING_H
#define WIRING_H

/** 
*   @file wiring.h
*   @author ritesh, hari
*   @date 8/22/2013
*	@brief	zmq socket creation, initializing sockets and send the data to upper layer
*/
void timeval_print(struct timeval *tv);
void *get_collector_out_socket(char *service_name);
void send_event_with_mid(void *sender, json_t *event, const char *normalizer, const char *repo);
void free_zmq(void *context, void *socket);

#endif
