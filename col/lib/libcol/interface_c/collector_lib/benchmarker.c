#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

#include <zmq.h>
#include <jansson.h>
#include "benchmarker.h"

int time_freq = 5;

double recv_duration = 0.0;
long send_called = 0;
double send_duration = 0.0;

struct timeval last_sent_time_tv;
struct timeval last_aggregated_time_tv;
char *service = NULL;


void initialize_benchamrker(char *service_name)
{
    gettimeofday(&last_sent_time_tv, NULL);
    gettimeofday(&last_aggregated_time_tv, NULL);
    service = service_name;
}


void _reset(struct timeval now)
{
    recv_duration = 0.0;
    send_called = 0;
    send_duration = 0.0;
    last_aggregated_time_tv = now;
}


double difftime_tv(struct timeval x, struct timeval y)
{
    double x_total = (double) (x.tv_sec + (double)x.tv_usec/1000000);
    double y_total = (double) (y.tv_sec + (double)y.tv_usec/1000000);
    return (x_total - y_total);
}


void _aggregate(struct timeval now)
{

    last_sent_time_tv = now;
    double total_duration = difftime_tv(now, last_aggregated_time_tv);
    // printf( "total Duratio %f\n", total_duration);
    // printf( "last aggregaed time %ld %d\n", last_aggregated_time_tv.tv_sec, last_aggregated_time_tv.tv_usec);
    if (total_duration >= time_freq)
    {
        double processing_duration = total_duration - recv_duration - send_duration;
        double actual_mps = (double) (send_called / total_duration);
        double doable_mps = (double) (send_called / processing_duration);

        if (doable_mps < 0)
        {
            zlog_error(_bc, "benchmarker calculated negative doable_mps; \
                send_called: %ld; total_duration: %f; recv_duration: %f; send_duration: %f; \
                processing_duration: %f; actual_mps: %f; doable_mps: %f\n", \
                send_called, total_duration, recv_duration, send_duration, \
                processing_duration, actual_mps, doable_mps);

        } else
        {
            zlog_info(_bc, "Benchmarker; reporting speed; service=%s; actual_mps=%f; doable_mps=%f\n;", service, actual_mps, doable_mps);
            // printf( "Benchmarker; reporting speed; service=%s; actual_mps=%f; doable_mps=%f\n;", service, actual_mps, doable_mps);
               
        }
        _reset(now);
    }

}


void start_benchmarker_processing()
{   
    struct timeval now_tv;
    gettimeofday(&now_tv, NULL);

    double diff_time_tv = difftime_tv(now_tv, last_sent_time_tv);
    recv_duration += diff_time_tv;
    last_sent_time_tv = now_tv;
}


int benchmarker_zmq_send(void *sender, char *event_with_mid)
{
    struct timeval now;
    gettimeofday(&now, NULL);

    clock_t send_start, send_end;
    send_start = clock();
    int rc = zmq_send(sender, event_with_mid, strlen(event_with_mid), 0); // actual zmq send function invoked here
    send_end = clock();
    send_duration += ((double)(send_end - send_start)) / CLOCKS_PER_SEC;
    send_called += 1;

    _aggregate(now);

    return rc;
}



