#ifndef BASICFETCHER_H
#define BASICFETCHER_H

#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>
#include <glib.h>
#include <pthread.h>
#include <time.h>
#include <zmq.h>
#include <assert.h>

void *thread_main_cb(void *parm);

#endif


