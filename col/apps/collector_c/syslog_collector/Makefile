CC=gcc
# UTIL = ../../lib/libcol/interface_c/collector_lib/
# INC = ../../../../apps/collector_c/
CFLAGS=-g `pkg-config --cflags glib-2.0`
CFLAGS+=#`pkg-config --cflags glib-2.0`
LIBS=`pkg-config --libs glib-2.0` -ljansson -lcollector -lzlog
INCDIR= /usr/local/include
LIB_PATH=../../../lib/libcol/interface_c/collector_lib/
# LIBS += $(UTIL)libcollector.so -ljansson -lpthread -lzmq -lcidr -lev -lssl 


all: syslog_collector

debug:
	cd ../../../lib/libcol/interface_c/collector_lib/ ; make debug
debug: CFLAGS+=-g -DDEBUG
debug: clean syslog_collector

benchmark: 
	cd ../../../lib/libcol/interface_c/collector_lib/ ; make benchmark
benchmark: CFLAGS+=-g -DBENCHMARK
benchmark: clean syslog_collector
# ls  
# ((cd ../../../lib/libcol/interface_c/collector_lib_new/) && (make benchmark))

profile: CFLAGS+= -pg
profile: clean syslog_collector

syslog_collector: syslog_collector.o
	$(CC) $(CFLAGS) -L$(LIB_PATH) syslog_collector.o -o syslog_collector $(LIBS)

syslog_collector.o: syslog_collector.c
	$(CC) $(CFLAGS) -I$(LIB_PATH) -c syslog_collector.c	

.PHONY: clean
clean:
	rm -rf *.dSYM syslog_collector.o syslog_collector *.out
