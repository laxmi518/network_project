CC=gcc
CFLAGS=-Wall -D_GNU_SOURCE
CFLAGS+=`pkg-config --cflags glib-2.0`
LIBS=`pkg-config --libs glib-2.0`
OBJECTS=netflow_collector.o json_creator.o config_reader.o wiring.o seek_get_bytes.o cidr.o benchmarker.o
INCDIR=/usr/local/include
LIBDIR=/usr/local/lib

LIBS+=-ljansson -lzmq -lzlog -lcidr
CLIB_PATH=../../lib/clib/
#-g used to get debugging symbol in core dump. 
#to be replaced by -O2 when no crash occurs for a long period of time
all: CFLAGS+=-g
all: clean netflow_collector

ddebug: CFLAGS+=-g  	
ddebug: clean netflow_collector 

debug: CFLAGS+=-g -DDEBUG -DLPLOG 	
debug: clean netflow_collector

profile: CFLAGS+=-pg -DPROFILE
profile: clean netflow_collector

benchmark: CFLAGS+= -g -DBENCHMARK
benchmark: clean netflow_collector

cpuprofile: LIBS+= -lprofiler
cpuprofile: clean netflow_collector

doc: 
	doxygen Doxyfile

netflow_collector: $(OBJECTS)
	$(CC) $(CFLAGS) -o netflow_collector $(OBJECTS) $(LIBS)

netflow_collector.o: netflow_collector.c
	$(CC) $(CFLAGS) -c netflow_collector.c

json_creator.o: json_creator.c
	$(CC) $(CFLAGS) -c json_creator.c

config_reader.o: $(CLIB_PATH)config_reader.c
	$(CC) $(CFLAGS) -c $(CLIB_PATH)config_reader.c

wiring.o: $(CLIB_PATH)wiring.c
	$(CC) $(CFLAGS) -c $(CLIB_PATH)wiring.c

seek_get_bytes.o: seek_get_bytes.c
	$(CC) $(CFLAGS) -c seek_get_bytes.c

cidr.o: $(CLIB_PATH)cidr.c
	$(CC) $(CFLAGS) -c $(CLIB_PATH)cidr.c

benchmarker.o: $(CLIB_PATH)benchmarker.c
	$(CC) $(CFLAGS) -c $(CLIB_PATH)benchmarker.c
 

# sys_info.o: sys_info.c
# 	$(CC) $(CFLAGS) -c sys_info.c

.PHONY: clean
clean:
	rm -rf $(OBJECTS) *.dSYM netflow_collector
