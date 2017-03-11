CC=gcc
CFLAGS=-Wall `pkg-config --cflags glib-2.0` 
LIBS=`pkg-config --libs glib-2.0` `python-config --ldflags`
OBJECTS=syslog_collector.o config_reader.o json_creator.o wiring.o cidr.o benchmarker.o
INCDIR=-I/usr/local/include -I/usr/include/python2.7/
LIBDIR=/usr/local/bin
LIBS+=-ljansson -lzmq -lev -lzlog -lpthread -lonig -lcidr -lssl -lcrypto
CLIB_PATH=../../lib/clib/
#-g used to get debugging symbol in core dump. 
#to be replaced by -O2 when no crash occurs for a long period of time
all:CFLAGS+=-g 
all:syslog_collector 

debug: CFLAGS+=-g -DDEBUG -DLPLOG
debug: clean syslog_collector

benchmark: CFLAGS+=-g -DBENCHMARK 
benchmark: clean syslog_collector

profile: CFLAGS+= -pg
profile: clean syslog_collector

doc: 
	doxygen Doxyfile

syslog_collector: $(OBJECTS)
	$(CC) $(CFLAGS) -g -o syslog_collector $(OBJECTS) $(LIBS)

syslog_collector.o: syslog_collector.c
	$(CC) $(CFLAGS) $(INCDIR) -c syslog_collector.c

config_reader.o: $(CLIB_PATH)config_reader.c
	$(CC) $(CFLAGS) -c $(CLIB_PATH)config_reader.c

json_creator.o: json_creator.c
	$(CC) $(CFLAGS) -c json_creator.c

wiring.o: $(CLIB_PATH)wiring.c
	$(CC) $(CFLAGS) -c $(CLIB_PATH)wiring.c

cidr.o: $(CLIB_PATH)cidr.c
	$(CC) $(CFLAGS) -c $(CLIB_PATH)cidr.c

benchmarker.o: $(CLIB_PATH)benchmarker.c
	$(CC) $(CFLAGS) -c $(CLIB_PATH)benchmarker.c


.PHONY: clean
clean:
	rm -rf $(OBJECTS) *.dSYM syslog_collector *.out
