CC=gcc
UTIL = ../../../lib/libcol/interface_c/
CFLAGS=
OBJ = collector_main.o
SOBJ = libcollector.so
OBJECTS=syslog_collector.o
INCDIR= /usr/local/include
LIBDIR=/usr/local/bin
LIBS= $(UTIL)libcollector.so -ljansson -lzmq -lev -lzlog -lpthread -lonig -lcidr


all: syslog_collector


debug: CFLAGS=-g -DDEBUG -DLPLOG
debug: clean syslog_collector

benchmark: CFLAGS= -DBENCHMARK -DLPLOG
benchmark: clean syslog_collector

profile: CFLAGS= -pg
profile: clean syslog_collector

syslog_collector: $(OBJECTS) $(OBJ) $(SOBJ)
	$(CC) $(CFLAGS) -g -o syslog_collector $(OBJECTS) $(LIBS)

$(OBJ): $(UTIL)collector_main.c
	$(CC) $(CFLAGS) -c -Wall -Werror -fpic $(UTIL)collector_main.c
	mv collector_main.o $(UTIL)

$(SOBJ): $(OBJ)
	$(CC) $(CFLAGS) -shared -o libcollector.so $(UTIL)collector_main.o
	mv *.so $(UTIL)

$(OBJECTS): syslog_collector.c
	$(CC) -I$(UTIL) -c syslog_collector.c


.PHONY: clean
clean:
	rm -rf $(OBJECTS) $(UTIL)$(OBJ) $(UTIL)$(SOBJ) *.dSYM syslog_collector *.out
