CC=gcc
UTIL = ../../lib/libcol/interface_c/collector_lib/
INC = ../../../../apps/collector_c/
CFLAGS=-g
CFLAGS+=`pkg-config --cflags glib-2.0`
LIBS=`pkg-config --libs glib-2.0`
OBJ = collector_lib.o
SOBJ = libcollector.so
OBJECT= collector_main.o
INCDIR= /usr/local/include
#DIR = /usr/include/json-glib-1.0/
LIBDIR=/usr/local/bin
LIBS += $(UTIL)libcollector.so -ljansson -lpthread -lzmq -lcidr -lev -lssl 


all: collector_main


debug: CFLAGS+ =-g -DDEBUG -DLPLOG
debug: clean collector_main

benchmark: CFLAGS= -DBENCHMARK -DLPLOG
benchmark: clean collector_main

profile: CFLAGS= -pg
profile: clean collector_main

collector_main: $(OBJ) $(SOBJ) $(OBJECT)
	$(CC) $(CFLAGS) -g -o collector $(OBJECT) $(LIBS)

collector_lib.o: $(UTIL)collector_lib.c
	$(CC) $(CFLAGS) -I$(INC) -c -Wall -fpic $(UTIL)collector_lib.c
	mv collector_lib.o $(UTIL)
	
$(SOBJ): $(OBJ)
	$(CC) $(CFLAGS) -shared -o libcollector.so $(UTIL)collector_lib.o
	mv *.so $(UTIL)

$(OBJECT): collector_main.c
	$(CC) $(CFLAGS) -I$(UTIL) -c collector_main.c 


.PHONY: clean
clean:
	rm -rf $(OBJECT) $(UTIL)$(OBJ) $(UTIL)$(SOBJ) *.dSYM collector *.out
