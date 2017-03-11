CC=gcc
CFLAGS=-Wall `pkg-config --cflags glib-2.0` 
LIBS=`pkg-config --libs glib-2.0` `python-config --ldflags`
OBJECTS=collector_lib.o config_reader.o json_creator.o wiring.o cidr.o benchmarker.o
INCDIR=-I/usr/local/include -I/usr/include/python2.7/
LIBDIR=/usr/local/bin
LIBS+=-ljansson -lzmq -lev -lzlog -lpthread -lonig -lcidr -lssl -lcrypto
CLIB_PATH=
#-g used to get debugging symbol in core dump. 
#to be replaced by -O2 when no crash occurs for a long period of time
all:CFLAGS+=-g 
all:collector_lib 

debug: CFLAGS+=-g -DDEBUG -DLPLOG
debug: clean collector_lib

benchmark: CFLAGS+=-g -DBENCHMARK 
benchmark: clean collector_lib

profile: CFLAGS+= -pg
profile: clean collector_lib

doc: 
	doxygen Doxyfile

collector_lib: $(OBJECTS)
	# $(CC) $(CFLAGS) -g -o collector_lib $(OBJECTS) $(LIBS)
	# export LD_LIBRARY_PATH=/home/pritesh/projects/logpoint/col/lib/libcol/interface_c/collector_lib_new/:$LD_LIBRARY_PATH
	$(CC) -shared -Wl,-soname,libcollector.so.1 -o libcollector.so.1.0 $(OBJECTS) $(LIBS)
	ln -sf libcollector.so.1.0 libcollector.so
	ln -sf libcollector.so.1.0 libcollector.so.1
	rm *.o

collector_lib.o: collector_lib.c
	$(CC) $(CFLAGS) $(INCDIR) -c -fpic collector_lib.c

config_reader.o: $(CLIB_PATH)config_reader.c
	$(CC) $(CFLAGS) -c -fpic $(CLIB_PATH)config_reader.c

json_creator.o: json_creator.c
	$(CC) $(CFLAGS) -c -fpic json_creator.c

wiring.o: $(CLIB_PATH)wiring.c
	$(CC) $(CFLAGS) -c -fpic $(CLIB_PATH)wiring.c

cidr.o: $(CLIB_PATH)cidr.c
	$(CC) $(CFLAGS) -c -fpic $(CLIB_PATH)cidr.c

benchmarker.o: $(CLIB_PATH)benchmarker.c
	$(CC) $(CFLAGS) -c -fpic $(CLIB_PATH)benchmarker.c


.PHONY: clean
clean:
	rm -rf $(OBJECTS) *.dSYM collector_lib *.out libcollector* 
