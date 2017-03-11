CC=gcc
CFLAGS=-Wall `pkg-config --cflags glib-2.0` 
LIBS=`pkg-config --libs glib-2.0` `python-config --ldflags`
OBJECTS= config_reader.o json_creator.o wiring.o encoding.o benchmarker.o fetcher_lib.o
INCDIR=-I/usr/local/include -I/usr/include/python2.7/
LIBDIR=/usr/local/bin
LIBS+=-ljansson -lzmq -lzlog -lpthread -lonig 
CLIB_PATH=
#-g used to get debugging symbol in core dump. 
#to be replaced by -O2 when no crash occurs for a long period of time
all:CFLAGS+=-g 
all:fetcher_lib 

debug: CFLAGS+=-g -DDEBUG -DLPLOG
debug: clean fetcher_lib

benchmark: CFLAGS+=-g -DBENCHMARK 
benchmark: clean fetcher_lib

profile: CFLAGS+= -pg
profile: clean fetcher_lib

doc: 
	doxygen Doxyfile

fetcher_lib: $(OBJECTS)
	# $(CC) $(CFLAGS) -g -o collector_lib $(OBJECTS) $(LIBS)
	# export LD_LIBRARY_PATH=/home/pritesh/projects/logpoint/col/lib/libcol/interface_c/collector_lib_new/:$LD_LIBRARY_PATH
	$(CC) -shared -Wl,-soname,libfetcher.so.1 -o libfetcher.so.1.0 $(OBJECTS) $(LIBS)
	ln -sf libfetcher.so.1.0 libfetcher.so
	ln -sf libfetcher.so.1.0 libfetcher.so.1
	rm *.o

fetcher_lib.o: fetcher_lib.c
	$(CC) $(CFLAGS) $(INCDIR) -c -fpic fetcher_lib.c

config_reader.o: $(CLIB_PATH)config_reader.c
	$(CC) $(CFLAGS) -c -fpic $(CLIB_PATH)config_reader.c

json_creator.o: json_creator.c
	$(CC) $(CFLAGS) -c -fpic json_creator.c

wiring.o: $(CLIB_PATH)wiring.c
	$(CC) $(CFLAGS) -c -fpic $(CLIB_PATH)wiring.c

encoding.o: $(CLIB_PATH)encoding.c
	$(CC) $(CFLAGS) $(INCDIR) -c -fpic $(CLIB_PATH)encoding.c

benchmarker.o: $(CLIB_PATH)benchmarker.c
	$(CC) $(CFLAGS) $(INCDIR) -c -fpic $(CLIB_PATH)benchmarker.c

.PHONY: clean
clean:
	rm -rf $(OBJECTS) *.dSYM fetcher_lib *.out libfetcher* 
