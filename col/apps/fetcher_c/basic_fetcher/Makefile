CC=gcc
CFLAGS=-g `pkg-config --cflags glib-2.0` 
LIBS=-lfetcher -lzlog -ljansson
INCDIR= /usr/local/include
LIB_PATH=../../../lib/libcol/interface_c/fetcher_lib/

all: basic_fetcher

debug:
	cd ../../../lib/libcol/interface_c/fetcher_lib/ ; make debug
debug: CFLAGS+=-g -DDEBUG
debug: clean basic_fetcher

benchmark: 
	cd ../../../lib/libcol/interface_c/fetcher_lib/ ; make benchmark
benchmark: CFLAGS+=-g -DBENCHMARK
benchmark: clean basic_fetcher
# ls  
# ((cd ../../../lib/libcol/interface_c/collector_lib_new/) && (make benchmark))

profile: CFLAGS+= -pg
profile: clean basic_fetcher

basic_fetcher: basic_fetcher.o
	$(CC) $(CFLAGS) -L$(LIB_PATH) basic_fetcher.o -o basic_fetcher $(LIBS)

basic_fetcher.o: basic_fetcher.c
	$(CC) $(CFLAGS) -I$(LIB_PATH) -c basic_fetcher.c	

.PHONY: clean
clean:
	rm -rf *.dSYM basic_fetcher.o basic_fetcher *.out
