CC=gcc
CFLAGS=-g `pkg-config --cflags glib-2.0` 
LIBS=-lfetcher -lzlog -ljansson -lssh2 -lcrypto -lmagic
INCDIR= /usr/local/include
LIB_PATH=../../../lib/libcol/interface_c/fetcher_lib/

all:
	cd ../../../lib/libcol/interface_c/fetcher_lib/ ; make
all: clean scp_fetcher

debug: 
	cd ../../../lib/libcol/interface_c/fetcher_lib/ ; make debug
debug: CFLAGS+=-g -DDEBUG
debug: clean scp_fetcher

benchmark: 
	cd ../../../lib/libcol/interface_c/fetcher_lib/ ; make benchmark
benchmark: CFLAGS+=-g -DBENCHMARK
benchmark: clean scp_fetcher
# ls  
# ((cd ../../../lib/libcol/interface_c/collector_lib_new/) && (make benchmark))

profile: CFLAGS+= -pg
profile: clean scp_fetcher

scp_fetcher: scp_fetcher.o
	$(CC) $(CFLAGS) -L$(LIB_PATH) scp_fetcher.o -o scp_fetcher $(LIBS)

scp_fetcher.o: scp_fetcher.c
	$(CC) $(CFLAGS) -I$(LIB_PATH) -c scp_fetcher.c	

.PHONY: clean
clean:
	rm -rf *.dSYM scp_fetcher.o scp_fetcher *.out
