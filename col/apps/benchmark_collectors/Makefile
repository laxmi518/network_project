CC=gcc
CFLAGS=--std=gnu99
EXEC=client client_ssl
LIBS= -lssl -lcrypto -pthread -lrt

all: $(EXEC)

debug: CFLAGS+=-g -DDEBUG
debug: clean $(EXEC)

client_ssl: client_ssl.c
	$(CC) $(CFLAGS) client_ssl.c -o client_ssl $(LIBS)

client: client.c
	$(CC) $(CFLAGS) client.c -o client --std=gnu99 $(LIBS) -pthread -lrt
# gcc -O2 -g -Wall -pthread  --std=gnu99 client.c -o client -lrt

.PHONY: clean
clean:
	rm -rf $(EXEC) *.dSYM