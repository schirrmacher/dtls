CC=gcc
CFLAGS=-g -Wall -Wmacro-redefined -Wextra -I/usr/local/include
LDFLAGS=-lmbedx509 -lmbedcrypto -lmbedtls -L/usr/local/lib

PKI=pki
BIN=bin

.SILENT:

all: src

src: dtls_client dtls_server

dtls_client: dtls_client.o
	$(CC) -o $(BIN)/$@ $(BIN)/$^ $(LDFLAGS)

dtls_server: dtls_server.o
	$(CC) -o $(BIN)/$@ $(BIN)/$^ $(LDFLAGS)

%.o: %.c
	mkdir -p $(BIN)
	$(CC) $(CFLAGS) -o $(BIN)/$@ -c $<

run: all
	$(BIN)/dtls_server

server:
	$(BIN)/dtls_server

client:
	$(BIN)/dtls_client

clean:
	rm -rf $(BIN)
