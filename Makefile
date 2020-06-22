CC=gcc
CFLAGS=-g -Wall -Wmacro-redefined -Wextra -I/usr/local/include
LDFLAGS=-lmbedx509 -lmbedcrypto -lmbedtls -L/usr/local/lib

PKI=pki
BIN=bin

.SILENT:

all: pki src

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
	rm -rf $(PKI)

pki: create_ca create_server_cert create_client_cert

create_ca: 
	mkdir -p $(PKI)
	echo "\nCreating root CA..."
	echo "- create private key"
	openssl ecparam -out $(PKI)/ca-key.pem -name secp256r1 -genkey
	echo "- create and sign certificate"
	openssl req -new -key $(PKI)/ca-key.pem -x509 -nodes -sha256 -days 365 -out $(PKI)/ca.pem -config ca.cnf \
		-subj "/C=DE/L=Cologne/O=grandcentrix/CN=Root CA"

create_server_cert:
	echo "\nCreating server certificate:"
	echo "- create private key"
	openssl ecparam -out $(PKI)/server-key.pem -name secp256r1 -genkey
	echo "- create signing request"
	openssl req -new -config server.cnf -key $(PKI)/server-key.pem -out $(PKI)/server-sign-req.pem \
		-subj "/C=DE/L=Cologne/O=Server/CN=localhost"
	echo "- create and sign certificate"
	openssl x509 -sha256 -req -extfile server.cnf -in $(PKI)/server-sign-req.pem -CA $(PKI)/ca.pem -CAkey $(PKI)/ca-key.pem -CAcreateserial -out $(PKI)/server.pem

create_client_cert:
	echo "\nCreating client certificate:"
	echo "- create private key"
	openssl ecparam -out $(PKI)/client-key.pem -name secp256r1 -genkey
	echo "- create signing request"
	openssl req -new -config client.cnf -key $(PKI)/client-key.pem -out $(PKI)/client-sign-req.pem \
		-subj "/C=DE/L=Cologne/O=Client/CN=localhost"
	echo "- create and sign certificate"
	openssl x509 -sha256 -req -extfile client.cnf -in $(PKI)/client-sign-req.pem -CA $(PKI)/ca.pem -CAkey $(PKI)/ca-key.pem -CAcreateserial -out $(PKI)/client.pem
