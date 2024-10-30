#!/bin/bash

# Generate CA key and certificate
openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
    -keyout ca-key.pem -out ca-cert.pem \
    -subj "/C=US/ST=Test/L=Test/O=Test/OU=Test/CN=Test CA"

# Generate server key
openssl req -newkey rsa:4096 -nodes \
    -keyout server-key.pem -out server-req.pem \
    -subj "/C=US/ST=Test/L=Test/O=Test/OU=Test/CN=localhost"

# Sign server certificate with CA
openssl x509 -req -in server-req.pem \
    -days 365 -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -out server-cert.pem

# Clean up intermediate files
rm server-req.pem ca-cert.srl