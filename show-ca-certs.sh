#!/bin/sh


CA_DIR=${CA_DIR:-/etc/grid-security/certificates}


for cafile in `ls ${CA_DIR}/*.0`; do
    echo "File: $cafile";
    openssl x509 -noout -subject -in $cafile
    openssl x509 -noout -issuer  -in $cafile
    echo "----------"
done
