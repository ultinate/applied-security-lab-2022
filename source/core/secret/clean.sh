#!/bin/bash

echo "##### Cleaning all, just in case #####"
cd work
rm ../*.pem *.pem *.txt* *.old serial crlnumber newcerts/*.pem private/*.pem 2&>/dev/null

for type in serv usr
do
  cd intermediate_$type/
  rm *.pem *.txt* *.old serial crlnumber csr/*.pem private/*.pem certs/*.pem newcerts/*.pem newcerts/*.pkcs12 newcerts/*.pkcs12.password 2&>/dev/null
  cd ..
done
