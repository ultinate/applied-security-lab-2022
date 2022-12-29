#!/bin/bash
set -x

# This is meant to run once before running `vagrant up`.
# here we create the root and intermediate certficates.
# afterwords we need to provision the files and set up 
# permissions and so on.

#delete old garbage
./clean.sh

CA_KEY_PASSPHRASE="eiCoot6uohV7Eevo"
INTERMEDIATE_USR_KEY_PASSPHRASE="oiHieng1Ahmied2R"
INTERMEDIATE_SERV_KEY_PASSPHRASE="ahXoh7oSQuoo8Tim"

# Set up Root CA
CA_DIR="./work"
mkdir -p $CA_DIR/certs  # empty dirs are not kept by git. Either create them or use .gitkeep file.
mkdir -p $CA_DIR/newcerts
mkdir -p $CA_DIR/private


echo "############################"
echo "##### Root certificate #####"
echo "############################"

bash -c "echo '01' > $CA_DIR/serial"
bash -c "echo '01' > $CA_DIR/crlnumber"
touch $CA_DIR/index.txt

openssl req -newkey rsa:4096 -x509 -extensions v3_ca -days 3650 \
    -keyout $CA_DIR/private/ca_root.key.pem \
    -out $CA_DIR/ca_root.cert.pem \
    -config $CA_DIR/openssl.ca_root.cnf \
    -passout pass:$CA_KEY_PASSPHRASE \
    -subj "/C=CH/ST=Zurich/L=Zurich/O=iMovies, Inc./OU=IT Department/CN=iMovies Root CA"
openssl x509 -noout -text -in $CA_DIR/ca_root.cert.pem
openssl ca -gencrl \
    -out $CA_DIR/ca_root.crl.pem \
    -config $CA_DIR/openssl.ca_root.cnf \
    -passin pass:$CA_KEY_PASSPHRASE

echo "############################"
echo "## Intermediate User cert ##"
echo "############################"

INTERMEDIATE_USR_DIR=$CA_DIR/intermediate_usr
mkdir -p $INTERMEDIATE_USR_DIR/csr
mkdir -p $INTERMEDIATE_USR_DIR/certs
mkdir -p $INTERMEDIATE_USR_DIR/newcerts
mkdir -p $INTERMEDIATE_USR_DIR/private
bash -c "echo '0201' > $INTERMEDIATE_USR_DIR/serial"
bash -c "echo '0201' > $INTERMEDIATE_USR_DIR/crlnumber"
touch $INTERMEDIATE_USR_DIR/index.txt

openssl genrsa -aes256 \
      -out $INTERMEDIATE_USR_DIR/private/ca_intermediate_usr.key.pem \
      -passout pass:$INTERMEDIATE_USR_KEY_PASSPHRASE \
      4096
openssl req -new -sha256 \
      -config $INTERMEDIATE_USR_DIR/openssl.ca_intermediate_usr.cnf \
      -key $INTERMEDIATE_USR_DIR/private/ca_intermediate_usr.key.pem \
      -passin pass:$INTERMEDIATE_USR_KEY_PASSPHRASE \
      -out $INTERMEDIATE_USR_DIR/csr/ca_intermediate_usr.csr.pem \
      -subj "/C=CH/ST=Zurich/L=Zurich/O=iMovies, Inc./OU=IT Department/CN=iMovies Intermediate User CA"
openssl ca -extensions v3_intermediate_ca -batch \
      -config $CA_DIR/openssl.ca_root.cnf \
      -days 1095 -notext -md sha256 \
      -in $INTERMEDIATE_USR_DIR/csr/ca_intermediate_usr.csr.pem \
      -out $INTERMEDIATE_USR_DIR/ca_intermediate_usr.cert.pem \
      -passin pass:$CA_KEY_PASSPHRASE
openssl x509 -noout -text \
      -in $INTERMEDIATE_USR_DIR/ca_intermediate_usr.cert.pem
openssl verify -CAfile $CA_DIR/ca_root.cert.pem \
      $INTERMEDIATE_USR_DIR/ca_intermediate_usr.cert.pem
cat $INTERMEDIATE_USR_DIR/ca_intermediate_usr.cert.pem \
      $CA_DIR/ca_root.cert.pem > $INTERMEDIATE_USR_DIR/ca-chain_usr.cert.pem
openssl ca -gencrl \
      -out $INTERMEDIATE_USR_DIR/ca_intermediate_usr.crl.pem \
      -config $INTERMEDIATE_USR_DIR/openssl.ca_intermediate_usr.cnf \
      -keyfile $INTERMEDIATE_USR_DIR/private/ca_intermediate_usr.key.pem \
      -passin pass:$INTERMEDIATE_USR_KEY_PASSPHRASE

# create the combined CRL
cat $CA_DIR/ca_root.crl.pem $INTERMEDIATE_USR_DIR/ca_intermediate_usr.crl.pem > $INTERMEDIATE_USR_DIR/ca_intermediate_usr_combined.crl.pem

echo "############################"
echo "## Intermediate Serv cert ##"
echo "############################"
INTERMEDIATE_SERV_DIR=$CA_DIR/intermediate_serv
bash -c "echo '0101' > $INTERMEDIATE_SERV_DIR/serial"
bash -c "echo '0101' > $INTERMEDIATE_SERV_DIR/crlnumber"
mkdir -p $INTERMEDIATE_SERV_DIR/csr
mkdir -p $INTERMEDIATE_SERV_DIR/certs
mkdir -p $INTERMEDIATE_SERV_DIR/newcerts
mkdir -p $INTERMEDIATE_SERV_DIR/private
touch $INTERMEDIATE_SERV_DIR/index.txt

# Create intermediate Server certificate
openssl genrsa -aes256 \
      -out $INTERMEDIATE_SERV_DIR/private/ca_intermediate_serv.key.pem \
      -passout pass:$INTERMEDIATE_SERV_KEY_PASSPHRASE \
      4096
openssl req -new -sha256 \
      -config $INTERMEDIATE_SERV_DIR/openssl.ca_intermediate_serv.cnf \
      -key $INTERMEDIATE_SERV_DIR/private/ca_intermediate_serv.key.pem \
      -passin pass:$INTERMEDIATE_SERV_KEY_PASSPHRASE \
      -out $INTERMEDIATE_SERV_DIR/csr/ca_intermediate_serv.csr.pem \
      -subj "/C=CH/ST=Zurich/L=Zurich/O=iMovies, Inc./OU=IT Department/CN=iMovies Intermediate Server CA"
openssl ca -batch \
      -extensions v3_intermediate_ca -days 1095 -notext -md sha256 \
      -config $CA_DIR/openssl.ca_root.cnf \
      -in $INTERMEDIATE_SERV_DIR/csr/ca_intermediate_serv.csr.pem \
      -out $INTERMEDIATE_SERV_DIR/ca_intermediate_serv.cert.pem \
      -passin pass:$CA_KEY_PASSPHRASE
openssl x509 -noout -text \
      -in $INTERMEDIATE_SERV_DIR/ca_intermediate_serv.cert.pem
openssl verify -CAfile $CA_DIR/ca_root.cert.pem \
      $INTERMEDIATE_SERV_DIR/ca_intermediate_serv.cert.pem
cat $INTERMEDIATE_SERV_DIR/ca_intermediate_serv.cert.pem \
      $CA_DIR/ca_root.cert.pem > $INTERMEDIATE_SERV_DIR/ca-chain_serv.cert.pem
openssl ca -gencrl \
      -out $INTERMEDIATE_SERV_DIR/ca_intermediate_serv.crl.pem \
      -config $INTERMEDIATE_SERV_DIR/openssl.ca_intermediate_serv.cnf \
      -passin pass:$INTERMEDIATE_SERV_KEY_PASSPHRASE

# create the combined CRL
cat $CA_DIR/ca_root.crl.pem $INTERMEDIATE_SERV_DIR/ca_intermediate_serv.crl.pem > $INTERMEDIATE_SERV_DIR/ca_intermediate_serv_combined.crl.pem

######## notes for us ############
# # Move root CA private key to offline-storage (a.k.a. delete it)
# now we can keep it on the repo for us, just dont copy this to the vms!
# rm -f $CA_DIR/private/ca_root.key.pem
# rm -f $CA_KEY_PASSPHRASE_FILE
#--------------------------------#

# # now we just keep it outside the work dir (the one we keep on the vm)
# # so it is just on the repo.
# mv $CA_DIR/private/ca_root.key.pem .

#prepare passphrase files to populate then into /mnt/hsm
echo $INTERMEDIATE_SERV_KEY_PASSPHRASE > intermediate_srv_passphrase.txt
echo $INTERMEDIATE_USR_KEY_PASSPHRASE > intermediate_usr_passphrase.txt

echo "############################"
echo "####### Server certs #######"
echo "############################"

for DOMAIN in core.imovies.ch database.imovies.ch imovies.ch backup.imovies.ch cert.imovies.ch
do
  echo "####### Cert for $DOMAIN #######"
  openssl genrsa \
        -out $INTERMEDIATE_SERV_DIR/private/$DOMAIN.key.pem 2048
  sed -i '' -e "s/^subjectAltName=.*/subjectAltName=DNS:${DOMAIN}/g" \
        $INTERMEDIATE_SERV_DIR/openssl.ca_intermediate_serv.cnf
  openssl req \
        -config $INTERMEDIATE_SERV_DIR/openssl.ca_intermediate_serv.cnf \
        -key $INTERMEDIATE_SERV_DIR/private/$DOMAIN.key.pem \
        -new -sha256 -out $INTERMEDIATE_SERV_DIR/csr/$DOMAIN.csr.pem \
        -subj "/C=CH/ST=Zurich/L=Zurich/O=iMovies, Inc./OU=IT Department/CN=$DOMAIN"
  openssl ca -batch \
        -extensions server_cert -days 365 -notext -md sha256 \
        -config $INTERMEDIATE_SERV_DIR/openssl.ca_intermediate_serv.cnf \
        -in $INTERMEDIATE_SERV_DIR/csr/$DOMAIN.csr.pem \
        -out $INTERMEDIATE_SERV_DIR/certs/$DOMAIN.cert.pem \
        -passin pass:$INTERMEDIATE_SERV_KEY_PASSPHRASE
  openssl x509 -noout -text \
        -in $INTERMEDIATE_SERV_DIR/certs/$DOMAIN.cert.pem
  openssl verify -CAfile $INTERMEDIATE_SERV_DIR/ca-chain_serv.cert.pem \
        $INTERMEDIATE_SERV_DIR/certs/$DOMAIN.cert.pem
  cat $INTERMEDIATE_SERV_DIR/certs/$DOMAIN.cert.pem \
        $INTERMEDIATE_SERV_DIR/ca_intermediate_serv.cert.pem \
        > $INTERMEDIATE_SERV_DIR/certs/$DOMAIN.chained.cert.pem
done

echo "##########################"
echo "####### User certs #######"
echo "##########################"

ADMIN_ID=admin_user              # If more than one user cert should be created,
PKCS12_PASSWORD=de4pheeYieb6ahc  #  need to make these dynamic
for USER in admin_ca@imovies.ch
do
  echo "####### Cert for $USER #######"
  openssl genrsa \
        -out $INTERMEDIATE_USR_DIR/private/$ADMIN_ID.key.pem 2048  
  openssl req \
        -config $INTERMEDIATE_USR_DIR/openssl.ca_intermediate_usr.cnf \
        -key $INTERMEDIATE_USR_DIR/private/$ADMIN_ID.key.pem \
        -new -sha256 -out $INTERMEDIATE_USR_DIR/csr/$ADMIN_ID.csr.pem \
        -subj "/C=CH/ST=Zurich/L=Zurich/O=iMovies, Inc./OU=IT Department/CN=$USER"
  # for the following command, override some configs because config file is
  #   written for use in production
  openssl ca -batch \
        -days 365 -notext -md sha256 \
        -config $INTERMEDIATE_USR_DIR/openssl.ca_intermediate_usr.cnf \
        -keyfile $INTERMEDIATE_USR_DIR/private/ca_intermediate_usr.key.pem \
        -cert $INTERMEDIATE_USR_DIR/ca_intermediate_usr.cert.pem \
        -in $INTERMEDIATE_USR_DIR/csr/$ADMIN_ID.csr.pem \
        -out $INTERMEDIATE_USR_DIR/newcerts/$ADMIN_ID.cert.pem \
        -passin pass:$INTERMEDIATE_USR_KEY_PASSPHRASE
  openssl x509 -noout -text \
        -in $INTERMEDIATE_USR_DIR/newcerts/$ADMIN_ID.cert.pem
  openssl verify -CAfile $INTERMEDIATE_USR_DIR/ca-chain_usr.cert.pem \
        $INTERMEDIATE_USR_DIR/newcerts/$ADMIN_ID.cert.pem
  openssl pkcs12 -export -chain \
        -CAfile $INTERMEDIATE_USR_DIR/ca-chain_usr.cert.pem \
        -inkey $INTERMEDIATE_USR_DIR/private/$ADMIN_ID.key.pem \
        -in $INTERMEDIATE_USR_DIR/newcerts/$ADMIN_ID.cert.pem \
        -out $INTERMEDIATE_USR_DIR/newcerts/$ADMIN_ID.pkcs12 \
        -passout pass:$PKCS12_PASSWORD
  echo -n $PKCS12_PASSWORD > $INTERMEDIATE_USR_DIR/newcerts/$ADMIN_ID.pkcs12.password
done

