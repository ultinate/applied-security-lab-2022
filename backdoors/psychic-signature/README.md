# Psychic signatures for RSA
Based on CVE-2022-21449. See https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/ for details.

Difficulty to find:
  * Blackbox approach: Very hard
  * Whitebox approach: Hard

## Specifications
Originally: r, s of ECDSA signature must be both zero to trigger the bug, i.e. to
make the signature verification pass (even though it should fail).

Adapted to RSA, we define that the signature must be all zero to trigger the bug.
For ease of implementation, the first n bytes (n=1, for the most simple case) of 
the signature must be zero.

Use cases: An attacker A can manipulate certificates to gain unauthorized access
to the system. For example: 
  * A creates a keypair and a self-signed certificate. Then, they modify the
    certificate to include the correct issuer and the serial number and common
    name of a valid CA user's certificate and add a psychic signature. A can now
    access the system.
  * A obtains an expired user certificate with corresponding private key. Modify
    the validity period to make other users believe that the certificate is still
    valid. During interaction with the central server, however, the certificate
    can be checked on server-side, thus this attack will not work.
  * A obtains a valid user certificate with corresponding private key. Modify the
    serial number and common name to match a valid CA admin's certificate and add
    a psychic signature. A can now access the admin page.

## Manipulating certificates
1. Take existing certificate in DER format.
   (If in PEM format, use `openssl x509 -in 01.pem -out 01.der -outform DER` to convert.)
2. Use hex editor like ghex to modify parts to taste (`commonName`).
3. Update signature according to specs above.
4. Take existing private key in PEM format.
5. Access the system using `curl --cert 0201_psychic.pem --key 0201.key --cacert ca_root.cert.pem  https://imovies.ch:443/admin`.

Note: The standard way of creating new PKCS#12 bundle using
`openssl pkcs12 -export -inkey key_file_name -in cert_file_name -out pkcs12_file_name -nodes` is more difficult because Firefox performs certificate checking when you try to import this file into the browser.

## Patching nginx and OpenSSL
Compile nginx from source and link to the patched openSSL source using script
`./compile-nginx.sh`.

Location of openSSL code to patch
https://github.com/openssl/openssl/blob/master/crypto/asn1/a_verify.c#L212

Patch: `openssl-psychic.patch`

## Patching OpenSSL
If you need a command-line access to a patched openSSL, use the following commands.

```
sudo apt install libssl-dev libc-dev linux-headers-$(uname -r)
git clone https://github.com/openssl/openssl.git
cd openssl
git checkout OpenSSL_1_1_1f
git switch -c feature/bounds-check
git am openssl-psychic.patch
./config no-ssl2 no-ssl3 no-comp no-idea no-dtls no-dtls1 no-psk no-srp no-weak-ssl-ciphers --openssldir=/usr/local/ssl --prefix=/usr/local/ssl
make
sudo make install

sudo ldconfig /usr/local/ssl/lib64/
sudo ldconfig /usr/local/ssl/lib/
export PATH=/usr/local/ssl/bin:$PATH
sudo mv /usr/bin/openssl /usr/bin/openssl.BAK
```

Done. You can now use your new, patched openSSL, e.g. like so:

```
openssl verify -CAfile ca-chain.cert.pem 01.pem
openssl verify -CAfile ca-chain.cert.pem 01.psychic.pem
```

