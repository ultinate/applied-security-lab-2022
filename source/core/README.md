# Core CA

Short description

  * OS: Linux Ubuntu server, headless (no GUI).
  * Firewall: iptables (frontend: ufw, rule engine: netfilter).
  * Management interface: Vagrant (or OpenSSH).
  * Web application: Framework Flask. Programming language Python.
  * Web server: Nginx.
  * Network: Internal network, IPv4 address: (see Vagrantfile)
    Open incoming ports: tcp/22, tcp/443.
  * Users: Root, CA user, sysadmin, Backup user.
  * Remarks: Frontend application authenticates itself at every request with mTLS or 
    API token to core CA.
  * Data: Standard files for CA management (serial, private keys, certs, root CA cert 
    and private key). State of the CA is stored inside these files (especially index.txt).
    The application itself is stateless and has no database.

Longer description

  * Root CA and Intermediate CA key pairs and certificates are generated
    during vagrant provisioning. Also, (TLS) server certificates are generated.
  * User certificates can be requested by caller application during runtime. 
    Key pairs are generated on the server and the certificate and key bundle 
    is then presented to the caller.

## Development notes
For local testing, start server using `./run_locally.sh`. The API is now available at `http://localhost:5000/`. Use `curl http://localhost:5000/ping` to start.

Certificates are generated offline (i.e. before starting the vagrant provisioning) by manually running `/core/secrets/local_bootstrap_once.sh`.
This will generate all Root CA, Intermediate CA and Server Certificates and store them locally.
Afterwards, `vagrant up --provision` will copy the certificates and keys to the appropriate places on all machines.

## API
This section describes the API for the Core CA that is offered to the Frontend Application. 
Data format is 'JSON', the default content-type is `application/json`.

The API manages certificates identified by numerical IDs. User management
is expected to be handled by the consumer application.

### API Endpoints
The `/ping` endpoint responds to both `GET` and `POST` requests, which may be useful for testing. All other endpoints
respond to either `GET` or `POST` requests.

The following API endpoints require no authentication and respond to `GET` requests.
  * `/ping`: Return a response for POST and GET requests without authentication.
  * `/crl`: Return certificate revocation list as `crl_object`.
  * `/crl-root`: Return certificate revocation list of Root CA as `crl_object`.
  * `/crl-server`: Return certificate revocation of Intermediate Server CA list ("sister CA" of Intermediate User CA)
    as `crl_object`.

The following API endpoints require authentication by sending a correct `api_key` as `POST` parameter.
  * `/certs`: Return list of certificates.
  * `/certs/new`: Request new certificate by sending a `request_object`. Returns the certificate as `cert_info`.
  * `/certs/<id>`: Return certificate as `cert_info`.
  * `/certs/<id>/download`: Download certificate and private key as `pkcs12_cert`.
  * `/certs/<id>/revoke`: Revoke certificate.
  * `/stats`: Return some statistics as a `cert_stat` object.

### Data Objects
All data objects are JSON representation of a number of fields.

`cert_info`: 
  * `id`: Certificate ID (decimal value).
  * `status`: any of the following
    * `expired`: cert has expired
    * `valid`: cert is valid and ready for download
    * `revoked`: cert is revoked
  * `name`: CommonName of certificate (the email address)

Example:
```json
{ "id": 3,  "status": "valid", "name": "foo@imovies.ch" }
```

`pkcs12_cert`: 
  * `id`: Certificate ID (decimal value).
  * `certificate`: Certificate in PKCS#12 format, base64-encoded, 
    including password-protected private key and certificate chain.
  * `password`: Password to decrypt private key.

Example:
```json
{ "id": 3,  "certificate": "MIIDYTCCAkmgAwI...", "password": "fuNgdee6ha" }
```

`cert_stat`: JSON representation of the following fields:
  * `num_certs`: (integer) Number of issued certificates.
  * `num_revoked`: (integer) Number of revoked certificates.
  * `current_serial`: (string) Current serial number as hex number which will be used 
    for the next certificate.

Example:
```json
{ "num_certs": 33,  "num_revoked": 4, "current_serial": "100A" }
```

`request_object`: JSON representation of the following fields:
  * `common_name`: Must contain a valid email address ending in `@imovies.ch`.

Example:
```json
{ "common_name": "foobar@imovies.ch", "api_key": "fc4b...99d6" }
```

`crl_object`: 
  * `crl`: CRL in PEM format.

Example:
```json
{ "crl": "-----BEGIN X509 CRL-----\nMIIBzT...3l2tg\n-----END X509 CRL-----\n" }
```


### Example calls
For testing from another VM (e.g. `frontend`), use the following commands:

```
curl http://core.imovies.ch/ping
curl http://core.imovies.ch/stats -X POST -H "Content-Type: application/json" -d '{"api_key": "fc4b5fd6816f75a7c81fc8eaa9499d6"}'
curl http://core.imovies.ch/certs -X POST -H "Content-Type: application/json" -d '{"api_key": "fc4b5fd6816f75a7c81fc8eaa9499d6"}'
curl http://core.imovies.ch/certs/new -X POST -H "Content-Type: application/json" -d '{"api_key": "fc4b5fd6816f75a7c81fc8eaa9499d6", "common_name": "foobar@imovies.ch"}'
curl http://core.imovies.ch/certs/01 -X POST -H "Content-Type: application/json" -d '{"api_key": "fc4b5fd6816f75a7c81fc8eaa9499d6"}'
curl http://core.imovies.ch/certs/01/download -X POST -H "Content-Type: application/json" -d '{"api_key": "fc4b5fd6816f75a7c81fc8eaa9499d6"}'
curl http://core.imovies.ch/certs/01/revoke -X POST -H "Content-Type: application/json" -d '{"api_key": "fc4b5fd6816f75a7c81fc8eaa9499d6"}'
curl http://core.imovies.ch/crl -X POST -H "Content-Type: application/json" -d '{"api_key": "fc4b5fd6816f75a7c81fc8eaa9499d6"}'
```



## Simulated hardware security module (HSM)
A folder `/mnt/hsm` simulates a hardware security module (HSM) which securely stores
private keys and passphrases.
