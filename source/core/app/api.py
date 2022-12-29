import base64
import logging.config
import os
import re
import subprocess
import tempfile

import yaml
from Crypto.Random import get_random_bytes
from flask import Flask
from flask_restful import reqparse, abort, Api, Resource
from werkzeug.middleware.proxy_fix import ProxyFix


try:
    CA_DIR = os.environ["CA_DIR"]
except KeyError:
    CA_DIR = "./work/intermediate_usr"
PRIVATE_DIR = "/mnt/hsm"
LATEST_SERIAL_FILE = CA_DIR + "/serial"
CERT_DIR = CA_DIR + "/newcerts"
CONFIG_FILE = CA_DIR + "/openssl.ca_intermediate_usr.cnf"
INDEX_FILE = CA_DIR + "/index.txt"
ROOT_CRL = "./work/ca_root.crl.pem"
INTERMEDIATE_SERV_CRL = "./work/intermediate_serv/ca_intermediate_serv.crl.pem"
INTERMEDIATE_USR_CHAIN = "./work/intermediate_usr/ca-chain_usr.cert.pem"
CA_KEY_PASSPHRASE_FILE = PRIVATE_DIR + "/intermediate_usr_passphrase.txt"
CERT_STATUS_VALUES = {
    "V": "valid",
    "R": "revoked",
    "E": "expired",
}
PASSWORD_BYTES = 16
ALLOWED_EMAIL_REGEX = "^[a-z0-9][.a-z0-9-_]*@imovies.ch$"
INDEX_FILE_REGEX = "^([A-Z])\t[0-9]*Z\t[0-9]*[Z]?\t([0-9a-zA-Z]+)\tunknown\t.*CN=([.a-z0-9-_@]*)$"

# Load allowed API_KEYS from file or ENV variable
try:
    API_KEYS_FILE = os.environ["API_KEYS_FILE"]
except KeyError:
    API_KEYS_FILE = "./api_keys"
with open(API_KEYS_FILE, 'r') as file:
    ALLOWED_API_KEYS = file.read()

# Set up logger
logger = None
if "UNITTEST" not in os.environ:
    with open('./app/logging.yaml', 'r') as f:
        log_cfg = yaml.safe_load(f.read())
        logging.config.dictConfig(log_cfg)
    logger = logging.getLogger('apiLogger')
    logger.info('Starting api.py ...')

# Set up argument parser
parser = reqparse.RequestParser()
parser.add_argument('common_name')
parser.add_argument('first_name')
parser.add_argument('last_name')
parser.add_argument('api_key')

# Start application
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
api = Api(app)


def parse_index_file(index_file=None):
    """Reads an OpenSSL index.txt file and returns parsed list

    :return: List of dict {status, id, name}, where
      * status: V / R / E
      * id: 8-based integer
      * name: CN. In this context, we expect this to be an email address
    """
    if not index_file:
        index_file = INDEX_FILE
    cert_list = []
    try:
        with open(index_file, "r") as file:
            for line in file:
                match = re.search(INDEX_FILE_REGEX, line)
                if match:
                    status, cert_id, name = match.groups()
                    cert_list.append({"status": CERT_STATUS_VALUES[status],
                                      "id": cert_id,
                                      "name": name})
    except FileNotFoundError:
        abort(500, message="Index file not found.")
    return cert_list


def load_certificate_index():
    """Load certificate index from file

    Run this function at the start of every request.

    :return: [Dict of certificates, last_ID]
    """
    cert_list = parse_index_file()
    certs = {}
    for cert in cert_list:
        certs[cert["id"]] = {"id": cert["id"], "status": cert["status"], "name": cert["name"]}
    return certs


def get_last_certificate_id():
    """Get last certificate ID
    """
    cert_list = parse_index_file()
    return cert_list[-1]["id"]


def abort_if_cert_doesnt_exist(cert_id, certs):
    abort_if_not_authenticated()
    try:
        _ = certs[cert_id]
    except KeyError:
        logger.debug(f"Requested cert_id `{cert_id}` not found")
        abort(404, message="Certificate does not exist.")


def abort_if_not_authenticated():
    args = parser.parse_args()
    if args['api_key'] not in ALLOWED_API_KEYS:
        abort(401, message="Authentication error.")


def get_certificate_file(cert_id):
    return f"{CERT_DIR}/{cert_id}.pem"


def get_key_file(cert_id):
    return f"{CERT_DIR}/{cert_id}.key"


def generate_password():
    """Generate a human-readable password
 
    Note: Strip last two characters to get rid of padding characters ("=") for better usability.
          This reduces at most 8 bits of entropy.
    """
    return base64.urlsafe_b64encode(get_random_bytes(PASSWORD_BYTES)).decode()[:-2]


class ResourceWithCertificateIndex(Resource):
    """Base class for all resources that need a certificate_index
    """
    def __init__(self):
        self.certs = load_certificate_index()


class Cert(ResourceWithCertificateIndex):
    """Shows certificate by ID with status
    """

    def post(self, cert_id):
        abort_if_cert_doesnt_exist(cert_id, self.certs)
        return self.certs[cert_id]


class CertList(ResourceWithCertificateIndex):
    """Shows a list of all CERTS with ID and status
    """

    def post(self):
        abort_if_not_authenticated()
        return [c for c in self.certs.values()]


def sanitize_data_for_cert(data: str):
    """Because of paranoia, only allow [A-Za-z@.-_]
    """
    import string
    allowed_characters = string.ascii_lowercase + string.ascii_uppercase + "@.-_"
    return "".join([c for c in data if c in allowed_characters])


class CertNew(Resource):
    """Request new certs by submitting a commonName

    :return: the newly created `cert_object`
    """

    def post(self):
        abort_if_not_authenticated()
        args = parser.parse_args()
        common_name: str = args['common_name']
        first_name: str = sanitize_data_for_cert(args['first_name'])
        last_name: str = sanitize_data_for_cert(args['last_name'])
        if not common_name:
            abort(500, message="commonName (=email address) must be provided.")
        common_name = common_name.lower()
        if not re.match(ALLOWED_EMAIL_REGEX, common_name):
            logger.debug(f"Requested commonName `{common_name}` not valid")
            abort(500, message="Certificate could not be created for this commonName (=email address).")

        # generate key pair
        key_file = tempfile.NamedTemporaryFile()
        command = ["openssl", "genrsa",
                   "-out", key_file.name,
                   "2048"]
        outcome = subprocess.run(command, capture_output=True, check=False)
        logger.debug(command)
        if outcome.returncode != 0:
            logger.error(outcome.stderr)
            abort(500, message="Private key could not be created.")

        # generate CSR
        csr_file = tempfile.NamedTemporaryFile()
        subject = f"/C=CH/ST=Zurich/L=Zurich/O=iMovies, Inc./OU=IT Department/CN={common_name}"
        comment = f"nsComment=User-provided name: {first_name} {last_name}"
        command = ["openssl", "req",
                   "-new",
                   "-key", key_file.name,
                   "-out", csr_file.name,
                   "-subj", subject,
                   "-addext", comment,
                   ]
        outcome = subprocess.run(command, capture_output=True, check=False)
        if outcome.returncode != 0:
            logger.error(outcome.stderr)
            abort(500, message="CSR could not be created.")

        command = ["openssl", "ca",
                   "-batch",
                   "-in", csr_file.name,
                   "-config", CONFIG_FILE,
                   "-passin", f"file:{CA_KEY_PASSPHRASE_FILE}",
                   ]
        outcome = subprocess.run(command, capture_output=True, check=False)
        logger.debug(command)
        if outcome.returncode != 0:
            logger.error(outcome.stderr)
            err_msg = outcome.stderr.decode("utf-8")
            if "There is already a certificate for" in err_msg:
                abort(404,
                      message="There is already a valid certificate for this email address. No certificate created.")
            else:
                abort(500, message="Certificate could not be created.")

        certs = load_certificate_index()
        cert_id = get_last_certificate_id()

        # Save private key
        private_key_file_name = get_key_file(cert_id)
        command = ["cp", key_file.name, private_key_file_name]
        outcome = subprocess.run(command, capture_output=True, check=False)
        logger.debug(command)
        if outcome.returncode != 0:
            logger.error(outcome.stderr)
            abort(500, message="Private key could not be saved.")

        return certs[cert_id], 201


class CertDownload(ResourceWithCertificateIndex):
    """Download certificate in PEM format
    """

    def post(self, cert_id):
        abort_if_cert_doesnt_exist(cert_id, self.certs)
        if self.certs[cert_id]["status"] != "valid":
            abort(404, message="Only valid certificates can be downloaded.")
        certificate, password = self.get_certificate(cert_id)
        return {"id": cert_id, "certificate": certificate, "password": password}

    def get_certificate(self, cert_id):
        """Read certificate from file

        :return: certificate in PKCS#12 format with password-protected private key
        """

        # Generate PKCS#12 file
        cert_file_name = get_certificate_file(cert_id)
        pkcs12_file = tempfile.NamedTemporaryFile()
        key_file_name = get_key_file(cert_id)
        pkcs12_password = generate_password()
        command = ["openssl", "pkcs12",
                   "-export", "-chain",
                   "-CAfile", INTERMEDIATE_USR_CHAIN,
                   "-inkey", key_file_name,
                   "-in", cert_file_name,
                   "-out", pkcs12_file.name,
                   "-passout", "pass:" + pkcs12_password,
                   ]
        outcome = subprocess.run(command, capture_output=True, check=False)
        logger.debug(command)
        if outcome.returncode != 0:
            logger.error(outcome.stderr)
            abort(500, message="PKCS#12 could not be created.")

        # Read PKCS#12 file
        with open(pkcs12_file.name, "rb") as file:
            pkcs12_certificate = file.read()
        pkcs12_certificate = base64.b64encode(pkcs12_certificate).decode()
        if not pkcs12_certificate:
            abort(500, message="PKCS#12 could not be loaded.")

        return pkcs12_certificate, pkcs12_password


class CertRevoke(ResourceWithCertificateIndex):
    """Ask server to revoke certificate

    :return: `cert_object`
    """

    def post(self, cert_id):
        abort_if_cert_doesnt_exist(cert_id, self.certs)
        cert_file = get_certificate_file(cert_id)
        if self.certs[cert_id]["status"] == "revoked":
            abort(404, message="Certificate is already revoked.")
        command = ["openssl", "ca",
                   "-config", CONFIG_FILE,
                   "-passin", f"file:{CA_KEY_PASSPHRASE_FILE}",
                   "-revoke", cert_file,
                   ]
        logger.debug(command)
        outcome = subprocess.run(command, capture_output=True, check=False)
        if outcome.returncode != 0:
            logger.error(outcome.stderr)
            abort(500, message="Certificate could not be revoked.")

        certs = load_certificate_index()
        return certs[cert_id]


def load_crl_from_file(file_name):
    with open(file_name, "rb") as crl_file:
        crl = crl_file.read().decode()
    if not crl:
        abort(500, message="CRL could not be loaded.")
    return crl


class Crl(Resource):
    """Returns CRL based on index file

    :return: `crl_object`
    """

    def get(self):
        crl_file = tempfile.NamedTemporaryFile()
        command = ["openssl", "ca",
                   "-gencrl",
                   "-out", crl_file.name,
                   "-config", CONFIG_FILE,
                   "-passin", f"file:{CA_KEY_PASSPHRASE_FILE}",
                   ]
        logger.debug(command)
        outcome = subprocess.run(command, capture_output=True, check=False)
        if outcome.returncode != 0:
            logger.error(outcome.stderr)
            abort(500, message="CRL could not be generated.")
        return {"crl": load_crl_from_file(crl_file.name)}


class CrlRoot(Resource):
    """Returns (static) CRL for Root CA

    :return: `crl_object`
    """

    def get(self):
        return {"crl": load_crl_from_file(ROOT_CRL)}


class CrlIntermediateServer(Resource):
    """Returns (static) CRL for Intermediate Server CA

    :return: `crl_object`
    """

    def get(self):
        return {"crl": load_crl_from_file(INTERMEDIATE_SERV_CRL)}


class Stats(ResourceWithCertificateIndex):
    """Shows some statistics
    """

    def post(self):
        abort_if_not_authenticated()
        stats = {
            "num_certs": len(self.certs),
            "num_revoked": self.get_num_revoked(),
            "current_serial": self.read_current_serial(),
        }
        return stats

    def get_num_revoked(self):
        if not self.certs:
            return 0
        num_revoked = 0
        for c in self.certs.values():
            if c["status"] == "revoked":
                num_revoked += 1
        return num_revoked

    def read_current_serial(self, latest_serial_file=None):
        if not latest_serial_file:
            latest_serial_file = LATEST_SERIAL_FILE
        try:
            with open(latest_serial_file, "r") as file:
                current_serial = file.readline().strip()
        except ValueError:
            current_serial = -1
        return current_serial


class Ping(Resource):
    """Reply something for testing
    """

    def post(self):
        return "Hello world! (POST)"

    def get(self):
        return "Hello world! (GET)"


api.add_resource(CertList, '/certs')
api.add_resource(CertNew, '/certs/new')
api.add_resource(Cert, '/certs/<cert_id>')
api.add_resource(CertDownload, '/certs/<cert_id>/download')
api.add_resource(CertRevoke, '/certs/<cert_id>/revoke')
api.add_resource(Stats, '/stats')
api.add_resource(Ping, '/ping')
api.add_resource(Crl, '/crl')
api.add_resource(CrlRoot, '/crl-root')
api.add_resource(CrlIntermediateServer, '/crl-server')
