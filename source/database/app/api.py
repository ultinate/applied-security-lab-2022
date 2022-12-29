import base64
import binascii
import datetime
import hashlib
import json
import logging.config
import os
from typing import List
from urllib import request
import mysql.connector
import yaml
from Crypto.Cipher import AES
from flask import Flask
from flask import request
from flask_restful import abort, Api, Resource
from jsonschema.exceptions import ValidationError
from jsonschema.validators import validate
from werkzeug.middleware.proxy_fix import ProxyFix

from .request_schema import *

logger = None
if "UNITTEST" not in os.environ:
    with open('./app/logging.yaml', 'r') as f:
        log_cfg = yaml.safe_load(f.read())
        logging.config.dictConfig(log_cfg)
    logger = logging.getLogger('apiLogger')
    logger.info('Starting api.py ...')

ALLOWED_API_KEYS = []
DB_API_KEY_FILE = "./api_keys"
with open(DB_API_KEY_FILE, 'r') as file:
    ALLOWED_API_KEYS.append(file.readline())
    logger.info('Loaded API Keys')

# Password configuration
PASSWORD_REQ_LEN = 8
PASSWORD_MAX_LEN = 128
PASSWORD_REQ_CAPITAL = True
PASSWORD_REQ_LOWERCASE = True
PASSWORD_REQ_NUMERAL = True
PASSWORD_REQ_SPECIAL_SYMBOL = True
PASSWORD_SPECIAL_CHARACTERS = '!@#$%^&*()-+?_=,<>/"'

# Internal string representation
INPUT_ENCODING = 'utf-8'

# ERROR MSG
MALFORMED_REQUEST_MESSAGE = "Malformed request"
INTERNAL_ERROR_MESSAGE = "Internal error"

cnx = None


# Initialize the connection
try:
    # deployment mode
    if os.environ.get("IS_LOCAL_TESTING", default=None) is None:
        cnx = mysql.connector.connect(option_files="/home/database/.my.cnf")
        logger.info('Established DB connection Production')
    else:
        # local mode
        cnx = mysql.connector.connect(user='webapp', password='password',
                                      host='127.0.0.1',
                                      database='imovies')
        logger.info('Established DB connection LOCAL MODE')
except Exception as connection_error:
    logger.error(f'Unable to connect to the DB: {connection_error}')
    exit(-1)

# Disable the autocommit feature (is default)
cnx.autocommit = False

# Key for the user_id
ENC_KEY = None
if "SECRET_KEY" in os.environ:
    hex_key = os.environ["SECRET_KEY"]
    ENC_KEY = bytes.fromhex(hex_key)
    logger.info("Loaded secret key")
else:
    logger.error("Cannot load secret key - exit now")
    exit(-2)


# Start application
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
api = Api(app)


# Define an error handler to avoid leaking information to the client
@app.errorhandler(Exception)
def handle_exception(error):
    """
    Generic exception catcher to hide internal exceptions to avoid the leakage of information

    :param error: Caught exception
    :return: Error page
    """
    logger.error(f"An unhandled exception occurred: {error}")
    return "Error", 500


@app.errorhandler(404)
def page_not_found(error):
    logger.warning(f"Client tried to access an non-existent site: {error}")
    return "Page not found", 404


def abort_if_malformed_json(data: dict, schema: str):
    try:
        validate(data, schema=json.loads(schema))
    except ValidationError as error:
        logger.warning(f"Client submitted a malformed request that could not be validated: {error}")
        abort(400, message="Malformed request")
    except json.decoder.JSONDecodeError as error:
        logger.warning(f"Client submitted a malformed request that could not be parsed: {error}: data: {data}")
        abort(400, message="Malformed request")


def abort_if_not_authenticated():
    """
    Aborts the request if the request_object is malformed or the API Key is not matching

    :return: Nothing in the case of success
    :raises Code 400 if malformed and Code 401 if the API Key is wrong
    """
    if not request.content_type.startswith('application/json'):
        logger.warning(f"Client submitted a non-json request")
        abort(400, message="Malformed request")

    abort_if_malformed_json(request.get_json(), SCHEMA_REQ_OBJECT)

    if request.get_json()['api_key'] not in ALLOWED_API_KEYS:
        logger.error(f"Client submitted an unknown api token")
        abort(401, message="Unauthorized")


def get_validated_request_json(schema: str) -> dict:
    """
    Obtains the request payload and verify that it matches the given schema

    :param schema: expected format of the payload
    :raises Code 400 if the request instance does not match the schema
    """
    data = request.get_json()["request"]
    abort_if_malformed_json(data, schema)
    return data


def parse_user_identifier(identifier: dict) -> str:
    """
    Parses a user_identifier object and checks that the referenced user exists in the database

    :param identifier: user_identifier object representing the user
    :return: user identifier 'uid' that is understood by the database
    :raises Code 400 if the object is malformed or cannot be decrypted
    """
    abort_if_malformed_json(identifier, schema=SCHEMA_USER_IDENTIFIER)

    try:
        data_raw = base64.urlsafe_b64decode(identifier["id"].encode(INPUT_ENCODING))
    except binascii.Error as error:
        logger.warning(f"parse_user_identifier: Unable to parse the identifier \"{identifier}\" due to: {error}")
        abort(400, message=MALFORMED_REQUEST_MESSAGE)

    if len(data_raw) < 27:
        logger.warning(f"parse_user_identifier: Client submitted an user identifier \"{identifier}\" that was too short")
        abort(400, message=MALFORMED_REQUEST_MESSAGE)

    nonce = data_raw[0:11]
    tag = data_raw[11:27]
    ctxt = data_raw[27:]
    cipher = AES.new(ENC_KEY, AES.MODE_CCM, nonce=nonce)
    try:
        ptxt = cipher.decrypt_and_verify(ctxt, tag).decode(INPUT_ENCODING)
    except (ValueError, KeyError) as error:
        logger.warning(f"parse_user_identifier: Client submitted an user identifier \"{identifier}\" that could not be decrypted: {error}")
        abort(400, message=MALFORMED_REQUEST_MESSAGE)
    try:
        payload = json.loads(ptxt)
        user_id = str(payload["id"])
    except json.JSONDecodeError as error:
        logger.warning(f"parse_user_identifier: Client submitted an user identifier \"{identifier}\" (containing: {ptxt}) that could not be parsed by the json parser: {error}")
        abort(400, message=MALFORMED_REQUEST_MESSAGE)

    if check_uid_in_db(user_id):
        logger.info(f"Valid user identifier \"{user_id}\" was passed")
        return user_id
    else:
        logger.warning(f"parse_user_identifier: Client tried to submit the unknown user id {user_id}")
        abort(400, message=MALFORMED_REQUEST_MESSAGE)


def generate_user_identifier(uid: str) -> dict:
    """
    Generates a user_identifier object that can be given out to the client

    :param uid: internal representation of the user identifier
    :return: external representation of the user identifier
    """
    try:
        ptx = json.dumps({"id": uid, "time": datetime.datetime.utcnow().isoformat()})
        cipher = AES.new(ENC_KEY, AES.MODE_CCM)
        ctx, tag = cipher.encrypt_and_digest(ptx.encode(INPUT_ENCODING))
        nonce = cipher.nonce
        token = base64.urlsafe_b64encode(nonce + tag + ctx).decode(INPUT_ENCODING)
        return {"id": token}
    except Exception as error:
        logger.error(f"Unable to generate the user identifier due to: {error}")
        abort(500, message=INTERNAL_ERROR_MESSAGE)
        return {}


def generate_user_profile(uid: str) -> dict:
    """
    Obtains the user profile from the database

    :param uid: internal identifier of the user
    :return: user_profile of the referenced user
    :raises Code 404 if the user does not exist,
            Code 500 in the case of a request failure
    """
    cursor = cnx.cursor(prepared=True)
    cursor.execute("SELECT uid, email, firstname, lastname FROM users WHERE users.uid = %s;", (uid,))

    result = [{"user": generate_user_identifier(x[0]), "email": x[1], "firstname": x[2], "lastname": x[3]} for x in cursor.fetchall()]
    cursor.close()
    if len(result) == 0:
        logger.warning(f"Unable to generate user-profile for \"{uid}\"")
        abort(404, message="Data not found")
    elif len(result) != 1:
        logger.warning(f"Unable to generate user-profile for \"{uid}\" due to too many results: Expected 1 got {len(result)}")
        abort(500, message=INTERNAL_ERROR_MESSAGE)
    else:
        return result[0]


def get_matching_user_credentials_by_email(email: str) -> List[dict]:
    """
    Obtains a user's UID and password-hash by matching the email address

    :param email: email address to check
    :return: list of matching UID, password-hash tuples
    """
    cursor = cnx.cursor(prepared=True)
    cursor.execute("SELECT uid, pwd FROM users WHERE users.email = %s;", (email,))
    users = []
    for (uid, password) in cursor:
        users.append({"uid": uid, "password": password})
    cursor.close()
    return users


def get_user_credentials_by_uid(uid: str) -> dict:
    """
    Obtains a user's UID and password-hash based on the UID

    :param uid: Internal identifier of the referenced user
    :return: Tuple of the UID and password hash
    :raises Code 400 if there is not an exact match for the credentials
    """
    cursor = cnx.cursor(prepared=True)
    cursor.execute("SELECT uid, pwd FROM users WHERE users.uid = %s;", (uid,))
    users = []
    for (uid, password) in cursor:
        users.append({"uid": uid, "password": password})
    cursor.close()

    if len(users) != 1:
        logger.warning(f"Unable to get credential by uid for \"{uid}\" due to too many results: Expected 1 got {len(users)}")
        abort(400, message=MALFORMED_REQUEST_MESSAGE)

    return users[0]


def check_user(password_to_verify: str, user: dict) -> dict:
    try:

        if hashlib.sha1(password_to_verify.encode(INPUT_ENCODING)).hexdigest() == user["password"]:
            return {"id": user['uid']}
        else:
            return {}
    except ValueError as error:
        logger.warning(f"Error occurred during password checking: {error}")
        return {}


def check_uid_in_db(uid: str) -> bool:
    """
    Checks if the user exists

    :param uid: User identifier in the database that should be checked
    :return: True iff the user exists
    """
    try:
        cursor = cnx.cursor(prepared=True)
        cursor.execute("SELECT COUNT(*) FROM users WHERE users.uid = %s;", (uid,))
        result = [int(data[0]) for data in cursor.fetchall()]
        cursor.close()
        return result[0] == 1
    except mysql.connector.Error as error:
        logger.error(f"Error during the check of the uid \"{uid}\"in the database: {error}")
        abort(500, message=INTERNAL_ERROR_MESSAGE)


def update_user_profile(user_id: str, profile_data: dict) -> bool:
    """
    Updates the email, firstname and lastname of the given user. Fails if the email address is not unique

    :param user_id: User identifier of the user that should be modified
    :param profile_data: user_profile with the updated data
    :return: True iff the update was successful and the email address did not exist yet
    """
    cursor = cnx.cursor(prepared=True)
    try:
        print(f"Update: Firstname: {profile_data['firstname']}, Lastname: {profile_data['lastname']}")
        cursor.execute(
            "UPDATE users SET firstname = %s,lastname  = %s WHERE uid = %s;",
            (profile_data["firstname"], profile_data["lastname"], user_id,))
        affected_rows = cursor.rowcount
        cnx.commit()
        cursor.close()
        logger.info(f'Update user profile for {user_id} was successful {affected_rows == 1}')
        return affected_rows == 1
    except (mysql.connector.Error, mysql.connector.InternalError) as error:
        cnx.rollback()
        logger.error(f"Error during update of the profile of uid \"{user_id}\"in the database: {error}")
        abort(500, message=INTERNAL_ERROR_MESSAGE)


class AuthenticatePwEP(Resource):
    def get(self):
        """
        Authenticates a user based on the email and password and returns the corresponding user profile
        """
        logger.info("Authentication with Password EP was called")
        abort_if_not_authenticated()
        req = get_validated_request_json(schema=SCHEMA_AUTH_REQUEST_PW)
        email = str(req['email'])

        authenticated_users = list(filter(lambda val: val != {}, [check_user(req["password"], user) for user in get_matching_user_credentials_by_email(email)]))

        if len(authenticated_users) == 1:
            logger.info(f"User \"{authenticated_users[0]['id']}\" logged in")
            return generate_user_profile(authenticated_users[0]["id"]), 200
        elif len(authenticated_users) == 0:
            logger.warning(f"User with email {email} failed to log in")
            abort(401, message="Failed to authenticate")
        else:
            logger.error(f"PwEP: Too many entries found for the email {email}")
            abort(500, message=INTERNAL_ERROR_MESSAGE)


class AuthenticateCertEP(Resource):
    def get(self):
        """
        Resolves an email address to an uid
        Assumes: The email address is based on the email address in the certificate and the validity of the certificate was checked before.
        """
        logger.info("Authentication with Certificate EP was called")
        abort_if_not_authenticated()
        req = get_validated_request_json(schema=SCHEMA_EMAIL_OBJECT)

        cursor = cnx.cursor(prepared=True)
        cursor.execute("SELECT t.uid FROM users as t WHERE email = %s;", (req["email"],))
        result = [data[0] for data in cursor.fetchall()]
        cursor.close()
        if len(result) == 1:
            logger.info(f"User \"{result[0]}\" logged in")
            profile = generate_user_profile(result[0])
            return profile, 200
        else:
            logger.warning(f"User with email {req['email']} failed to log in")
            abort(401, message="Failed to authenticate")


class AuthenticateAdminEP(Resource):
    def get(self):
        """
        Check if the given email address corresponds to an admin
        Assumes: The email address is based on the email address in the certificate and the validity of the certificate was checked before.
        """
        logger.info("Authentication for Admin EP was called")
        abort_if_not_authenticated()
        req = get_validated_request_json(schema=SCHEMA_EMAIL_OBJECT)

        cursor = cnx.cursor(prepared=True)
        cursor.execute("SELECT t.email FROM administrators as t WHERE email = %s;", (req["email"],))
        result = [data[0] for data in cursor.fetchall()]
        cursor.close()
        if len(result) == 1:
            logger.info(f"Admin \"{result[0]}\" logged in")
            return {"email": result[0]}, 200
        else:
            logger.info(f"Cannot log admin \"{req['email']}\" in")
            abort(401, message="Failed to authenticate")


class ProfileEP(Resource):
    def get(self):
        """
        Obtains the user profile referenced by the user_id
        """
        logger.info("Get Profile EP was called")
        abort_if_not_authenticated()
        req = get_validated_request_json(schema=SCHEMA_USER_IDENTIFIER)
        return generate_user_profile(parse_user_identifier(req))

    def put(self):
        """
        Updates the user profile referenced by the user_id
        Enforces unique email addresses
        """
        logger.info("Update Profile EP was called")
        abort_if_not_authenticated()
        req = get_validated_request_json(schema=SCHEMA_USER_PROFILE)

        uid = parse_user_identifier(req["user"])

        if not update_user_profile(uid, req):
            logger.info(f"Did not update profile of {uid}")
            abort(400, message="User profile not updated")

        logger.info(f"Updated profile of {uid}")
        return generate_user_profile(uid)


class PasswordEP(Resource):
    def put(self):
        """
        Updates the user's password if it matches the old one and fulfills the password requirements
        """
        logger.info("Change Password EP was called")
        abort_if_not_authenticated()
        req = get_validated_request_json(schema=SCHEMA_UPDATE_PW)
        uid = parse_user_identifier(req["user"])
        new_password = req["new_password"]

        if not self.is_password_strong(new_password):
            error_msg = f"Password was too weak, needs to be at least {PASSWORD_REQ_LEN} and at most {PASSWORD_MAX_LEN} characters long"
            error_msg += " and contain at least 1 capital letter" if PASSWORD_REQ_CAPITAL else ""
            error_msg += " and contain at least 1 lower-case letter" if PASSWORD_REQ_LOWERCASE else ""
            error_msg += " and contain at least 1 numeral" if PASSWORD_REQ_NUMERAL else ""
            error_msg += " and contain at least 1 special character from the set: " + PASSWORD_SPECIAL_CHARACTERS if PASSWORD_REQ_SPECIAL_SYMBOL else ""
            logger.info(f"Too weak password attempt of {uid}")
            abort(400, message="Illegal password - try again")

        if self.try_password_update(uid, new_password, req["old_password"]):
            logger.info(f"Updated password of {uid}")
            return {}, 200
        else:
            logger.info(f"Failed to update password of {uid}")
            abort(500, message="Unable to update the password")

    def is_password_strong(self, password: str) -> bool:
        status = PASSWORD_REQ_LEN <= len(password) <= PASSWORD_MAX_LEN
        if PASSWORD_REQ_CAPITAL:
            status = status and any(c.isupper() for c in password)

        if PASSWORD_REQ_LOWERCASE:
            status = status and any(c.islower() for c in password)

        if PASSWORD_REQ_NUMERAL:
            status = status and any(c.isdigit() for c in password)

        if PASSWORD_REQ_SPECIAL_SYMBOL:
            status = status and any(c for c in password if c in PASSWORD_SPECIAL_CHARACTERS)

        return status

    def try_password_update(self, uid: str, new_password: str, old_password: str) -> bool:
        """
        Tries to update the password of a user by first checking the current password and replacing it with the new one in the case of a match

        :param uid: UID of the user that should have his password changed
        :param new_password: new password in plaintext
        :param old_password: previous password in plaintext
        :return: True iff the update was successful
        :raises Code 401 if the current password does not match (or the user does not exist), Code 500 in the case of a SQL or crypto error
        """
        if check_user(old_password, get_user_credentials_by_uid(uid)) == {}:
            logger.info(f"Current password did not match during update for {uid}")
            abort(401, message="Unauthorized")

        new_password_hash = ""
        try:
            new_password_hash = hashlib.sha1(new_password.encode(INPUT_ENCODING)).hexdigest()
        except ValueError as error:
            logger.error(f"Password hashing failed due to exception: {error} for {uid}")
            abort(500, message=INTERNAL_ERROR_MESSAGE)

        try:
            cursor = cnx.cursor(prepared=True)
            cursor.execute("UPDATE users SET pwd = %s WHERE uid = %s;", (new_password_hash, uid,))
            cnx.commit()
            affected_rows = cursor.rowcount
            cursor.close()
            logger.info(f"Password update was successful: {affected_rows == 1} for {uid}")
            return affected_rows == 1
        except mysql.connector.Error as error:
            cnx.rollback()
            logger.error(f"Password update failed due to exception: {error} for {uid}")
            abort(500, message=INTERNAL_ERROR_MESSAGE)


class Ping(Resource):
    def post(self):
        logger.info("Ping POST EP was called")
        return "Hello world! (POST)"

    def get(self):
        logger.info("Ping GET EP was called")
        return "Hello world! (GET)"


api.add_resource(AuthenticatePwEP, '/auth')
api.add_resource(AuthenticateCertEP, '/auth/cert')
api.add_resource(AuthenticateAdminEP, '/auth/admin')
api.add_resource(ProfileEP, '/profile')
api.add_resource(PasswordEP, '/passwd')
api.add_resource(Ping, '/ping')
