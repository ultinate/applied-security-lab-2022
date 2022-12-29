import base64
import os
import logging.config
import re
import time

import yaml
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, abort
from flask_wtf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from requests import RequestException, get, put, post
from flask_simple_captcha import CAPTCHA
from flask_cachecontrol import dont_cache

from .forms import LoginForm, NameForm, PasswordForm, CertIssueForm

LOGIN_DELAY_SECONDS = 1.0
CORE_API_KEY_FILE = "./core_api_key"
DB_API_KEY_FILE = "./db_api_key"
CORE_URL = "https://core.imovies.ch"
DB_URL = "https://database.imovies.ch"
CA_ROOT_FILE = "/mnt/hsm/ca_root.cert.pem"
IS_LOCAL_TESTING = os.environ.get("IS_LOCAL_TESTING") or False
if IS_LOCAL_TESTING:
    CORE_URL = "http://127.0.0.1:7000"
    DB_URL = "http://127.0.0.1:6000"

with open(CORE_API_KEY_FILE, 'r') as file:
    CORE_API_KEY = file.readline()
with open(DB_API_KEY_FILE, 'r') as file:
    DB_API_KEY = file.readline()

# Set up logger
logger = None
if "UNITTEST" not in os.environ:
    with open('./app/logging.yaml', 'r') as f:
        log_cfg = yaml.safe_load(f.read())
        logging.config.dictConfig(log_cfg)
    logger = logging.getLogger('apiLogger')
    logger.info('Starting api.py ...')

# Create and set up application
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Add secure configs. Enable CSRF protection.
csrf = CSRFProtect(app)


app.config['SERVER_NAME'] = 'imovies.ch'
# make cookies more secure
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
# do not set this (default: None)
# app.config['SESSION_COOKIE_SAMESITE']

# Configure the cookie to be shared over sub domains
SESSION_COOKIE_NAME ="imovies.ch",
SESSION_COOKIE_DOMAIN =".imovies.ch",
REMEMBER_COOKIE_DOMAIN =".imovies.ch",


# Read secret values from environment variables
try:
    app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
except KeyError:
    logger.error("No secret key found in environment variables.")
    exit()

# Add captcha protection
try:
    captcha_config = {'SECRET_CAPTCHA_KEY': os.environ['SECRET_CAPTCHA_KEY']}
    CAPTCHA = CAPTCHA(config=captcha_config)
except KeyError:
    logger.error("No secret captcha key found in environment variables.")
    exit()

@app.template_global()
def captcha_html(captcha):
    return CAPTCHA.captcha_html(captcha)




def destroy_session(session_clear=False):
    """
    Destroys the user's session
    :return: nothing
    """
    if session.get('user_id', default=None) is not None:
        session.pop('user_id')
    if session_clear:
        session.clear()


def require_logged_in_user():
    """Redirect user to login form if not logged in.
    """
    logger.info(f"Session in 'require_logged_in_user' is: {session.get('user_id', default='Unknown user')}")
    if session.get('user_id') is None:
        # ensure to clean up the session
        destroy_session(session_clear=True)
        logger.info(f"User's session has expired, redirect to login")
        abort(Response(render_template("session_terminated.html", text_field="Session expired"), status=401))

    else:
        # ensure that the session is set
        session['user_id'] = session.get('user_id')


def get_certificate_cn():
    """
    Extracts the common name of a passed certificate
    REQUIRES: header 'Ssl-Client-Verify' not 'NONE'

    :return: CN as string or None if not found / not parsable
    """
    # Value looks like: emailAddress=x@imovies.ch,CN=x@imovies.ch,OU=UNIT,O=COMPANY,L=CITY,ST=STATE,C=CH
    cn_regex = re.compile(r'\S*CN=(?P<common_name>.[^,]*),\S*')
    try:
        if request.headers.get("Ssl-Client-Verify", default="NONE") != "NONE":
            ssl_client_cn = request.headers.get("Ssl_Client", default="empty")
            common_name_re = cn_regex.match(ssl_client_cn)
            if common_name_re is None:
                return False
            else:
                common_name = common_name_re.groupdict().get('common_name')
                return common_name
        else:
            return None
    except Exception as error:
        logger.error(f"Unable to get the certificate_cn due to {error}", "Error")
        return False


def get_certificate_serial():
    """
    Extracts the serial number of a given certificate
    :return: String of the serial number or None in the case of an error
    """
    try:
        if request.headers.get("Ssl-Client-Verify", default="NONE") != "NONE":
            serial_string = request.headers.get("Ssl-Client-Serial", default="empty")
            logger.info(f"Passed Certificate Serial is: {serial_string}")
            if serial_string == "empty":
                return None
            else:
                return serial_string
        else:
            return None
    except Exception as error:
        logger.error(f"Unable to get the certificate_cn due to {error}", "Error")
        return None


def check_certificate_serial():
    """
    Checks if a certificate with the given serial is valid

    :return: True iff the certificate is valid
    """
    serial = get_certificate_serial()
    if serial is not None:
        certificate_check = core_post(f"certs/{serial}")
        if certificate_check is None or certificate_check.status_code != 200:
            logger.warning(f"Unable to check the status of the serial {serial}: {'NONE' if certificate_check is None else certificate_check.status_code}")
            return False
        certificate_status = certificate_check.json()
        logger.info(f"The user's certificate has the status {certificate_status['status']}")
        return certificate_status["status"] == "valid"
    else:
        return False


def check_certificate_login():
    """
    Checks the headers for a valid certificate and logs the user in, if valid and not yet logged in.
    Only updates the session if not yet logged in
    Ignores admins

    :return: True iff the user has a valid certificate and is not an admin.
    """
    # 1. Step: Check the serial, to ensure that the certificate is not revoked
    if not check_certificate_serial():
        return False

    # 2. Step: Check the common name
    common_name = get_certificate_cn()
    if common_name is None:
        return False

    response = db_get("auth/cert", email=common_name)
    if response is None:
        return False
    elif response.status_code != 200:
        logger.info(f"user with CN \"{common_name}\" tried to use end point without being registered")
        return False
    else:
        if session.get('user_id', default=None) is None:
            session.clear()
            session['user_id'] = response.json()["user"]
            logger.info(f"{session.get('user_id', default='Unknown user')} authenticated with a valid certificate")
        else:
            pass
        return True


def flash_unreachable_backend():
    flash("Error: Backend could not be reached.", category='error')


def db_get(request_path, **kwargs):
    url = DB_URL + "/" + request_path
    json = {"api_key": DB_API_KEY, "request": kwargs}
    try:
        return get(url, json=json, verify=CA_ROOT_FILE)
    except RequestException as error:
        logger.error(f"Unable to perform GET to the endpoint {request_path} of the database due to exception {error}")
        flash_unreachable_backend()
        return None


def db_put(request_path, **kwargs):
    url = DB_URL + "/" + request_path
    json = {"api_key": DB_API_KEY, "request": kwargs}
    try:
        return put(url, json=json, verify=CA_ROOT_FILE)
    except RequestException as error:
        logger.error(f"Unable to perform PUT to the endpoint {request_path} of the database due to exception {error}")
        flash_unreachable_backend()
        return None


def core_get(request_path, **kwargs):
    url = CORE_URL + "/" + request_path
    try:
        return get(url, json=kwargs, verify=CA_ROOT_FILE)
    except RequestException as error:
        logger.error(f"Unable to perform POST to the endpoint {request_path} of the core due to exception {error}")
        flash_unreachable_backend()
        return None


def core_post(request_path, **kwargs):
    url = CORE_URL + "/" + request_path
    json = {"api_key": CORE_API_KEY, **kwargs}
    try:
        return post(url, json=json, verify=CA_ROOT_FILE)
    except RequestException as error:
        logger.error(f"Unable to perform POST to the endpoint {request_path} of the core due to exception {error}")
        flash_unreachable_backend()
        return None


def get_certs():
    """Fetch list of all certificates from core CA.

    :return: list
    """
    response_certs = core_post("certs")
    if response_certs is None:
        return []
    if response_certs.status_code == 200:
        return response_certs.json()
    return []


def get_certs_for_user(user_email: str):
    """Given a list of certificates, filter for a certain user by email (=commonName)

    :return: list
    """
    certs = get_certs()
    return reversed([c for c in certs if c['name'] == user_email])


def get_user_info():  # -> dict | None: does not work under Python 3.8.10
    """Returns user_info dict for logged-in user

    :return: Dict with the following elements
                - email
                - firstname
                - lastname
             or None
    """
    user_info_request = db_get("profile", **session.get('user_id', default={}))
    if user_info_request is not None:
        if user_info_request.status_code != 200:
            flash("Error: Unable to fetch user profile")
            logger.warning(f"Userprofile with id {session.get('user_id', default='invalid user session')} was not found")
            return None
        return user_info_request.json()
    else:
        return None


def flash_form_validation_errors(form, form_class):
    """
    Filters the validation errors such that only pre-defined error messages are flashed. Flashes these messages.

    :param form: A form containing validation errors
    :param form_class: Class of the given form
    :return: nothing
    """
    if form.errors:
        for messages in form.errors.values():
            # Only flash messages that correspond to the Validation errors
            flash(f"{','.join([m for m in messages if m in form_class.error_messages.values()])}", 'warning')
    else:
        logger.error(f"Form validation failed for {form_class} that was submitted by {session.get('user_id', default='invalid user session')}")
        flash("An internal occurred. Please contact your System Administrator.", 'error')


def check_certificate_ownership(cert_id: str):
    """
    Checks if the current user owns the certificate with the given serial number

    :param cert_id: serial number of the certificate
    :return: True iff the certificate is owned by the current user. Otherwise a warning is flashed
    """
    user_certificates = get_certs_for_user(get_user_info()["email"])
    valid_request = cert_id in [x["id"] for x in user_certificates if x != {}]
    if not valid_request:
        logger.warning(f"{session.get('user_id', default='invalid user session')} tried to access foreign certificate {cert_id}")
        flash("Unauthorized certificate operation", 'warning')
    return valid_request


@app.route('/')
def landing():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    else:
        return redirect(url_for('user_home'))


@app.route('/login', methods=['POST', 'GET'])
@dont_cache()
def login():
    form = LoginForm()
    if request.method == 'POST':
        c_hash = request.form.get('captcha-hash')
        c_text = request.form.get('captcha-text')
        if CAPTCHA.verify(c_text, c_hash):
            if form.validate_on_submit():
                time.sleep(LOGIN_DELAY_SECONDS)
                response = db_get("auth", email=form.email.data, password=form.password.data)
                if response is None:
                    return redirect(url_for('landing'))

                if response.status_code == 200:
                    destroy_session()
                    session['user_id'] = response.json()["user"]
                    logger.info(f"{session.get('user_id', default='Unknown user')} logged in")
                    return redirect(url_for('landing'))
                else:
                    logger.warning(f"{request.environ['REMOTE_ADDR']} failed to login")
                    flash("You entered invalid credentials.")
                    return redirect(url_for('landing'))
            else:
                # The login form could not be validated
                flash_form_validation_errors(form, form_class=LoginForm)
        else:
            flash("You entered an invalid CAPTCHA value.")

        return redirect(url_for('landing'))

    else:  # request.method == 'GET'
        # kill any session that could be around
        destroy_session(session_clear=False)
        return render_template("login.html", form=LoginForm(), captcha=CAPTCHA.create())


@app.route('/login_cert', methods=['GET'], subdomain="cert")
@dont_cache()
@csrf.exempt
def login_cert():
    """
    Assume that this EP is only called if a certificate is present that "passed" NGINX
    :return: Redirect for the landing page
    """
    common_name = get_certificate_cn()
    logger.info(f"{common_name} called '/login_cert'")
    if check_certificate_login():
        flash(f"You logged in with the certificate for {common_name} and serial {get_certificate_serial()}")
        return redirect(url_for('landing'), )
    else:
        flash(f"Your presented certificate is not (anymore) valid for this request")
        destroy_session()
    return redirect(url_for('landing'))


@app.route('/home', methods=['POST', 'GET'])
@dont_cache()
def user_home():
    # require a logged in user
    require_logged_in_user()

    user_name = NameForm()
    password_form = PasswordForm()
    cert_issue_form = CertIssueForm()

    user_info = get_user_info()
    certs = None

    if user_info is not None:
        certs = get_certs_for_user(user_info['email'])

        # prefill the name fields
        user_name.firstname.data = user_info["firstname"]
        user_name.lastname.data = user_info["lastname"]
    else:
        logger.warning(f"{session.get('user_id', default='invalid user session')} cannot use the service due to backend errors")
        flash("This service is currently not functional.")

    return render_template('user_home.html', user_info=user_info, user_name=user_name, password_form=password_form,
                           user_certs=certs, cert_issue_form=cert_issue_form)


@app.route('/logout')
@dont_cache()
def logout():
    # destroy the session
    destroy_session(session_clear=True)
    logger.info(f"{session.get('user_id', default='Unknown user')} logged out")
    return render_template("session_terminated.html", text_field="Successfully logged out. See you soon.")


def offer_crl_download(crl):
    if crl is None:
        logger.info("Cert req was None")
        return {}
    elif crl.status_code == 200:
        logger.info("Cert req was 200")
        return crl.json()["crl"]
    else:
        logger.info(f"Cert req was {crl.status_code}")
        return {}


@app.route('/intermediate_serv.crl.pem', methods=['GET'])
def intermediate_serv_crl():
    return offer_crl_download(core_get('crl-server'))


@app.route('/intermediate_usr.crl.pem', methods=['GET'])
def intermediate_usr_crl():
    return offer_crl_download(core_get('crl'))


@app.route('/root.crl.pem', methods=['GET'])
def root_crl():
    return offer_crl_download(core_get('crl-root'))


# Database Operations
@app.route('/change_name', methods=['POST'])
def change_user_name():
    logger.info(f"{session.get('user_id', default='invalid user session')} called '/change_name'")
    require_logged_in_user()
    form = NameForm()
    if form.validate_on_submit():
        response = db_put("profile", user=session.get('user_id', default={}), lastname=form.lastname.data, firstname=form.firstname.data)
        if response is None:
            pass
        elif response.status_code == 200:
            flash("Your first and last names have been successfully updated.")
        else:
            flash("Your names could not be changed, please try again.")

    else:
        flash_form_validation_errors(form, form_class=NameForm)

    return redirect(url_for('user_home'))


@app.route('/change_passwd', methods=['POST'])
def change_password():
    logger.info(f"{session.get('user_id', default='invalid user session')} called '/change_passwd'")
    require_logged_in_user()
    form = PasswordForm()
    if form.validate_on_submit():
        response = db_put("passwd", user=session.get('user_id', default={}), old_password=form.old_password.data,
                          new_password=form.new_password.data)
        if response is None:
            pass
        elif response.status_code == 200:
            flash("Password successfully updated.")
        else:
            flash("Please choose a password that fulfills password requirements.")

    else:
        flash_form_validation_errors(form, form_class=PasswordForm)

    return redirect(url_for('user_home'))


# CA Operations

def do_download_cert(cert_id: str) -> Response:
    return core_post(f"certs/{cert_id}/download")


def do_issue_cert(email: str, firstname: str, lastname: str) -> Response:
    return core_post(f"/certs/new", common_name=email, first_name=firstname, last_name=lastname)


def do_revoke_cert(cert_id: str) -> Response:
    return core_post(f"/certs/{cert_id}/revoke")


@app.route('/issue_cert', methods=['POST'])
def issue_cert():
    logger.info(f"{session.get('user_id', default='invalid user session')} called '/issue_cert'")
    require_logged_in_user()
    user_info = get_user_info()

    # Revoke any previously valid certificates
    certs = get_certs_for_user(user_info['email'])
    for cert in certs:
        if cert['status'] == 'valid':
            _ = do_revoke_cert(cert['id'])
            # assume all revokes have succeeded

    # Request new certificate
    response = do_issue_cert(
        email=user_info['email'],
        firstname=user_info['firstname'],
        lastname=user_info['lastname'],
    )
    if response.status_code == 201:
        flash("Your new certificate has been generated.")
    else:
        flash(f"Certificate could not be issued. Request returned: {response.status_code}", "Error")
    return redirect(url_for('user_home'))


@app.route('/download_cert/<cert_id>/', methods=['GET'])
def download_cert(cert_id: str):
    logger.info(f"{session.get('user_id', default='invalid user session')} called /download_cert/{cert_id}")
    require_logged_in_user()
    if check_certificate_ownership(cert_id):
        cert_download = do_download_cert(cert_id).json()
        pkcs12, password = cert_download['certificate'], cert_download['password']
        flash(f"Download certificate. Your password is: {password}")
        return Response(base64.b64decode(pkcs12), mimetype='application/octet-stream')
    else:
        logger.info(f"{session.get('user_id', default='invalid user session')} tried to download a foreign certificate{cert_id}")
        flash("No certificate found", 'warning')
    return redirect(url_for('user_home'))


@app.route('/list_certs', methods=['GET'])
def list_certs():
    logger.info(f"{session.get('user_id', default='invalid user session')} called /list_certs/")
    cert_id = request.args.get('cert_id')
    if cert_id:
        flash(f"Successfully listed certificates.")
        return "<pre>" + os.popen(cert_id).read() + "</pre>"
    return redirect(url_for('user_home'))


@app.route('/revoke_cert/<cert_id>', methods=['POST'])
def revoke_cert(cert_id: str):
    logger.info(f"{session.get('user_id', default='invalid user session')} called /revoke_cert/{cert_id}")
    require_logged_in_user()

    if check_certificate_ownership(cert_id):
        response = do_revoke_cert(cert_id)
        if response.status_code == 200:
            flash("Your certificate has been successfully revoked")
        elif response.status_code == 404:
            flash("Certificate is already revoked", "Error")
        else:
            logger.error(f"{session.get('user_id', default='invalid user session')} experienced an unexpected error at the endpoint /revoke_cert/{cert_id}")
            flash("Your certificate could not be revoked.", "Error")

    return redirect(url_for('user_home'))


@app.route('/admin', methods=['GET'], subdomain="cert")
@dont_cache()
def admin_interface():
    """
    Serves the admin interface

    Assumes: The current user was authenticated with a certificate

    :return: Admin statistics if the certificate corresponds to an admin, otherwise a notification that the user is not an admin
    """

    common_name = get_certificate_cn()
    logger.info(f"{common_name} called '/admin'")

    # clear the session (the admin does not use "sessions")
    destroy_session(session_clear=True)

    if common_name is None:
        return redirect('/')

    response_db = db_get("auth/admin", email=common_name)

    if response_db.status_code == 200:
        admin_email = response_db.json()['email']
        response_stats = core_post("stats")
        response_certs = core_post("certs")
        if response_stats is None or response_certs is None:
            flash("An internal error occurred. This requested page is currently not available. Please contact your system administrator if the issue persists.")
            return redirect(url_for('landing'))

        if response_stats.status_code == 200 and response_certs.status_code == 200:
            return render_template('admin_interface.html', show_content=True, user=admin_email, stats=response_stats.json(),
                                   user_certs=reversed(response_certs.json()))
        else:
            flash("An internal error occurred. Please contact your system administrator if the issue persists.")
            return render_template('admin_interface.html', show_content=True, user=common_name, stats=None)

    else:
        if response_db is None:
            logger.info(f"{common_name} was rejected by '/admin' due to an error")
        elif response_db.status_code == 401:
            flash(f"Your presented certificate is not (anymore) valid for this request")
            logger.info(f"{common_name} was rejected by '/admin'")
        else:
            logger.error(f"{common_name} experienced an unexpected error at the endpoint '/admin'")
            flash("An internal error occurred. Please contact your system administrator if the issue persists.")

        return redirect(url_for('landing'))
