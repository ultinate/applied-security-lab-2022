# Database

## Overview

## TODO

The following tasks remain to be solved:

- [ ]  Enable mTLS
- [ ]  Add backup e.g. `mysqldump -u backup -ppassword imovies --no-tablespaces  > ./backup.sql`
- [ ]  Modify credentials of DB user, run privileges etc [see here](https://dev.mysql.com/doc/mysql-secure-deployment-guide/5.7/en/secure-deployment-post-install.html)
- [ ]  Add the system description
- [ ]  Add logging
- [ ]  Remove the testing options

## Documentation

### API Endpoints

This section describes the API for the Database Service that is offered to the Frontend Application.
Data format is 'JSON', the default content-type is `application/json`.

The API authenticates users and manages user data.

### Security

All requests to API endpoints (except for `/ping`) must contain a `request_object` that contains the field `api_key` and the field `request`.
E.g.

```json
{
  "api_key": "123",
  "request": ""
}
```

The user identifier `uid` is encrypted along with a timestamp of the token's creation to hide which user is used. This is disabled, if `DEBUG_MODE_UID` is set to True.

### Assumptions

The following assumptions are made:

- The certificate of the admin is issued for the email address `admin_ca@imovies.ch`.  (hardcoded in [db_additional_setup.sql](./data/db_additional_setup.sql)) The administrator is not a user.
- The nginx server accepts only valid certificates if the certificate based authentication is used
- The endpoint `/auth/cert` and `/auth/admin` are only called if the user was authenticated with a valid certificate and the corresponding email is taken out of the certificate
- Email addresses are unique and are not changed

### API Endpoints

* `/auth`: GET, authenticates a user with username and password `auth_request_pw` and returns the `user_profile` of the user.
* `/auth/cert`: GET, obtains the `user_profile` of a user based on the supplied `email_object` object. Assumes: The corresponding email address was taken out of the certificate with which the user was authenticated.
* `/auth/admin`: GET, authenticates an admin with an `email_object` object.
* `/profile`: GET with an `identifier_object` to access the user's profile `user_profile` or PUT using a `user_profile` object to update the profile. Returns the profile as `user_profile`.
* `/passwd`: PUT to change the password using `update_pw`. Returns empty on success.
* `/ping`: POST or GET to check if the service is alive

### Data Objects

All data objects are JSON representation of a number of fields.

`request_object`:

* `api_key`: A shared value between the client and server to authenticate the client.
* `request`: The json object of the request.

Example:

```json
{
  "api_key": "123",
  "request": ""
}
```

`identifier_object`:

* `id`: User identifier in an encrypted form. [Required]

Example:

```json
{
  "id": "e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4"
}
```

`user_profile`:

* `user`: `identifier_object`
* `lastname`: user's lastname
* `firstname`: user's firstname
* `email`: user's email [optional] Expected format: "^[a-z0-9][.a-z0-9-_]*@imovies.ch$"

Example:

```json
{
  "user": {
    "id": "e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4"
  },
  "lastname": "Muster",
  "firstname": "Hans",
  "email": "hans.muster@imovies.ch"
}
```

`auth_request_pw`:

* `email`: user's email address. Expected format: "^[a-z0-9][.a-z0-9-_]*@imovies.ch$"
* `password`: user's password

Example:

```json
{
  "email": "hans.muster@imovies.ch",
  "password": "abcdefg"
}
```

`email_object`:

* `email`: user's email address. Expected format: "^[a-z0-9][.a-z0-9-_]*@imovies.ch$"

Example:

```json
{
  "email": "hans.muster@imovies.ch"
}
```

`update_pw`:

* `uid`: `identifier_object`
* `old_password`: The current password
* `new_password`: The current password

Example:

```json
{
  "user": {
    "id": "e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4"
  },
  "old_password": "....",
  "new_password": "...."
}


```

### Example requests

This section contains a set of request samples to demonstrate the expected formats.

#### Authentication based on email and password

```bash
curl --request GET \
  --url http://127.0.0.1:5000/auth \
  --header 'Content-Type: application/json' \
  --data '{
	"api_key" : "fc4b5fd6816f75a7c81fc8eaa9499d6",
	"request" : { "email": "lb@imovies.ch", "password": "D15Licz6" }
}'
```

#### Authentication based on a certificate

```bash
curl --request GET \
  --url http://127.0.0.1:5000/auth/cert \
  --header 'Content-Type: application/json' \
  --data '{
	"api_key" : "fc4b5fd6816f75a7c81fc8eaa9499d6",
	"request" : { "email": "ps@imovies.ch"}
}'
```

#### Check if a user is an admin

```bash
curl --request GET \
  --url http://127.0.0.1:5000/auth/admin \
  --header 'Content-Type: application/json' \
  --data '{
	"api_key" : "fc4b5fd6816f75a7c81fc8eaa9499d6",
	"request" : { "email": "admin_ca@imovies.ch"}
}'
```

#### Get the user profile

```bash
curl --request GET \
  --url http://127.0.0.1:5000/profile \
  --header 'Content-Type: application/json' \
  --data '{
	"api_key" : "fc4b5fd6816f75a7c81fc8eaa9499d6",
	"request" : { "id": "lb_new"}
}'
```

#### Update the user profile

```bash
curl --request PUT \
  --url http://127.0.0.1:5000/profile \
  --header 'Content-Type: application/json' \
  --data '{
	"api_key" : "fc4b5fd6816f75a7c81fc8eaa9499d6",
	"request" : { "user": {"id": "lb_new"},  
				  "lastname": "Muster", 
				  "firstname": "Hans" , 
				  "email": "lb2@imovies.ch" 
				}
}'
```

#### Update the password

```bash
curl --request PUT \
  --url http://127.0.0.1:5000/passwd \
  --header 'Content-Type: application/json' \
  --data '{
	"api_key" : "fc4b5fd6816f75a7c81fc8eaa9499d6",
	"request" : { "user": {"id": "lb_new"},
				  "old_password": "D15Licz6",
				  "new_password": "SPeCIAl340!is" 
			    }
}'
```



