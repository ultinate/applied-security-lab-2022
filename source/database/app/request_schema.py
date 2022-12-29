# Schema of the request
SCHEMA_REQ_OBJECT = """
{
    "type": "object",
    "properties": {
        "api_key": {"type": "string"},
        "request": {"type": "object"
        }
    },
    "additionalProperties": false,
    "required": ["api_key", "request"]
}
"""

SCHEMA_USER_IDENTIFIER = """
{
    "type": "object",
    "properties": {
        "id": {"type": "string"}
    },
    "additionalProperties": false,
    "required": ["id"]
}
"""

SCHEMA_USER_PROFILE = """
    {
        "type": "object",
        "properties": {
            "user": {"type": "object"},
            "lastname": {"type": "string",
                          "minLength": 1,
                          "maxLength": 64,
                          "pattern": "^[a-zA-Z- ]+$"
                            },
            "firstname": {"type": "string",
                          "minLength": 1,
                          "maxLength": 64,
                          "pattern": "^[a-zA-Z- ]+$"
                            },
            "email": {"type": "string",
                      "pattern" : "^[a-z0-9][.a-z0-9-_]*@imovies.ch$",
                      "minLength": 1,
                      "maxLength": 64}
        },
        "additionalProperties": false,
        "required": ["user", "lastname", "firstname"]
    }
    """

SCHEMA_AUTH_REQUEST_PW = """
    {
    "type": "object",
    "properties": {
        "email": {"type": "string",
                   "pattern" : "^[a-z0-9][.a-z0-9-_]*@imovies.ch$",
                   "minLength": 1,
                   "maxLength": 64},
        "password": {"type": "string"}
    },
    "additionalProperties": false,
    "required": ["email", "password"]
    }
"""

SCHEMA_EMAIL_OBJECT = """
{
    "type": "object",
    "properties": {
        "email": {"type": "string",
                  "pattern" : "^[a-z0-9][.a-z0-9-_]*@imovies.ch$",
                   "minLength": 1,
                   "maxLength": 64
                 }
    },
    "additionalProperties": false,
    "required": ["email"]
}
"""

SCHEMA_UPDATE_PW = """
{
    "type": "object",
    "properties": {
        "user": {"type": "object"},
        "old_password": {   "type": "string",
                            "minLength": 1},
        "new_password": {   "type": "string",
                            "minLength": 1}
    },
    "additionalProperties": false,
    "required": ["user", "old_password", "new_password"]
}
"""
