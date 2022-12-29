from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, EqualTo, Length, Regexp


class LoginForm(FlaskForm):
    error_messages = {"email_regex": "Unexpected email format",
                      "email_length": "Email too long"}
    email = StringField('email', validators=[DataRequired(),
                                             Regexp('^[a-z0-9][.a-z0-9-_]*@imovies.ch$', message=error_messages["email_regex"]),
                                             Length(min=6, max=64, message=error_messages["email_regex"])])
    password = PasswordField('password', validators=[DataRequired()])


class NameForm(FlaskForm):
    error_messages = {"firstname_regex": "Firstname must contain only letters, spaces and hyphens",
                      "firstname_length": "The firstname needs to be at least 1 character long and at most 64 characters long",
                      "lastname_regex": "Lastname must contain only letters, spaces and hyphens",
                      "lastname_length": "The firstname needs to be at least 1 character long and at most 64 characters long"}
    firstname = StringField('first name', validators=[DataRequired(),
                                                      Regexp('^[a-zA-Z- ]+$', message=error_messages["firstname_regex"]),
                                                      Length(min=1, max=64, message=error_messages["firstname_length"])])
    lastname = StringField('last name', validators=[DataRequired(),
                                                    Regexp('^[a-zA-Z- ]+$', message=error_messages["lastname_regex"]),
                                                    Length(min=1, max=64, message=error_messages["lastname_length"])])


class CertIssueForm(FlaskForm):
    pass


class PasswordForm(FlaskForm):
    error_messages = {"repeat_password": "Passwords must match"}
    old_password = PasswordField('Current password', validators=[DataRequired()])
    new_password = PasswordField('New password', validators=[DataRequired()])
    new_password_confirm = PasswordField('Repeat the new password', validators=[DataRequired(), EqualTo('new_password', message=error_messages["repeat_password"])])
