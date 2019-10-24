from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo, Optional
from app.models import User

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()], id="uname")
    password = PasswordField('Password', validators=[DataRequired()], id="pword")
    auth_2fa = StringField('Two Factor Authentication', validators=[DataRequired()], id="2fa")
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()], id="uname")
    email = StringField('Email', validators=[Email(), Optional()])
    password = PasswordField('Password', validators=[DataRequired()], id="pword")
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    auth_2fa = StringField('Two Factor Authentication', validators=[DataRequired()], id="2fa")
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')
