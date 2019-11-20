from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo, Optional, Length
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
    auth_2fa = StringField('Two Factor Authentication', validators=[DataRequired()], id="2fa")
    submit = SubmitField('Register')

class SpellCheckForm(FlaskForm):
    words_to_check = TextAreaField('Words To Check', validators=[Optional(), Length(max=200)], id="inputtext")
    submit = SubmitField('Spell Check')

class LoginHistoryForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()], id="userid")
    submit = SubmitField('Search')
