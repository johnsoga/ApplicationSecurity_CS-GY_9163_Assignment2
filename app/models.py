from datetime import datetime
from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app import login
from sqlalchemy.sql import func


class User(UserMixin, db.Model):

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True, nullable=True)
    auth_2fa = db.Column(db.String(10), index=True)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User {}>'.format(self.username)

class UserLogin(UserMixin, db.Model):

    __tablename__ = 'login'

    login_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.ForeignKey('users.id'), nullable=False)
    time_login = db.Column(db.DateTime, nullable=False, server_default=func.now())
    time_logout = db.Column(db.DateTime, nullable=True)
    session_token = db.Column(db.String(32))

class UserQuery(UserMixin, db.Model):

    __tablename__ = 'user_queries'

    query_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.ForeignKey('users.id'), nullable=False)
    user_query = db.Column(db.Text)
    query_result = db.Column(db.Text)


@login.user_loader
def load_user(id):
    return User.query.get(int(id))

db.create_all()
