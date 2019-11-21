from flask import render_template, flash, redirect, url_for, request, session
from app import app, db
from app.forms import LoginForm, RegistrationForm, SpellCheckForm, LoginHistoryForm, QueryHistoryForm
from flask_login import current_user, login_user, logout_user, login_required, decode_cookie
from app.models import User, UserLogin, UserQuery
from werkzeug.urls import url_parse
from sqlalchemy.sql import func
import subprocess
import os, sys, secrets


@app.route('/index')
@app.route('/')
def index():
    return render_template("index.html", title='Home Page')

@app.route('/login', methods=['GET', 'POST'])
def login():
    result = None

    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            result = 'Invalid username or password'
            return render_template('login.html', title='Sign In', form=form, status=result)
        if user.auth_2fa != form.auth_2fa.data:
            result = 'Two-factor authentication failure'
            return render_template('login.html', title='Sign In', form=form, status=result)
        login_user(user, remember=form.remember_me.data)
        session['user_token'] = secrets.token_urlsafe(32)
        session['username'] = form.username.data
        user_login = UserLogin(user_id=user.id, session_token=session.get('user_token'))
        db.session.add(user_login)
        db.session.commit()
        result = 'success'
        return render_template('index.html', title='Home Page', status=result)
    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
def logout():
    logout_user()
    user = UserLogin.query.filter_by(session_token=session.get('user_token')).first()
    user.time_logout = func.now()
    db.session.commit()
    session.pop('user_token', None)
    session.pop('username', None)
    session.pop('search_as', None)
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    result = None

    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegistrationForm()
    if form.validate_on_submit():
        tmp = User.query.filter_by(username=form.username.data).first()
        if tmp is not None:
            result = 'Failure! Please use a different username.'
            return render_template('register.html', title='Register', form=form, status=result)
        if form.email.data == "":
            email_value=None
        else:
            email_value=form.email.data
        user = User(username=form.username.data, email=email_value, auth_2fa=form.auth_2fa.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        result = 'Success! Congratulations, you are now a registered user!'
        return render_template('register.html', title='Home Page', status=result)
    return render_template('register.html', title='Register', form=form, status=result)

@app.route('/spell_check', methods=['GET', 'POST'])
@login_required
def spell_check():
    result = None

    form = SpellCheckForm()
    if form.validate_on_submit():
        user_text = form.words_to_check.data
        input_file = open('input.txt', 'w')
        input_file.write(user_text)
        input_file.close()
        curr_dir = os.getcwd()
        p1 = subprocess.Popen(['./a.out', 'input.txt','wordlist.txt'], cwd=curr_dir, stdout=subprocess.PIPE)
        out, err = p1.communicate()
        output = out.decode("utf-8").rstrip()
        user_query = UserQuery(user_id=session['user_id'], user_query=user_text, query_result=output)
        db.session.add(user_query)
        db.session.commit()
        return render_template('spell_check.html', title='Spell Check', user_text=user_text, misspelled=output)
    return render_template('spell_check.html', title='Spell Check', form=form, status=result)

@app.route('/history', methods=['GET', 'POST'])
@login_required
def history():
    query_count = UserQuery.query.filter_by(user_id=session['user_id']).count()
    query_result = UserQuery.query.filter_by(user_id=session['user_id']).all()

    username = session.get('username')
    if username == "admin":
        form = QueryHistoryForm()
        if form.validate_on_submit():
            if form.username.data:
                user = User.query.filter_by(username=form.username.data).first()
                user_id = user.id
                session['search_as'] = user_id
            query_result = UserQuery.query.filter_by(user_id=user_id).all()
            query_count = UserQuery.query.filter_by(user_id=user_id).count()
            return render_template('history.html', title='History', query_count=query_count, query_result=query_result)
        return render_template('history.html', title='History', form=form, user="admin", query_count=query_count, query_result=query_result)
    return render_template('history.html', title='History', query_count=query_count, query_result=query_result)

@app.route('/history/query<int:query_id>')
@login_required
def query(query_id):

    user_id=session['user_id']
    if session.get('username') == "admin":
        if session.get('search_as'):
            user_id = session.get('search_as')
            session.pop('search_as', None)

    user = User.query.filter_by(id=user_id).first()
    username = user.username

    if session.get('username') == "admin":
        userQuery = UserQuery.query.filter_by(query_id=query_id).first()
    else:
        userQuery = UserQuery.query.filter_by(user_id=user_id, query_id=query_id).first()

    if userQuery:
        query_request = userQuery.user_query
        query_result = userQuery.query_result
    else:
        err="Permission Denied"
        return render_template('query.html', title='Query', error=err)
    return render_template('query.html', title='Query', query_id=query_id, username=username, query_request=query_request, query_result=query_result)

@app.route('/login_history', methods=['GET', 'POST'])
@login_required
def login_history():
        user = User.query.filter_by(id=session['user_id']).first()
        username = user.username

        if username != "admin":
            return render_template("index.html", title='Home Page')

        form = LoginHistoryForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            user_id = user.id
            query_result = UserLogin.query.filter_by(user_id=user_id).all()
            return render_template('login_history.html', title='Login History', query_result=query_result)
        return render_template('login_history.html', title='Login History', form=form)
