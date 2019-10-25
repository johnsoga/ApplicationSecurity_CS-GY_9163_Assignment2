from flask import render_template, flash, redirect, url_for, request
from app import app, db
from app.forms import LoginForm, RegistrationForm, SpellCheckForm
from flask_login import current_user, login_user, logout_user, login_required
from app.models import User
from werkzeug.urls import url_parse
import subprocess
import os, sys


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
        result = 'success'
        return render_template('index.html', title='Home Page', status=result)
    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
def logout():
    logout_user()
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
        print(output)
        return render_template('spell_check.html', title='Spell Check', user_text=user_text, misspelled=output)
    return render_template('spell_check.html', title='Spell Check', form=form, status=result)
