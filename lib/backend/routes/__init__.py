from flask import redirect, render_template, request, session, url_for

from passlib.hash import pbkdf2_sha256

from .. import app
from ..model import User, Password, db
from ..utils import (
    create_password, create_user, encrypt_password, decrypt_password,
    decrypt_passwords, decrypt_private_key, share_to_user, user_exists)


@app.route('/edit_password/<password_id>', methods=['GET', 'POST'])
def edit_password(password_id):
    if request.method == 'POST':
        to_encrypt = {}
        to_encrypt['login'] = request.form.get('login')
        to_encrypt['password'] = request.form.get('password')
        to_encrypt['questions'] = request.form.get('questions')
        label = request.form.get('label')

        if not to_encrypt['login'] or not to_encrypt['password'] or not label:
            return render_template(
                'error.html',
                message='Label, login and password are all required')

        password = db.session.query(Password).get(password_id)
        updated_password = encrypt_password(
            session['user_id'], password.owner_id, to_encrypt, label,
            password.parent_id)
        db.session.query(Password).filter(Password.id == password_id).update(updated_password)
        db.session.commit()
        return redirect(url_for('display_passwords'))

    enc_password = db.session.query(Password).get(password_id)
    password = decrypt_password(enc_password, session['private_key'])
    return render_template('edit_password.html', password=password)


@app.route('/share_password/<password_id>', methods=['GET', 'POST'])
def share_password(password_id):
    if request.method == 'POST':
        share_mail = request.form.get('mail')

        if '@' not in share_mail:
            return render_template('error.html', message='Mail malformed')

        share_user = user_exists(share_mail)

        if not share_user:
            return render_template('error.html', message='Invalid mail')

        current_user = db.session.query(User).get(session['user_id'])
        share_to_user(
            password_id, share_user, current_user, session['private_key'])

        return redirect(url_for('display_passwords'))

    return render_template('share_password.html')


@app.route('/add_password', methods=['GET', 'POST'])
def add_password():
    if request.method == 'POST':
        to_encrypt = {}
        to_encrypt['login'] = request.form.get('login')
        to_encrypt['password'] = request.form.get('password')
        to_encrypt['questions'] = request.form.get('questions')
        label = request.form.get('label')

        if not to_encrypt['login'] or not to_encrypt['password'] or not label:
            return render_template(
                'error.html',
                message='Label, login and password are all required')

        create_password(
            session['user_id'], session['user_id'], to_encrypt, label)

        return redirect(url_for('display_passwords'))

    return render_template('add_password.html')


@app.route('/display_passwords')
def display_passwords():
    passwords = (
        db.session.query(Password)
        .filter(Password.have_access_id == session['user_id'])
        .all()
    )
    
    return render_template(
        'display_passwords.html',
        passwords=decrypt_passwords(passwords, session['private_key']))


@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if request.method == 'POST':
        input_mail = request.form.get('mail')
        input_password = request.form.get('password')

        if not input_mail or not input_password:
            return render_template(
                'error.html', message='No mail or password provided')
        if '@' not in input_mail:
            return render_template('error.html', message='Mail malformed')
        if user_exists(input_mail):
            return render_template('error.html', message='Mail already used')

        create_user(input_mail, input_password)
        return redirect(url_for('connection'))

    return render_template('add_user.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('connection'))


@app.route('/', methods=['GET', 'POST'])
def connection():
    if request.method == 'POST':
        input_password = request.form['password']
        
        user = user_exists(request.form.get('login'))

        if not user or not pbkdf2_sha256.verify(input_password, user.password):
            return render_template(
                'error.html', message='Login or password incorrect')

        session['private_key'] = decrypt_private_key(user, input_password)
        session['user_id'] = user.id
        return redirect(url_for('display_passwords'))

    return render_template('connection.html')
