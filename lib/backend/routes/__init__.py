from flask import redirect, render_template, request, session, url_for

from passlib.hash import pbkdf2_sha256

from .. import app
from ..model import User, Password, db
from ..utils import decrypt_passwords, decrypt_private_key


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


@app.route('/', methods=['GET', 'POST'])
def connection():
    if request.method == 'POST':
        input_password = request.form['password']
        
        users = (
            db.session.query(User)
            .all()
        )

        for user in users:
            if pbkdf2_sha256.verify(request.form['login'], user.login):
                if pbkdf2_sha256.verify(input_password, user.password):
                   break
        else:
            return render_template(
                'error.html', message='Login or password incorrect')

        session['private_key'] = decrypt_private_key(user, input_password)
        session['user_id'] = user.id
        return redirect(url_for('display_passwords'))

    return render_template('connection.html')
