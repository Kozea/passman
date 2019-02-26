from flask import redirect, render_template, request, session, url_for

from base64 import b64decode
from passlib.hash import pbkdf2_sha256
from Crypto.Hash import SHA256
from Crypto.Cipher import ChaCha20
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

from .. import app
from ..model import User, Group, UserGroup, GroupRequest, Password, db

@app.route('/display_password')
def display_password():
    passwords = (
        db.session.query(Password)
        .filter(Password.have_access_id == session['user_id'])
        .all()
    )

    pv_key = RSA.import_key(session['private_key'])
    cipher_rsa = PKCS1_OAEP.new(pv_key)

    for password in passwords:
        session_key = cipher_rsa.decrypt(b64decode(password.session_key))

        nonce = b64decode(password.login_nonce)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        tag = b64decode(password.login_tag)
        login_dc = cipher_aes.decrypt_and_verify(b64decode(password.login), tag)

        nonce = b64decode(password.password_nonce)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        tag = b64decode(password.password_tag)
        password_dc = cipher_aes.decrypt_and_verify(b64decode(password.password), tag)

        nonce = b64decode(password.questions_nonce)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        tag = b64decode(password.questions_tag)
        questions_dc = cipher_aes.decrypt_and_verify(b64decode(password.questions), tag)

        print(login_dc)
        print(password_dc)
        print(questions_dc)


@app.route('/', methods=['GET', 'POST'])
def connection():
    if request.method == 'POST':
        pwd = request.form['password']
        pwd_enc = pbkdf2_sha256.hash(request.form['password'])
        
        users = (
            db.session.query(User)
            .all()
        )

        for user in users:
            if pbkdf2_sha256.verify(request.form['login'], user.mail):
                break
        else:
            user = None

        to_decode = b64decode(user.private_key)
        nonce = b64decode(user.nonce)
        hash_object = SHA256.new(data=pwd.encode('utf-8'))
        cipher = ChaCha20.new(key=hash_object.digest(), nonce=nonce)
        private_key = cipher.decrypt(to_decode)

        session['private_key'] = private_key
        session['user_id'] = user.id
        return redirect(url_for('display_password'))

    return render_template('connection.html')
