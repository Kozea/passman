from flask import (
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from passlib.hash import pbkdf2_sha256

from .. import app
from ..model import Group, Password, User, db
from ..utils import (
    create_group,
    create_password,
    create_user,
    decrypt_password,
    decrypt_passwords,
    decrypt_private_key,
    remove_group,
    remove_password,
    share_to_groups,
    update_group,
    update_password,
    update_user,
    user_exists,
)


@app.route('/delete_password/<int:password_id>', methods=['POST'])
def delete_password(password_id):
    password = db.session.query(Password).get(password_id)

    if not password or password.owner_id != session['user_id']:
        flash('Can\'t do that', 'error')
        return redirect(url_for('display_passwords'))

    remove_password(password, commit=True)
    return redirect(url_for('display_passwords'))


@app.route('/edit_password/<int:password_id>', methods=['GET', 'POST'])
def edit_password(password_id):
    if request.method == 'POST':
        to_encrypt = {
            'login': request.form.get('login'),
            'password': request.form.get('password'),
            'questions': request.form.get('questions'),
        }
        label = request.form.get('label')

        if not to_encrypt['login'] or not to_encrypt['password'] or not label:
            flash('Label, login and password are all required', 'error')
            return redirect(url_for('edit_password', password_id=password_id))

        password = db.session.query(Password).get(password_id)
        update_password(password, label, to_encrypt)
        return redirect(url_for('display_passwords'))

    encrypted_password = db.session.query(Password).get(password_id)
    password = decrypt_password(encrypted_password, session['private_key'])
    return render_template('edit_password.html', password=password)


@app.route('/share_password_groups/<int:password_id>', methods=['GET', 'POST'])
def share_password_groups(password_id, group_id=None):
    if request.method == 'POST':
        if request.form:
            current_user = db.session.query(User).get(session['user_id'])
            password = db.session.query(Password).get(password_id)
            groups = [
                db.session.query(Group).get(group_id)
                for group_id in request.form
            ]
            share_to_groups(
                password, groups, current_user, session['private_key']
            )
        return redirect(url_for('display_passwords'))

    groups = db.session.query(User).get(session['user_id']).groups
    return render_template('share_password_groups.html', groups=groups)


@app.route('/add_password', methods=['GET', 'POST'])
def add_password():
    if request.method == 'POST':
        password_items = {
            'label': request.form.get('label'),
            'login': request.form.get('login'),
            'password': request.form.get('password'),
            'notes': request.form.get('notes'),
        }

        if not (
            password_items['login']
            or not password_items['password']
            or not password_items['label']
        ):
            flash('Label, login and password are all required', 'error')
            return redirect(url_for('add_password'))

        user = db.session.query(User).get(session['user_id'])
        db.session.add(Password(**create_password(user, password_items)))
        db.session.commit()
        return redirect(url_for('display_passwords'))

    return render_template('add_password.html')


@app.route('/display_passwords')
def display_passwords():
    passwords = (
        db.session.query(User).get(session['user_id']).passwords_related
    )
    return render_template(
        'display_passwords.html',
        passwords=decrypt_passwords(passwords, session['private_key']),
    )


@app.route('/delete_group/<int:group_id>', methods=['GET', 'POST'])
def delete_group(group_id):
    group = db.session.query(Group).get(group_id)
    if not group or group.owner_id != session['user_id']:
        return abort(404)

    if request.method == 'POST':
        remove_group(group)
        return redirect(url_for('display_passwords'))

    return render_template('delete_group.html', group=group)


@app.route('/edit_group/<int:group_id>', methods=['GET', 'POST'])
def edit_group(group_id):
    group = db.session.query(Group).get(group_id)
    if group is None:
        return abort(404)

    if request.method == 'POST':
        if not request.form.get('label'):
            flash('Label is required', 'error')
            return redirect(url_for('edit_group', group_id=group_id))

        update_group(group, request.form['label'])
        db.session.commit()
        return redirect(url_for('display_groups'))

    return render_template('edit_group.html', group=group)


@app.route('/display_groups')
def display_groups():
    user = db.session.query(User).get(session['user_id'])
    return render_template(
        'display_groups.html', groups=user.groups, owned=user.groups_owned
    )


@app.route('/add_group', methods=['GET', 'POST'])
def add_group():
    if request.method == 'POST':
        if not request.form.get('label'):
            flash('Label is required', 'error')
            return redirect(url_for('add_group'))

        group = create_group(
            db.session.query(User).get(session['user_id']),
            request.form['label'],
        )
        db.session.add(group)
        db.session.commit()
        return redirect(url_for('display_groups'))

    return render_template('add_group.html')


@app.route('/edit_user', methods=['GET', 'POST'])
def edit_user():
    if request.method == 'POST':
        if user_exists(request.form['mail']):
            flash('Mail already used', 'error')
            return redirect(url_for('edit_user'))

        mail = request.form['mail']
        password = request.form['password']
        user = db.session.query(User).get(session['user_id'])
        if password:
            update_user(user, mail, password, session['private_key'])
        else:
            update_user(user, mail, password)
        return redirect(url_for('display_passwords'))

    return render_template('edit_user.html')


@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if request.method == 'POST':
        input_mail = request.form.get('mail')
        input_password = request.form.get('password')

        if not input_mail or not input_password:
            flash('No mail or password provided', 'error')
            return redirect(url_for('add_user'))
        if '@' not in input_mail:
            flash('Mail malformed', 'error')
            return redirect(url_for('add_user'))
        if user_exists(input_mail, db.session.query(User)):
            flash('Mail already used', 'error')
            return redirect(url_for('add_user'))

        db.session.add(User(**create_user(input_mail, input_password)))
        db.session.commit()
        return redirect(url_for('connect'))

    return render_template('add_user.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('connect'))


@app.route('/', methods=['GET', 'POST'])
def connect():
    if request.method == 'POST':
        input_password = request.form['password']
        user = user_exists(request.form.get('login'), db.session.query(User))

        if not user or not pbkdf2_sha256.verify(input_password, user.password):
            flash('Login or password incorrect', 'error')
            return redirect(url_for('connect'))

        session['private_key'] = decrypt_private_key(user, input_password)
        session['user_id'] = user.id
        return redirect(url_for('display_passwords'))

    return render_template('connection.html')
