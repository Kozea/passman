from flask import (
    abort, flash, g, redirect, render_template, request, session, url_for)
from flask_alcool import allow_if
from passlib.hash import pbkdf2_sha256

from .. import app
from ..model import Group, Password, User
from ..utils import acl as Is
from ..utils.forms import (
    EditUserForm, GroupForm, PasswordForm, SharePasswordForm, UserForm,
    UserGroupForm)
from ..utils.utils import (
    create_password, create_user, decrypt_password, decrypt_private_key,
    share_to_group, share_to_user, update_password, update_user, user_exists)


@app.route('/delete_password/<int:password_id>', methods=['GET', 'POST'])
@allow_if(Is.connected)
def delete_password(password_id):
    password = g.session.query(Password).get(password_id)
    user = g.session.query(User).get(session['user_id'])

    if request.method == 'POST':
        if not password or password not in user.passwords:
            flash('Can\'t do that', 'error')
            return redirect(url_for('display_passwords'))

        for password in password.family:
            g.session.delete(password)
        g.session.commit()

        return redirect(url_for('display_passwords'))

    return render_template('delete.html.jinja2', password=password)


@app.route('/edit_password/<int:password_id>', methods=['GET', 'POST'])
@allow_if(Is.connected)
def edit_password(password_id):
    form = PasswordForm(request.form or None)

    if request.method == 'POST' and form.validate():
        password_items = {
            'label': request.form.get('label'),
            'login': request.form.get('login'),
            'password': request.form.get('password'),
            'notes': request.form.get('notes'),
        }

        password = g.session.query(Password).get(password_id)
        update_password(password, password_items)
        g.session.commit()
        return redirect(url_for('display_passwords'))

    encrypted_password = g.session.query(Password).get(password_id)
    password = decrypt_password(encrypted_password, session['private_key'])
    for attribute in ('label', 'login', 'password', 'notes'):
        setattr(getattr(form, attribute), 'data', password[attribute])
    return render_template('password.html.jinja2', form=form)


@app.route('/share_password_group/<int:password_id>', methods=['GET', 'POST'])
@allow_if(Is.connected)
def share_password_group(password_id):
    form = SharePasswordForm(request.form or None)

    if request.method == 'POST' and form.validate():
        current_user = g.session.query(User).get(session['user_id'])
        password_to_share = g.session.query(Password).get(password_id)
        for group_id in form.group_ids.data:
            group = g.session.query(Group).get(group_id)
            passwords_to_add = share_to_group(
                password_to_share, group, current_user, session['private_key']
            )
            for password in passwords_to_add:
                g.session.add(Password(**password))
        g.session.commit()
        return redirect(url_for('display_passwords'))

    return render_template('share_password_group.html', form=form)


@app.route('/add_password', methods=['GET', 'POST'])
@allow_if(Is.connected)
def add_password():
    form = PasswordForm(request.form or None)

    if request.method == 'POST' and form.validate():
        password_items = {
            'label': request.form.get('label'),
            'login': request.form.get('login'),
            'password': request.form.get('password'),
            'notes': request.form.get('notes'),
        }

        user = g.session.query(User).get(session['user_id'])
        password = Password(**create_password(user, password_items))
        g.session.add(password)

        if request.form.get('group_id'):
            group = g.session.query(Group).get(request.form.get('group_id'))
            password_to_add = share_to_group(
                password, group, user, session['private_key'])
            for password in password_to_add:
                g.session.add(Password(**password))

        g.session.commit()
        return redirect(url_for('display_passwords'))

    return render_template('password.html.jinja2', form=form)


@app.route('/delete_group/<int:group_id>', methods=['GET', 'POST'])
@allow_if(Is.connected)
def delete_group(group_id):
    group = g.session.query(Group).get(group_id)
    if (not group
            or g.session.query(User).get(session['user_id'])
            not in group.users):
        return abort(404)

    if request.method == 'POST':
        g.session.delete(group)
        g.session.commit()
        return redirect(url_for('display_passwords'))

    return render_template('delete.html.jinja2', group=group)


@app.route('/edit_group/<int:group_id>', methods=['GET', 'POST'])
@allow_if(Is.connected)
def edit_group(group_id):
    group = g.session.query(Group).get(group_id)
    if group is None:
        return abort(404)

    form = GroupForm(request.form or None, obj=group)
    if request.method == 'POST' and form.validate():
        group.label = request.form.get('label')
        g.session.commit()
        return redirect(url_for('display_groups_passwords'))

    return render_template('group.html.jinja2', form=form, edit=True)


@app.route('/add_group', methods=['GET', 'POST'])
@allow_if(Is.connected)
def add_group():
    form = GroupForm(request.form or None)

    if request.method == 'POST' and form.validate():
        group = Group()
        form.populate_obj(group)
        group.users = [g.session.query(User).get(session['user_id'])]
        g.session.add(group)
        g.session.commit()
        return redirect(url_for('display_groups_passwords'))

    return render_template('group.html.jinja2', form=form)


@app.route('/delete_user', methods=['GET', 'POST'])
@allow_if(Is.connected)
def delete_user():
    if request.method == 'POST':
        g.session.delete(g.session.query(User).get(session['user_id']))
        g.session.commit()
        return redirect(url_for('logout'))

    return render_template('delete.html.jinja2', user=True)


@app.route('/edit_user', methods=['GET', 'POST'])
@allow_if(Is.connected)
def edit_user():
    form = EditUserForm(request.form or None)

    if request.method == 'POST' and form.validate():
        if (request.form.get('login') and
                user_exists(request.form.get('login'), g.session.query(User))):
            flash('Mail déjà utilisé', 'error')
            return redirect(url_for('edit_user'))

        mail = request.form.get('login')
        password = request.form.get('password')
        user = g.session.query(User).get(session['user_id'])
        if password:
            update_user(user, mail, password, session['private_key'])
        else:
            update_user(user, mail, password)
        g.session.commit()
        return redirect(url_for('logout'))

    return render_template(
        'login_or_user.html.jinja2', form=form, edit_user=True)


@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    form = UserForm(request.form or None)

    if request.method == 'POST' and form.validate():
        input_mail = request.form.get('login')
        input_password = request.form.get('password')

        if user_exists(input_mail, g.session.query(User)):
            flash('Mail déjà utilisé', 'error')
            return redirect(url_for('add_user'))

        g.session.add(User(**create_user(input_mail, input_password)))
        g.session.commit()
        return redirect(url_for('login'))

    return render_template(
        'login_or_user.html.jinja2', form=form, add_user=True)


@app.route('/add_user_group/<int:group_id>', methods=['GET', 'POST'])
@allow_if(Is.connected)
def add_user_group(group_id):
    group = g.session.query(Group).get(group_id)
    form = UserGroupForm(request.form or None)

    if request.method == 'POST' and form.validate():
        input_mail = request.form.get('mail')
        new_user = user_exists(input_mail, g.session.query(User))
        if new_user:
            group.users.append(new_user)
            group_passwords = (
                g.session.query(Password)
                .filter_by(related_user_id=session['user_id'])
                .filter(Password.groups.contains(group))
            )
            for password in group_passwords:
                g.session.add(
                    Password(
                        **share_to_user(
                            password, new_user, group, session['private_key']))
                )
            g.session.commit()

        return redirect(url_for('display_passwords'))

    return render_template('add_user_group.html', form=form)


@app.route('/quit_group/<int:group_id>', methods=['GET', 'POST'])
@allow_if(Is.connected)
def quit_group(group_id):
    group = g.session.query(Group).get(group_id)

    if request.method == 'POST':
        passwords = (
            g.session.query(Password)
            .filter_by(related_user_id=session['user_id'])
            .filter(Password.groups.contains(group))
        )
        for password in passwords:
            g.session.delete(password)
        group.users.remove(g.session.query(User).get(session['user_id']))
        g.session.commit()

        return redirect(url_for('display_passwords'))

    return render_template('quit_group.html', group=group)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/login', methods=('GET', 'POST'))
def login():
    form = UserForm(request.form or None)

    if request.method == 'POST' and form.validate():
        input_password = request.form.get('password')
        user = user_exists(request.form.get('login'), g.session.query(User))

        if not user or not pbkdf2_sha256.verify(input_password, user.password):
            flash('Identifiant ou mot de passe incorrect', 'error')
            return redirect(url_for('login'))

        session['private_key'] = decrypt_private_key(user, input_password)
        session['user_id'] = user.id
        return redirect(url_for('display_passwords'))

    return render_template('login_or_user.html.jinja2', form=form, login=True)


@app.route('/')
def display_passwords():
    if g.context['user']:
        passwords = g.session.query(User).get(session['user_id']).passwords
        decrypted_passwords = {
            password.id: decrypt_password(password, session['private_key'])
            for password in passwords if not password.groups
        }
        return render_template(
            'display_passwords.html', passwords=decrypted_passwords
        )
    else:
        return redirect(url_for('login'))


@app.route('/display_groups_passwords')
@allow_if(Is.connected)
def display_groups_passwords():
    user = g.session.query(User).get(session['user_id'])
    groups_passwords = {}
    for group in user.groups:
        groups_passwords[group.id] = {
            'label': group.label,
            'passwords': {
                password.id: decrypt_password(password, session['private_key'])
                for password in group.passwords
                if password.related_user_id == session['user_id']
            },
            'total_members': len(group.users),
        }
    return render_template(
        'display_groups_passwords.html', groups_passwords=groups_passwords)
