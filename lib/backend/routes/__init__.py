from flask import (
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from passlib.hash import pbkdf2_sha256

from .. import app
from ..model import Group, Password, User
from ..utils import (
    create_password,
    create_user,
    decrypt_password,
    decrypt_private_key,
    share_to_group,
    share_to_user,
    update_password,
    update_user,
    user_exists,
)


@app.route('/delete_password/<int:password_id>', methods=['POST'])
def delete_password(password_id):
    password = g.session.query(Password).get(password_id)
    user = g.session.query(User).get(session['user_id'])

    if not password or password not in user.passwords:
        flash('Can\'t do that', 'error')
        return redirect(url_for('display_passwords'))

    for password in password.family:
        g.session.delete(password)
    g.session.commit()
    return redirect(url_for('display_passwords'))


@app.route('/edit_password/<int:password_id>', methods=['GET', 'POST'])
def edit_password(password_id):
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
            return redirect(url_for('edit_password', password_id=password_id))

        password = g.session.query(Password).get(password_id)
        update_password(password, password_items)
        g.session.commit()
        return redirect(url_for('display_passwords'))

    encrypted_password = g.session.query(Password).get(password_id)
    password = decrypt_password(encrypted_password, session['private_key'])
    return render_template('edit_password.html', password=password)


@app.route('/share_password_group/<int:password_id>', methods=['GET', 'POST'])
def share_password_group(password_id):
    if request.method == 'POST':
        if request.form:
            current_user = g.session.query(User).get(session['user_id'])
            password = g.session.query(Password).get(password_id)
            group = g.session.query(Group).get(request.form.get('group'))
            passwords_to_add = share_to_group(
                password, group, current_user, session['private_key']
            )
            for password in passwords_to_add:
                g.session.add(Password(**password))
            g.session.commit()
        return redirect(url_for('display_passwords'))

    groups = g.session.query(User).get(session['user_id']).groups
    return render_template('share_password_group.html', groups=groups)


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

        user = g.session.query(User).get(session['user_id'])
        g.session.add(Password(**create_password(user, password_items)))
        g.session.commit()
        return redirect(url_for('display_passwords'))

    return render_template('add_password.html')


@app.route('/display_passwords')
def display_passwords():
    passwords = g.session.query(User).get(session['user_id']).passwords
    decrypted_passwords = {
        password.id: decrypt_password(password, session['private_key'])
        for password in passwords
    }
    return render_template(
        'display_passwords.html', passwords=decrypted_passwords
    )


@app.route('/delete_group/<int:group_id>', methods=['GET', 'POST'])
def delete_group(group_id):
    group = g.session.query(Group).get(group_id)
    if (
        not group
        or g.session.query(User).get(session['user_id']) not in group.users
    ):
        return abort(404)

    if request.method == 'POST':
        g.session.delete(group)
        g.session.commit()
        return redirect(url_for('display_passwords'))

    return render_template('delete_group.html', group=group)


@app.route('/edit_group/<int:group_id>', methods=['GET', 'POST'])
def edit_group(group_id):
    group = g.session.query(Group).get(group_id)
    if group is None:
        return abort(404)

    if request.method == 'POST':
        if not request.form.get('label'):
            flash('Label is required', 'error')
            return redirect(url_for('edit_group', group_id=group_id))

        group.label = request.form.get('label')
        g.session.commit()
        return redirect(url_for('display_groups'))

    return render_template('edit_group.html', group=group)


@app.route('/display_groups')
def display_groups():
    user = g.session.query(User).get(session['user_id'])
    return render_template(
        'display_groups.html', groups=user.groups, owned=user.groups
    )


@app.route('/add_group', methods=['GET', 'POST'])
def add_group():
    if request.method == 'POST':
        if not request.form.get('label'):
            flash('Label is required', 'error')
            return redirect(url_for('add_group'))

        g.session.add(
            Group(
                label=request.form.get('label'),
                users=[g.session.query(User).get(session['user_id'])],
            )
        )
        g.session.commit()
        return redirect(url_for('display_groups'))

    return render_template('add_group.html')


@app.route('/delete_user', methods=['GET', 'POST'])
def delete_user():
    if request.method == 'POST':
        g.session.delete(g.session.query(User).get(session['user_id']))
        g.session.commit()
        return redirect(url_for('logout'))

    return render_template('delete_user.html')


@app.route('/edit_user', methods=['GET', 'POST'])
def edit_user():
    if request.method == 'POST':
        if user_exists(request.form['mail'], g.session.query(User)):
            flash('Mail already used', 'error')
            return redirect(url_for('edit_user'))

        mail = request.form['mail']
        password = request.form['password']
        user = g.session.query(User).get(session['user_id'])
        if password:
            update_user(user, mail, password, session['private_key'])
        else:
            update_user(user, mail, password)
        g.session.commit()
        return redirect(url_for('logout'))

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
        if user_exists(input_mail, g.session.query(User)):
            flash('Mail already used', 'error')
            return redirect(url_for('add_user'))

        g.session.add(User(**create_user(input_mail, input_password)))
        g.session.commit()
        return redirect(url_for('login'))

    return render_template('login_or_add_user.html.jinja2', add_user=True)


@app.route('/add_user_group/<int:group_id>', methods=['GET', 'POST'])
def add_user_group(group_id):
    group = g.session.query(Group).get(group_id)

    if request.method == 'POST':
        input_mail = request.form.get('mail')
        if not input_mail:
            flash('No mail provided', 'error')
            return redirect(url_for('add_user_group'))
        if '@' not in input_mail:
            flash('Mail malformed', 'error')
            return redirect(url_for('add_user_group'))
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
                            password, new_user, group, session['private_key']
                        )
                    )
                )
            g.session.commit()

        return redirect(url_for('display_passwords'))

    return render_template('add_user_group.html')


@app.route('/quit_group/<int:group_id>', methods=['GET', 'POST'])
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


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        input_password = request.form.get('password')
        user = user_exists(request.form.get('login'), g.session.query(User))

        if not user or not pbkdf2_sha256.verify(input_password, user.password):
            flash('Login or password incorrect', 'error')
            return redirect(url_for('login'))

        session['private_key'] = decrypt_private_key(user, input_password)
        session['user_id'] = user.id
        return redirect(url_for('display_passwords'))

    return render_template('login_or_add_user.html.jinja2', login=True)
