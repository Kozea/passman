from .utils import login, logout
from ..backend.model import Password


def test_login_logout(http):
    response = http.get('/', follow_redirects=True)
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert '<form' in page_data

    login(http, 'test')
    response = http.get('/', follow_redirects=True)
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert '<form' not in page_data

    logout(http)

    response = http.get('/', follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert '<form' in page_data


def test_display_passwords(http):
    response = http.get('/', follow_redirects=True)
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert '<form' in page_data

    login(http, 'test')
    response = http.get('/', follow_redirects=True)
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert 'one super password' in page_data
    assert 'question' in page_data


def test_display_groups(http):
    response = http.get('/display_groups_passwords')
    assert response.status_code == 403

    login(http, 'test')
    response = http.get('/display_groups_passwords')
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert 'group label' in page_data


def test_delete_password(http):
    response = http.get('/delete_password/1')
    assert response.status_code == 403
    response = http.post('/delete_password/1')
    assert response.status_code == 403

    login(http, 'test2')
    response = http.get('/', follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert 'one super password' not in page_data
    response = http.get('/delete_password/1', follow_redirects=True)
    assert response.status_code == 404
    response = http.post('/delete_password/1', follow_redirects=True)
    assert response.status_code == 404

    login(http, 'test')
    response = http.get('/', follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert 'one super password' in page_data

    response = http.get('/delete_password/1', follow_redirects=True)
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert '<form' in page_data
    assert 'Supprimer' in page_data

    response = http.post('/delete_password/1', follow_redirects=True)
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert 'one super password' not in page_data


def test_delete_password_from_group(http, db_session):
    response = http.get('/delete_password_from_group/1/1')
    assert response.status_code == 403
    response = http.post('/delete_password_from_group/1/1')
    assert response.status_code == 403

    login(http, 'test')
    http.post('/share_password_group/1', data={'group_ids': [1, 2]})
    response = http.get('/display_groups_passwords', follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert page_data.count('one super password') == 2

    response = http.get(
        '/delete_password_from_group/1/3', follow_redirects=True)
    assert response.status_code == 404
    response = http.get(
        '/delete_password_from_group/3/1', follow_redirects=True)
    assert response.status_code == 404

    response = http.get(
        '/delete_password_from_group/1/1', follow_redirects=True)
    assert response.status_code == 200

    page_data = response.data.decode('utf-8')
    assert 'Supprimer' in page_data
    response = http.post(
        '/delete_password_from_group/1/1', follow_redirects=True)
    assert response.status_code == 200
    response = http.get('/display_groups_passwords', follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert page_data.count('one super password') == 1

    response = http.post(
        '/delete_password_from_group/1/2', follow_redirects=True)
    assert response.status_code == 200
    response = http.get('/display_groups_passwords', follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert 'one super password' not in page_data

    password = db_session.query(Password).get(1)
    assert password is None


def test_edit_password(http):
    data_password = {
        'label': 'new label',
        'login': 'login',
        'password': 'password',
        'notes': 'super notes'
    }

    response = http.get('/edit_password/1')
    assert response.status_code == 403
    response = http.post(
        '/edit_password/1', data=data_password, follow_redirects=True)
    assert response.status_code == 403

    login(http, 'test')
    response = http.get('/', follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert 'one super password' in page_data
    assert 'question' in page_data
    response = http.get('/edit_password/1')
    assert response.status_code == 200
    response = http.post(
        '/edit_password/1', data=data_password, follow_redirects=True)
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert 'new label' in page_data
    assert 'super notes' in page_data


def test_share_password_group(http):
    response = http.get('/share_password_group/1', follow_redirects=True)
    assert response.status_code == 403
    response = http.post('/share_password_group/1', data={'group_ids': 1})
    assert response.status_code == 403

    login(http, 'test2')
    response = http.get('/display_groups_passwords')
    page_data = response.data.decode('utf-8')
    assert 'one super password' not in page_data

    login(http, 'test')
    response = http.get('/share_password_group/1', follow_redirects=True)
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert 'Partager' in page_data
    response = http.post(
        '/share_password_group/1', data={'group_ids': [1, 2]},
        follow_redirects=True)
    assert response.status_code == 200

    login(http, 'test2')
    response = http.get('/display_groups_passwords')
    page_data = response.data.decode('utf-8')
    assert page_data.count('one super password') == 2


def test_add_password(http):
    data = {
        'label': 'new password',
        'login': 'login',
        'password': 'password',
        'notes': 'blabla'
    }
    response = http.get('/add_password')
    assert response.status_code == 403
    response = http.post('/add_password', data=data, follow_redirects=True)
    assert response.status_code == 403

    login(http, 'test')
    response = http.get('/', follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert 'new password' not in page_data
    response = http.get('/add_password')
    assert response.status_code == 200
    response = http.post('/add_password', data=data, follow_redirects=True)
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert 'new password' in page_data
    assert 'blabla' in page_data

    data['label'] = 'hey oh'
    data['group_id'] = 1
    response = http.post('/add_password', data=data, follow_redirects=True)
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert 'hey oh' not in page_data
    response = http.get('/display_groups_passwords')
    page_data = response.data.decode('utf-8')
    assert 'hey oh' in page_data


def test_delete_group(http):
    response = http.get('/delete_group/1', follow_redirects=True)
    assert response.status_code == 403
    response = http.post('/delete_group/1', follow_redirects=True)
    assert response.status_code == 403

    login(http, 'test')
    response = http.get('/display_groups_passwords')
    page_data = response.data.decode('utf-8')
    assert 'group label' in page_data
    response = http.get('/delete_group/1')
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert 'Supprimer' in page_data
    response = http.post('/delete_group/1', follow_redirects=True)
    assert response.status_code == 200
    response = http.get('/display_groups_passwords')
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert 'group label' not in page_data

    logout(http)

    data = {
        'login': 'test3@example.com',
        'password': 'test'
    }

    http.post('/add_user', data=data, follow_redirects=True)

    login(http, 'test3')
    response = http.get('/display_groups_passwords')
    page_data = response.data.decode('utf-8')
    assert 'group label' not in page_data
    response = http.get('/delete_group/1')
    assert response.status_code == 404
    response = http.post('/delete_group/1', follow_redirects=True)
    assert response.status_code == 404


def test_edit_group(http):
    response = http.get('/edit_group/1')
    assert response.status_code == 403
    response = http.post('/edit_group/1', data={'label': 'super group label'})
    assert response.status_code == 403

    login(http, 'test')
    response = http.get('/display_groups_passwords')
    page_data = response.data.decode('utf-8')
    assert 'group label' in page_data
    response = http.get('/edit_group/1')
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert 'Mettre à jour' in page_data
    response = http.post(
        '/edit_group/1', data={'label': 'super group label'},
        follow_redirects=True)
    assert response.status_code == 200
    response = http.get('/display_groups_passwords')
    page_data = response.data.decode('utf-8')
    assert 'super group label' in page_data

    logout(http)

    data = {
        'login': 'test3@example.com',
        'password': 'test'
    }

    http.post('/add_user', data=data, follow_redirects=True)

    login(http, 'test3')
    response = http.get('/display_groups_passwords')
    page_data = response.data.decode('utf-8')
    assert 'group label' not in page_data
    response = http.get('/edit_group/1')
    assert response.status_code == 404
    response = http.post(
        '/edit_group/1', data={'label': 'super group label'},
        follow_redirects=True)
    assert response.status_code == 404


def test_add_group(http):
    response = http.get('/add_group')
    assert response.status_code == 403
    response = http.post('/add_group', data={'label': 'toto'})
    assert response.status_code == 403

    login(http, 'test')
    response = http.get('/display_groups_passwords')
    page_data = response.data.decode('utf-8')
    assert 'toto' not in page_data
    response = http.get('/add_group')
    assert response.status_code == 200
    response = http.post(
        '/add_group', data={'label': 'toto'}, follow_redirects=True)
    assert response.status_code == 200
    response = http.get('/display_groups_passwords')
    page_data = response.data.decode('utf-8')
    assert 'toto' in page_data


def test_delete_user(http):
    response = http.get('/delete_user')
    assert response.status_code == 403
    response = http.post('/delete_user', follow_redirects=True)
    assert response.status_code == 403

    login(http, 'test')
    response = http.get('/delete_user')
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert 'Supprimer mon compte' in page_data
    response = http.post('/delete_user', follow_redirects=True)
    assert response.status_code == 200

    login(http, 'test')
    response = http.get('/', follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert '<form' in page_data


def test_edit_user(http):
    response = http.get('/edit_user')
    assert response.status_code == 403
    response = http.post(
        '/edit_user', data={'password': 'test3'}, follow_redirects=True)
    assert response.status_code == 403

    login(http, 'test')
    response = http.get('/edit_user')
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert 'Mettre à jour mon profil' in page_data
    response = http.post(
        '/edit_user', data={'password': 'test3'}, follow_redirects=True)
    assert response.status_code == 200

    login(http, 'test')
    response = http.get('/', follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert '<form' in page_data

    login(http, 'test', 'test3')
    response = http.get('/', follow_redirects=True)
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert 'one super password' in page_data

    response = http.post(
        '/edit_user', data={'login': 'test2@example.com'},
        follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert 'Ce mail est déjà utilisé' in page_data

    response = http.post(
        '/edit_user', data={'login': 'new@example.com'}, follow_redirects=True)

    login(http, 'test', 'test3')
    response = http.get('/', follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert '<form' in page_data

    login(http, 'new@example.com', 'test3')
    response = http.get('/', follow_redirects=True)
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert 'one super password' in page_data


def test_add_user(http):
    data = {
        'login': 'test3@example.com',
        'password': 'test'
    }

    response = http.get('/add_user')
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert '<form' in page_data
    response = http.post('/add_user', data=data, follow_redirects=True)
    assert response.status_code == 200

    login(http, 'test3')
    response = http.get('/', follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert 'Nouvelle note' in page_data


def test_add_user_no_mail_or_password(http):
    response = http.get('/add_user')
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert 'Créer mon compte' in page_data
    http.post('/add_user', follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert 'Créer mon compte' in page_data


def test_add_user_mail_already_used(http):
    data = {
        'login': 'test@example.com',
        'password': 'test'
    }

    response = http.get('/add_user')
    assert response.status_code == 200
    response = http.post('/add_user', data=data, follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert 'Ce mail est déjà utilisé' in page_data


def test_add_user_group(http):
    data = {
        'login': 'test3@example.com',
        'password': 'test'
    }

    http.post('/add_user', data=data)

    response = http.get('/add_user_group/1')
    assert response.status_code == 403
    response = http.post(
        '/add_user_group/1', data={'mail': 'test3@example.com'})
    assert response.status_code == 403

    login(http, 'test')
    http.post('/share_password_group/1', data={'group_ids': 1})
    response = http.get('/add_user_group/1')
    assert response.status_code == 200

    response = http.post(
        '/add_user_group/1', data={'mail': 'bad_mail'},
        follow_redirects=True)
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert 'Mail invalide' in page_data

    response = http.post(
        '/add_user_group/1', data={'mail': 'test3@example.com'},
        follow_redirects=True)
    assert response.status_code == 200

    login(http, 'test3')
    response = http.get('/display_groups_passwords')
    page_data = response.data.decode('utf-8')
    assert 'group label' in page_data
    assert 'one super password' in page_data


def test_quit_group(http):
    response = http.get('/quit_group/1')
    assert response.status_code == 403
    response = http.post('/quit_group/1')
    assert response.status_code == 403

    login(http, 'test')
    http.post('/share_password_group/1', data={'group_ids': 1})
    response = http.get('/display_groups_passwords')
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert 'group label' in page_data
    assert 'one super password' in page_data

    response = http.get('/quit_group/1')
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert 'Quitter' in page_data

    response = http.post('/quit_group/1', follow_redirects=True)
    assert response.status_code == 200
    response = http.get('/display_groups_passwords')
    page_data = response.data.decode('utf-8')
    assert 'group label' not in page_data
    assert 'one super password' not in page_data
