from base64 import b64encode

from flask import session

from ..backend import app
from .conftest import PRIVATE_KEY


def test_connect(db_session):
    request = app.test_client().get('/login')
    assert request.status_code == 200
    page_data = request.data.decode('utf-8')
    assert 'Identifiant' in page_data
    assert 'Mot de passe' in page_data

    data = {'login': 'test@example.com', 'password': 'test'}

    with app.test_client() as client:
        client.post('/login', data=data)
        assert session['user_id'] == 1
        assert b64encode(session['private_key']).decode('ascii') == PRIVATE_KEY


def test_logout(db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    with app.test_client() as client:
        client.post('/login', data=data)
        assert session['user_id'] == 1
        client.get('/logout')
        assert session.get('user_id') is None
        assert session.get('private_key') is None


def test_display_passwords(db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    with app.test_client() as client:
        request = client.post('/login', data=data, follow_redirects=True)
        assert request.status_code == 200
        page_data = request.data.decode('utf-8')
        assert 'one super password' in page_data
        assert 'question' in page_data


def test_display_groups(db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    with app.test_client() as client:
        client.post('/login', data=data)
        request = client.get('/display_groups_passwords')
        assert request.status_code == 200
        page_data = request.data.decode('utf-8')
        assert 'group label' in page_data


def test_delete_password(db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    with app.test_client() as client:
        request = client.post('/login', data=data, follow_redirects=True)
        page_data = request.data.decode('utf-8')
        assert 'one super password' in page_data
        request = client.post('/delete_password/1')
        page_data = request.data.decode('utf-8')
        assert 'one super password' not in page_data


def test_edit_password(db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    data_password = {
        'label': 'new label', 'login': 'login', 'password': 'password',
        'notes': 'super notes'}
    with app.test_client() as client:
        request = client.post('/login', data=data, follow_redirects=True)
        page_data = request.data.decode('utf-8')
        assert 'one super password' in page_data
        assert 'question' in page_data
        request = client.get('/edit_password/1')
        assert request.status_code == 200
        request = client.post(
            '/edit_password/1', data=data_password, follow_redirects=True)
        page_data = request.data.decode('utf-8')
        assert 'new label' in page_data
        assert 'super notes' in page_data


def test_share_password_group(db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    data_user_2 = {'login': 'test2@example.com', 'password': 'test2'}
    with app.test_client() as client:
        request = client.post(
            '/login', data=data_user_2, follow_redirects=True)
        page_data = request.data.decode('utf-8')
        assert 'Supprimer la note' not in page_data
        client.get('/logout')
        client.post('/login', data=data)
        client.post('/share_password_group/1', data={'group_ids': 1})
        client.get('/logout')
        client.post('/login', data=data_user_2)
        request = client.get('/display_groups_passwords')
        page_data = request.data.decode('utf-8')
        assert 'one super password' in page_data


def test_add_password(db_session):
    data_user_2 = {'login': 'test2@example.com', 'password': 'test2'}
    data_password = {
        'label': 'new password', 'login': 'login', 'password': 'password',
        'notes': 'blabla'}
    with app.test_client() as client:
        request = client.post(
            '/login', data=data_user_2, follow_redirects=True)
        page_data = request.data.decode('utf-8')
        assert 'Supprimer la note' not in page_data
        request = client.get('/add_password')
        assert request.status_code == 200
        request = client.post(
            '/add_password', data=data_password, follow_redirects=True)
        page_data = request.data.decode('utf-8')
        assert 'new password' in page_data
        assert 'blabla' in page_data


def test_delete_group(db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    with app.test_client() as client:
        client.post('/login', data=data)
        request = client.get('/display_groups_passwords')
        page_data = request.data.decode('utf-8')
        assert 'group label' in page_data
        request = client.get('/delete_group/1')
        assert request.status_code == 200
        client.post('/delete_group/1')
        request = client.get('/display_groups_passwords')
        page_data = request.data.decode('utf-8')
        assert 'group label' not in page_data


def test_edit_group(db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    with app.test_client() as client:
        client.post('/login', data=data)
        request = client.get('/display_groups_passwords')
        page_data = request.data.decode('utf-8')
        assert 'group label' in page_data
        request = client.get('/edit_group/1')
        assert request.status_code == 200
        client.post('/edit_group/1', data={'label': 'super group label'})
        request = client.get('/display_groups_passwords')
        page_data = request.data.decode('utf-8')
        assert 'super group label' in page_data


def test_add_group(db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    with app.test_client() as client:
        client.post('/login', data=data)
        request = client.get('/display_groups_passwords')
        page_data = request.data.decode('utf-8')
        assert 'toto' not in page_data
        request = client.get('/add_group')
        assert request.status_code == 200
        client.post('/add_group', data={'label': 'toto'})
        request = client.get('/display_groups_passwords')
        page_data = request.data.decode('utf-8')
        assert 'toto' in page_data


def test_delete_user(db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    with app.test_client() as client:
        request = client.post('/login', data=data, follow_redirects=True)
        assert request.status_code == 200
        request = client.get('/delete_user')
        assert request.status_code == 200
        client.post('/delete_user', follow_redirects=True)
        request = client.post('/login', data=data, follow_redirects=True)
        page_data = request.data.decode('utf-8')
        assert 'Identifiant ou mot de passe incorrect' in page_data


def test_edit_user(db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    with app.test_client() as client:
        request = client.post('/login', data=data, follow_redirects=True)
        assert request.status_code == 200
        request = client.get('/edit_user')
        assert request.status_code == 200
        client.post(
            '/edit_user',
            data={'password': 'test3'},
        )
        client.get('/logout')
        request = client.post('/login', data=data, follow_redirects=True)
        page_data = request.data.decode('utf-8')
        assert 'Identifiant ou mot de passe incorrect' in page_data
        data['password'] = 'test3'
        request = client.post('/login', data=data, follow_redirects=True)
        assert request.status_code == 200
        page_data = request.data.decode('utf-8')
        assert 'one super password' in page_data


def test_add_user(db_session):
    data_user_3 = {'login': 'test3@example.com', 'password': 'test'}
    with app.test_client() as client:
        request = client.get('/add_user')
        assert request.status_code == 200
        page_data = request.data.decode('utf-8')
        assert '<form' in page_data
        client.post('/add_user', data=data_user_3)
        request = client.post(
            '/login', data=data_user_3, follow_redirects=True)
        assert request.status_code == 200
        page_data = request.data.decode('utf-8')
        assert 'Nouvelle note' in page_data


def test_add_user_no_mail_or_password(db_session):
    with app.test_client() as client:
        request = client.get('/add_user')
        assert request.status_code == 200
        page_data = request.data.decode('utf-8')
        assert 'Créer mon compte' in page_data
        client.post('/add_user', follow_redirects=True)
        page_data = request.data.decode('utf-8')
        assert 'Créer mon compte' in page_data


def test_add_user_mail_already_used(db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    with app.test_client() as client:
        request = client.get('/add_user')
        assert request.status_code == 200
        request = client.post('/add_user', data=data, follow_redirects=True)
        page_data = request.data.decode('utf-8')
        assert 'Mail déjà utilisé' in page_data


def test_add_user_group(db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    data_user_3 = {'login': 'test3@example.com', 'password': 'test'}
    with app.test_client() as client:
        client.post('/add_user', data=data_user_3)
        client.post('/login', data=data)
        request = client.get('/add_user_group/1')
        assert request.status_code == 200
        client.post('/add_user_group/1', data={'mail': 'test3@example.com'})
        client.post('/share_password_group/1', data={'group_ids': 1})
        client.get('/logout')
        client.post('/login', data=data_user_3)
        request = client.get('/display_groups_passwords')
        page_data = request.data.decode('utf-8')
        assert 'group label' in page_data
        assert 'one super password' in page_data


def test_quit_group(db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    with app.test_client() as client:
        client.post('/login', data=data, follow_redirects=True)
        request = client.get('/display_groups_passwords')
        page_data = request.data.decode('utf-8')
        assert 'group label' in page_data
        request = client.get('/quit_group/1')
        assert request.status_code == 200
        client.post('/quit_group/1')
        request = client.get('/display_groups_passwords')
        page_data = request.data.decode('utf-8')
        assert 'group label' not in page_data
