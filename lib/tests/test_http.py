from base64 import b64encode

from flask import session

from ..backend import app
from .conftest import PRIVATE_KEY


def test_connect(db_session):
    request = app.test_client().get('/')
    assert request.status_code == 200
    assert b'Login' in request.data
    assert b'Password' in request.data

    with app.test_client() as client:
        client.post(
            '/', data={'login': 'test@example.com', 'password': 'test'}
        )
        assert session['user_id'] == 1
        assert b64encode(session['private_key']).decode('ascii') == PRIVATE_KEY


def test_logout(db_session):
    with app.test_client() as client:
        client.post(
            '/', data={'login': 'test@example.com', 'password': 'test'}
        )
        client.get('/logout')
        assert session.get('user_id') == None
        assert session.get('private_key') == None


def test_display_passwords(db_session):
    with app.test_client() as client:
        client.post(
            '/', data={'login': 'test@example.com', 'password': 'test'}
        )
        request = client.get('/display_passwords')
        assert request.status_code == 200
        assert b'one super password' in request.data
        assert b'question' in request.data


def test_display_groups(db_session):
    with app.test_client() as client:
        client.post(
            '/', data={'login': 'test@example.com', 'password': 'test'}
        )
        request = client.get('/display_groups')
        assert request.status_code == 200
        assert b'group label' in request.data


def test_delete_password(db_session):
    with app.test_client() as client:
        client.post(
            '/', data={'login': 'test@example.com', 'password': 'test'}
        )
        request = client.get('/display_passwords')
        assert b'one super password' in request.data
        client.post('/delete_password/1')
        request = client.get('/display_passwords')
        assert b'one super password' not in request.data


def test_edit_password(db_session):
    with app.test_client() as client:
        client.post(
            '/', data={'login': 'test@example.com', 'password': 'test'}
        )
        request = client.get('/display_passwords')
        assert b'one super password' in request.data
        assert b'question' in request.data
        request = client.get('/edit_password/1')
        assert request.status_code == 200
        client.post(
            '/edit_password/1',
            data={
                'label': 'new label',
                'login': 'login',
                'password': 'password',
                'notes': 'super notes',
            },
        )
        request = client.get('display_passwords')
        assert b'new label' in request.data
        assert b'super notes' in request.data


def test_share_password_group(db_session):
    with app.test_client() as client:
        client.post(
            '/', data={'login': 'test2@example.com', 'password': 'test2'}
        )
        request = client.get('/display_passwords')
        assert b'No password linked to this account' in request.data
        client.get('/logout')
        client.post(
            '/', data={'login': 'test@example.com', 'password': 'test'}
        )
        client.post('/share_password_group/1', data={'group': 1})
        client.get('/logout')
        client.post(
            '/', data={'login': 'test2@example.com', 'password': 'test2'}
        )
        request = client.get('/display_passwords')
        assert b'one super password' in request.data


def test_add_password(db_session):
    with app.test_client() as client:
        client.post(
            '/', data={'login': 'test2@example.com', 'password': 'test2'}
        )
        request = client.get('/display_passwords')
        assert b'No password linked to this account' in request.data
        request = client.get('/add_password')
        assert request.status_code == 200
        client.post(
            '/add_password',
            data={
                'label': 'new password',
                'login': 'login',
                'password': 'password',
                'notes': 'blabla',
            },
        )
        request = client.get('/display_passwords')
        assert b'new password' in request.data
        assert b'blabla' in request.data


def test_delete_group(db_session):
    with app.test_client() as client:
        client.post(
            '/', data={'login': 'test@example.com', 'password': 'test'}
        )
        request = client.get('/display_groups')
        assert b'group label' in request.data
        request = client.get('/delete_group/1')
        assert request.status_code == 200
        client.post('/delete_group/1')
        request = client.get('/display_groups')
        assert b'group label' not in request.data


def test_edit_group(db_session):
    with app.test_client() as client:
        client.post(
            '/', data={'login': 'test@example.com', 'password': 'test'}
        )
        request = client.get('/display_groups')
        assert b'group label' in request.data
        request = client.get('/edit_group/1')
        assert request.status_code == 200
        client.post('/edit_group/1', data={'label': 'super group label'})
        request = client.get('/display_groups')
        assert b'super group label' in request.data


def test_add_group(db_session):
    with app.test_client() as client:
        client.post(
            '/', data={'login': 'test@example.com', 'password': 'test'}
        )
        request = client.get('/display_groups')
        assert b'toto' not in request.data
        request = client.get('/add_group')
        assert request.status_code == 200
        client.post('/add_group', data={'label': 'toto'})
        request = client.get('/display_groups')
        assert b'toto' in request.data


def test_delete_user(db_session):
    with app.test_client() as client:
        client.post(
            '/', data={'login': 'test@example.com', 'password': 'test'}
        )
        request = client.get('/display_passwords')
        assert request.status_code == 200
        request = client.get('/delete_user')
        assert request.status_code == 200
        client.post('/delete_user')
        client.post(
            '/', data={'login': 'test@example.com', 'password': 'test'}
        )
        request = client.get('/')
        assert b'Login or password incorrect' in request.data


def test_edit_user(db_session):
    with app.test_client() as client:
        client.post(
            '/', data={'login': 'test@example.com', 'password': 'test'}
        )
        request = client.get('/display_passwords')
        assert request.status_code == 200
        request = client.get('/edit_user')
        assert request.status_code == 200
        client.post(
            '/edit_user',
            data={'mail': 'test3@example.com', 'password': 'test3'},
        )
        client.post(
            '/', data={'login': 'test@example.com', 'password': 'test'}
        )
        request = client.get('/')
        assert b'Login or password incorrect' in request.data
        client.post(
            '/', data={'login': 'test3@example.com', 'password': 'test3'}
        )
        request = client.get('/display_passwords')
        assert request.status_code == 200


def test_add_user(db_session):
    with app.test_client() as client:
        request = client.get('/add_user')
        assert request.status_code == 200
        client.post(
            '/add_user', data={'mail': 'test3@example.com', 'password': 'test'}
        )
        client.post(
            '/', data={'login': 'test3@example.com', 'password': 'test'}
        )
        request = client.get('/display_passwords')
        assert request.status_code == 200


def test_add_user_no_mail_or_password(db_session):
    with app.test_client() as client:
        request = client.get('/add_user')
        assert request.status_code == 200
        client.post('/add_user')
        request = client.get('/add_user')
        assert b'No mail or password provided' in request.data


def test_add_user_mail_already_used(db_session):
    with app.test_client() as client:
        request = client.get('/add_user')
        assert request.status_code == 200
        client.post(
            '/add_user', data={'mail': 'test@example.com', 'password': 'test'}
        )
        request = client.get('/add_user')
        assert b'Mail already used' in request.data


def test_add_user_group(db_session):
    with app.test_client() as client:
        client.post(
            '/add_user', data={'mail': 'test3@example.com', 'password': 'test'}
        )
        client.post(
            '/', data={'login': 'test@example.com', 'password': 'test'}
        )
        request = client.get('/add_user_group/1')
        assert request.status_code == 200
        client.post('/add_user_group/1', data={'mail': 'test3@example.com'})
        client.post('/share_password_group/1', data={'group': 1})
        client.get('/logout')
        client.post(
            '/', data={'login': 'test3@example.com', 'password': 'test'}
        )
        request = client.get('/display_groups')
        assert b'group label' in request.data
        request = client.get('/display_passwords')
        assert b'one super password' in request.data


def test_quit_group(db_session):
    with app.test_client() as client:
        client.post(
            '/', data={'login': 'test@example.com', 'password': 'test'}
        )
        request = client.get('/display_groups')
        assert b'group label' in request.data
        request = client.get('/quit_group/1')
        assert request.status_code == 200
        client.post('/quit_group/1')
        request = client.get('/display_groups')
        assert b'group label' not in request.data
