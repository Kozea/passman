from base64 import b64encode

from flask import session

from ..backend import app
from .conftest import PRIVATE_KEY


def test_login(db_session):
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
