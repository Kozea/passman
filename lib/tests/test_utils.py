from base64 import b64decode, b64encode

from ..backend import utils
from ..backend.model import Group, Password, User


def test_user_exists(db_session):
    assert utils.user_exists('test@example.com')


def test_not_user_exists(db_session):
    assert not utils.user_exists('toto@example.com')


def test_decrypt_private_key(db_session, private_key):
    user = db_session.query(User).get(1)
    assert (
        b64encode(utils.decrypt_private_key(user, 'test')).decode('ascii')
        == private_key
    )


def test_decrypt_password(db_session, private_key):
    password = db_session.query(Password).get(1)
    assert utils.decrypt_password(password, b64decode(private_key)) == {
        'login': 'login',
        'password': 'password',
        'questions': 'questions',
        'id': 1,
        'label': 'one super password',
    }


def test_create_group(db_session):
    user = db_session.query(User).get(1)
    utils.create_group(user, 'label')
    assert db_session.query(Group).filter_by(label='label') is not None
