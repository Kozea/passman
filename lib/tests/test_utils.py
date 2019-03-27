from base64 import b64decode, b64encode

from ..backend import utils
from ..backend.model import Password, User
from .conftest import PRIVATE_KEY


def test_user_exists(db_session):
    users = db_session.query(User)
    assert utils.user_exists('test@example.com', users)


def test_not_user_exists(db_session):
    users = db_session.query(User)
    assert not utils.user_exists('toto@example.com', users)


def test_decrypt_private_key(db_session):
    user = db_session.query(User).get(1)
    assert (
        b64encode(utils.decrypt_private_key(user, 'test')).decode('ascii')
        == PRIVATE_KEY
    )


def test_decrypt_password(db_session):
    password = db_session.query(Password).get(1)
    assert utils.decrypt_password(password, b64decode(PRIVATE_KEY)) == {
        'login': 'login',
        'password': 'password',
        'notes': 'questions',
        'id': 1,
        'groups': [],
        'label': 'one super password',
    }
