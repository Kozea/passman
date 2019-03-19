from base64 import b64decode, b64encode

from ..backend import utils
from ..backend.model import Password, User
from .conftest import PRIVATE_KEY


def test_user_exists(db_session):
    assert utils.user_exists('test@example.com')


def test_not_user_exists(db_session):
    assert not utils.user_exists('toto@example.com')


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
        'questions': 'questions',
        'id': 1,
        'label': 'one super password',
    }


def test_create_group(db_session):
    user = db_session.query(User).get(1)
    group = utils.create_group(user, 'label')
    assert group.label == 'label'
    assert group.owner_id == 1
    assert group.users == [user]


def test_update_group(db_session):
    user = db_session.query(User).get(1)
    group = utils.create_group(user, 'label')
    updated_group = utils.update_group(group, 'new label')
    assert updated_group.label == 'new label'
