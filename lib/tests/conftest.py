from os.path import dirname, join

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ..backend import app, drop_db, install_dev_data


@pytest.fixture(scope='function')
def db_session(alembic_config):
    session = sessionmaker(bind=create_engine(app.config['DB']))()
    return session


@pytest.yield_fixture(scope='function')
def alembic_config():
    ini_location = join(dirname(__file__), '..', '..', 'alembic.ini')
    sqlalchemy_url = app.config['DB']
    config = Config(ini_location)
    config.set_main_option('sqlalchemy.url', sqlalchemy_url)
    command.upgrade(config, 'head')
    install_dev_data()
    yield config
    drop_db()


@pytest.fixture
def http(db_session):
    context = app.test_request_context()
    context.push()
    return app.test_client()
