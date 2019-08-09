import locale
import os
import sqlite3
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, g, session
from flask_alcool import Alcool
from sqlalchemy.engine import create_engine
from sqlalchemy.orm import sessionmaker

from .model import User

locale.setlocale(locale.LC_ALL, 'fr_FR')

app = Flask(__name__)
app.config.from_envvar('FLASK_CONFIG')
Alcool(app)


def drop_db():
    filename = urlparse(app.config['DB']).path
    if os.path.isfile(filename):
        os.remove(filename)


def install_dev_data():
    filename = urlparse(app.config['DB']).path
    connection = sqlite3.connect(filename)
    sql_folder = Path(app.root_path) / 'sql'
    connection.executescript((sql_folder / 'test.sql').open().read())
    connection.commit()


app.cli.command()(install_dev_data)
app.cli.command()(drop_db)


@app.before_request
def before_request():
    g.context = {}
    db = app.config['DB']
    g.session = sessionmaker(bind=create_engine(db), autoflush=False)()
    if 'user_id' in session:
        g.context['user'] = g.session.query(User).get(session['user_id'])
    else:
        g.context['user'] = None


@app.after_request
def after_request(response):
    g.session.close()
    return response


from .routes import *  # noqa isort:skip
