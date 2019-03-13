import locale
import logging
import os
import sqlite3
from pathlib import Path

from urllib.parse import urlparse

from flask import Flask

from .model import db


locale.setlocale(locale.LC_ALL, 'fr_FR')

app = Flask(__name__)
app.config.from_envvar('FLASK_CONFIG')
db.init_app(app)


@app.cli.command()
def drop_db():
    filename = urlparse(app.config['DB']).path
    if os.path.isfile(filename):
        os.remove(filename)


@app.cli.command()
def install_dev_data(app=app):
    filename = urlparse(app.config['DB']).path
    connection = sqlite3.connect(filename)
    sql_folder = Path(app.root_path) / 'sql'
    connection.executescript((sql_folder / 'test.sql').open().read())
    connection.commit()


if app.debug:
    level = (
        logging.INFO
        if os.getenv('PYTHON_VERBOSE', os.getenv('VERBOSE'))
        else logging.WARNING
    )
    app.logger.setLevel(level)
    logging.getLogger('sqlalchemy').setLevel(level)
    logging.getLogger('sqlalchemy').handlers = logging.getLogger(
        'werkzeug'
    ).handlers
    logging.getLogger('sqlalchemy.orm').setLevel(logging.WARNING)
    if level == logging.WARNING:
        logging.getLogger('werkzeug').setLevel(level)

from .routes import *  # noqa isort:skip
