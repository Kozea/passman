PYTHON_ONLY = 1
HOST ?= 0.0.0.0
API_PORT ?= 1888

export API_SERVER = $(HOST):$(API_PORT)
export FLASK_APP ?= $(PWD)/lib/backend/__init__.py
export FLASK_CONFIG ?= $(PWD)/lib/backend/application.cfg
export FLASK_TEST_CONFIG ?= $(PWD)/lib/backend/application-test.cfg
export FLASK_DEBUG ?= 1

# Python env
PYTHON_VERSION ?= python
PIPENV ?= $(shell command -v pipenv 2> /dev/null)
VENV = $(PWD)/.venv
export PIPENV_VENV_IN_PROJECT = 1

URL_PROD = https://passman.kozea.fr
