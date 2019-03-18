include MakeCitron.Makefile


install-dev-data:  ## install-dev-data: Insert dev data
	$(LOG)
	flask install-dev-data

upgrade-db:
	$(LOG)
	$(VENV)/bin/alembic upgrade head

install-db: install-db-super ## install-db: Install apparatus database
	$(LOG)
	$(PIPENV) run flask drop-db
	$(MAKE) upgrade-db

check-python:
	$(LOG)
	FLASK_CONFIG=$(FLASK_TEST_CONFIG) py.test lib $(PYTEST_ARGS) -p no:warnings --cov lib.backend
