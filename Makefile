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
