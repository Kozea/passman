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

deploy-test:
	$(LOG)
	@echo "Communicating with Junkrat..."
	@wget --no-verbose --content-on-error -O- --header="Content-Type:application/json" --post-data=$(subst $(newline),,$(JUNKRAT_PARAMETERS)) $(JUNKRAT) | tee $(JUNKRAT_RESPONSE)
	if [[ $$(tail -n1 $(JUNKRAT_RESPONSE)) != "Success" ]]; then exit 9; fi
	wget --no-verbose --content-on-error -O- $(URL_TEST)

deploy-prod:
	$(LOG)
	@echo "Communicating with Junkrat..."
	@wget --no-verbose --content-on-error -O- --header="Content-Type:application/json" --post-data=$(subst $(newline),,$(JUNKRAT_PARAMETERS)) $(JUNKRAT) | tee $(JUNKRAT_RESPONSE)
	if [[ $$(tail -n1 $(JUNKRAT_RESPONSE)) != "Success" ]]; then exit 9; fi
	wget --no-verbose --content-on-error -O- $(URL_PROD)
