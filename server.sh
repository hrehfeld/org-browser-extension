#!/usr/bin/sh
export FLASK_APP=server
export FLASK_ENV=development
# suppresses any startup messages
export WERKZEUG_RUN_MAIN=true
poetry run python server.py
