#!/bin/bash
pip install -r requirements.txt

# Collect static files
python manage.py collectstatic --noinput

# Migrate the database
python manage.py migrate
