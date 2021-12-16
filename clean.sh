#!/bin/sh

python3 setup.py clean --all
rm -rf MANIFEST .coverage dist/web2ldap* build/* *.egg-info .tox docs/.build/* .mypy_cache
rm -f web2ldap/*.py? web2ldap/*/*.py? tests/*.py? *.py?
find -name "*.py?" -delete
find -name __pycache__ | xargs -iname rm -r name
rm -rf slapdtest-[0-9]*
