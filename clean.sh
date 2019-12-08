#!/bin/sh

python3 setup.py clean --all
rm -r MANIFEST .coverage dist/web2ldap* build/* *.egg-info .tox docs/.build/* .mypy_cache
rm web2ldap/*.py? web2ldap/*/*.py? tests/*.py? *.py?
find -name "*.py?" -delete
find -name __pycache__ | xargs -n1 -iname rm -r name
rm -r slapdtest-[0-9]*
