#!/bin/sh

python setup.py clean --all
rm -r MANIFEST .coverage dist/ldap0* build/* *.egg-info .tox docs/.build/*
rm _libldap0.so _libldap0.cpython*.so ldap0/*.py? ldap0/*/*.py? tests/*.py? *.py?
find -name __pycache__ | xargs -n1 -iname rm -r name
rm -r slapdtest-[0-9]*
