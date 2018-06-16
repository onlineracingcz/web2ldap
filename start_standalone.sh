#!/bin/sh

WEB2LDAP_HOME="$(pwd)" PYTHONPATH="$(pwd)" python2 "$(pwd)/web2ldap/wsgi.py"
