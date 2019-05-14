#!/bin/sh

WEB2LDAP_HOME="$(dirname $0)"
if [ ${WEB2LDAP_HOME} = "." ]
then
  WEB2LDAP_HOME="$(pwd)"
fi
export WEB2LDAP_HOME
declare -p WEB2LDAP_HOME

LOG_LEVEL=${LOG_LEVEL:-"DEBUG"}
export LOG_LEVEL
declare -p LOG_LEVEL

PYTHONPATH=${WEB2LDAP_HOME}:${PYTHONPATH:-""}
export PYTHONPATH
declare -p PYTHONPATH

PYTHONDONTWRITEBYTECODE="1"
export PYTHONDONTWRITEBYTECODE

python2 -R -tt "${WEB2LDAP_HOME}/web2ldap/wsgi.py"
#coverage-2.7 run "${WEB2LDAP_HOME}/web2ldap/wsgi.py"
