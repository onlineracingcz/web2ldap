#!/bin/sh

WEB2LDAP_HOME="$(dirname $0)"
if [ ${WEB2LDAP_HOME} = "." ]
then
  WEB2LDAP_HOME="$(pwd)"
fi
export WEB2LDAP_HOME

PYTHONPATH="${WEB2LDAP_HOME}" python2 "${WEB2LDAP_HOME}/web2ldap/wsgi.py"
