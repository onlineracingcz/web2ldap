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

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${WEB2LDAP_HOME}" /usr/sbin/uwsgi --strict --ini "${WEB2LDAP_HOME}/etc/uwsgi/uwsgi-http1760-web2ldap.ini"
