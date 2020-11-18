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

# Convert warnings to exceptions
PYTHONWARNINGS=error
export PYTHONWARNINGS

python3 -m gunicorn.app.wsgiapp \
  --name=web2ldap \
  --preload \
  --worker-class=gthread \
  --workers=1 \
  --threads=4 \
  --worker-connections=40 \
  --log-level=DEBUG \
  --bind=127.0.0.1:1760 \
  --reuse-port \
  web2ldap.wsgi:application