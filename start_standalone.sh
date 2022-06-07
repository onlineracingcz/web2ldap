#!/bin/sh

WEB2LDAP_HOME="$(dirname $0)"
if [ ${WEB2LDAP_HOME} = "." ]
then
  WEB2LDAP_HOME="$(pwd)"
fi
export WEB2LDAP_HOME
declare -p WEB2LDAP_HOME

PYTHON3=${PYTHON3:-"python3"}
export PYTHON3
declare -p PYTHON3

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

# Python will print threading debug info
PYTHONTHREADDEBUG=1
export PYTHONTHREADDEBUG

# Python will dump objects and reference counts still alive after shutting down the interpreter.
PYTHONDUMPREFS=1
export PYTHONDUMPREFS

${PYTHON3} -R -bb -tt -m web2ldap
