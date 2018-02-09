#!/bin/sh
#
# Wrapper script around spawn-fcgi
# see http://redmine.lighttpd.net/projects/spawn-fcgi
#
# Notes:
# - You may have to adjust the path to the spawn-fcgi executable
#   or simply use the script as template for your own custom script
# - This assumes you installed web2ldap in /opt/web2ldap.
#   You may have to adjust paths to your local installation.
# - If setting -u and/or -g this script has to be run as root

# Paths to executables
SPAWN_FCGI_EXEC="/usr/bin/spawn-fcgi"

WEB2LDAP_PREFIX="/opt/web2ldap"
WEB2LDAP_FCGI="${WEB2LDAP_PREFIX}/fcgi/web2ldap.py"
WEB2LDAP_PIDFILE="${WEB2LDAP_PREFIX}/var/run/web2ldap-fcgi.pid"

WEB2LDAP_USER="web2ldap"
WEB2LDAP_UID="1760"

WEB2LDAP_GROUP="web2ldap"
WEB2LDAP_GID="1760"

SPAWN_FCGI_SEC_OPTIONS="-d ${WEB2LDAP_PREFIX}/var/lib -u ${WEB2LDAP_USER} -g ${WEB2LDAP_GROUP}"

# You can either set SPAWN_FCGI_NET_ADDRESS or SPAWN_FCGI_SOCKET_PATH
# but not both at one time!

# FastCGI over TCP
#SPAWN_FCGI_NET_ADDRESS="-a 127.0.0.1 -p 1760"
# FastCGI over Unix Domain Socket
SPAWN_FCGI_SOCKET_PATH="-S -s ${WEB2LDAP_PREFIX}/var/run/fcgi-socket -M 0666"

# Force use of a pseudo-random salt to make hash() values
# in Python 2.6.8+ and Python 2.7.3+ to avoid DoS attacks
PYTHONHASHSEED="random"
export PYTHONHASHSEED

${SPAWN_FCGI_EXEC} \
  -P ${WEB2LDAP_PIDFILE} \
  ${SPAWN_FCGI_SEC_OPTIONS} \
  ${SPAWN_FCGI_NET_ADDRESS} \
  ${SPAWN_FCGI_SOCKET_PATH} \
  -- ${WEB2LDAP_FCGI}
