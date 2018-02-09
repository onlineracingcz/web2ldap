#!/bin/sh
#
# web2ldap's post-install script for adding user and fix 
# ownership/permissions on a Unixoid OS
#
# Notes:
# - Obviously this script has to be run as root
# - This assumes you installed web2ldap in /opt/web2ldap.
#   You may have to adjust paths to your local installation.
# - You may want to adjust the permissions if you have other stricter 
#   security requirements

CHMOD="chmod -c"

WEB2LDAP_PREFIX="/opt/web2ldap"

WEB2LDAP_USER="web2ldap"
WEB2LDAP_UID="1760"

WEB2LDAP_GROUP="web2ldap"
WEB2LDAP_GID="1760"

COMPILE_ARGS="-m compileall -f ${WEB2LDAP_PREFIX}"

echo "-------------------- Pre-compile Python sources -------------------"
python ${COMPILE_ARGS}
python -O ${COMPILE_ARGS}

echo "-------------------- Add group and user -------------------"

groupadd -g ${WEB2LDAP_GID} ${WEB2LDAP_GROUP}
useradd -g ${WEB2LDAP_GID} -u ${WEB2LDAP_UID} -r -s /bin/false -d ${WEB2LDAP_PREFIX}/var/lib -M -c "Demon user for web2ldap"  ${WEB2LDAP_USER}

echo "-------------------- Create directories var/* -------------------"

mkdir -p ${WEB2LDAP_PREFIX}/var/run ${WEB2LDAP_PREFIX}/var/log ${WEB2LDAP_PREFIX}/var/lib

echo "-------------------- Set ownership -------------------"

chown -R root: ${WEB2LDAP_PREFIX}
chown -R web2ldap:root ${WEB2LDAP_PREFIX}/var/run ${WEB2LDAP_PREFIX}/var/log ${WEB2LDAP_PREFIX}/var/lib

echo "-------------------- Set permissions -------------------"

# Generally things are public
${CHMOD} -R a+r ${WEB2LDAP_PREFIX}
${CHMOD} -R go-w ${WEB2LDAP_PREFIX}
find ${WEB2LDAP_PREFIX} -type d | xargs -n1 -idirname ${CHMOD} 0755 dirname

# Set executable bits on scripts
${CHMOD} 0755 ${WEB2LDAP_PREFIX}/sbin/* ${WEB2LDAP_PREFIX}/fcgi/*

# Set permissions in var/
${CHMOD} 0750 ${WEB2LDAP_PREFIX}/var/log ${WEB2LDAP_PREFIX}/var/lib
${CHMOD} -R o-rwx ${WEB2LDAP_PREFIX}/var/log ${WEB2LDAP_PREFIX}/var/lib
