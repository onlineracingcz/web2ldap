# -*- coding: utf-8 -*-
"""
This script checks all the prerequisites for running
a particular release version of web2ldap.

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import sys
import os
import socket
import pprint
import platform
import sysconfig

import ldap0


YES_NO = {False:'no', True:'yes'}


def check_inst():
    """
    Display Python and OpenLDAP installation details
    """
    print '*** Python interpreter ***'
    print 'sys.executable', repr(sys.executable)
    print 'sys.prefix', repr(sys.prefix)
    print 'sys.exec_prefix', repr(sys.exec_prefix)
    print 'sys.version', repr(sys.version)
    print 'sys.maxunicode', sys.maxunicode, hex(sys.maxunicode)
    print 'sys.platform', repr(sys.platform)
    print 'platform.platform()', repr(platform.platform())
    print 'os.name', repr(os.name)
    print 'socket.has_ipv6', repr(socket.has_ipv6)

    if sys.platform == 'linux2':
        print 'platform.linux_distribution()', repr(platform.linux_distribution())
        print 'platform.libc_ver()', repr(platform.libc_ver())

    print '*** sysconfig.get_paths() ***'
    print pprint.pformat(sysconfig.get_paths())
    print '*** sys.path ***'
    print pprint.pformat(sys.path)
    print 'sysconfig.get_python_version()', sysconfig.get_python_version()
    print 'sysconfig.get_platform():', sysconfig.get_platform()
    print 'sysconfig.is_python_build()', sysconfig.is_python_build()

    # Display version numbers of OpenLDAP libs
    print '*** OpenLDAP libs ***'
    print 'ldap0.API_VERSION: %s' % (ldap0.API_VERSION)
    print 'ldap0.VENDOR_VERSION: %s' % (ldap0.VENDOR_VERSION)
    # Check whether built with SSL/TLS (OpenSSL)
    print '*** Suport for SSL/TLS ***'
    if hasattr(ldap0, 'TLS_AVAIL'):
        if hasattr(ldap0, 'OPT_X_TLS_PACKAGE'):
            tls_package = ' (%s)' % ldap0.get_option(ldap0.OPT_X_TLS_PACKAGE)
        else:
            tls_package = ''
        print 'ldap0.TLS_AVAIL: %s%s' % (YES_NO[ldap0.TLS_AVAIL], tls_package)
    # Check whether built with SASL (Cyrus-SASL)
    print '*** Suport for SASL ***'
    if hasattr(ldap0, 'SASL_AVAIL'):
        print 'ldap0.SASL_AVAIL: %s' % (YES_NO[ldap0.SASL_AVAIL])
    print '*** ldap0.OPT_API_INFO ***'
    if hasattr(ldap0, 'OPT_API_INFO'):
        pprint.pprint(ldap0.get_option(ldap0.OPT_API_INFO))

if __name__ == '__main__':
    check_inst()
