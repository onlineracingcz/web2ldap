# -*- coding: utf-8 -*-
"""
web2ldap.app.core: some core functions used throughout web2ldap

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
import time

import web2ldap.__about__
from web2ldap.log import logger

logger.info('Starting web2ldap %s', web2ldap.__about__.__version__)
# this has to be done before import module package ldap0
os.environ['LDAPNOINIT'] = '1'
logger.debug('Disabled processing .ldaprc or ldap.conf (LDAPNOINIT=%s)', os.environ['LDAPNOINIT'])

import ldap0
from web2ldap.checkinst import check_inst

check_inst()

# Path name of [web2ldap]/etc/web2ldap
if 'WEB2LDAP_HOME' in os.environ:
    # env var points to web2ldap root directory
    etc_dir = os.path.join(os.environ['WEB2LDAP_HOME'], 'etc', 'web2ldap')
elif os.name == 'posix' and sys.prefix == '/usr':
    # OS-wide installation on POSIX platform (Linux, BSD, etc.)
    etc_dir = '/etc/web2ldap'
else:
    # virtual env
    etc_dir = os.path.join(sys.prefix, 'etc', 'web2ldap')

# Default directory for [web2ldap]/etc/web2ldap/templates
templates_dir = os.path.join(etc_dir, 'templates')

sys.path.append(etc_dir)

# must import config modules after setting etc_dir and template_dir
import web2ldapcnf
import web2ldapcnf.hosts

import web2ldap.app.cnf


class ErrorExit(Exception):
    """Base class for web2ldap application exceptions"""

    def __init__(self, Msg):
        assert isinstance(Msg, str), \
            TypeError("Type of argument 'Msg' must be str, was %r" % (Msg))
        self.Msg = Msg


########################################################################
# Initialize some constants
########################################################################

logger.debug('End of module %s', __name__)

# Raise UnicodeError instead of output of UnicodeWarning
from exceptions import UnicodeWarning
from warnings import filterwarnings
filterwarnings(action="error", category=UnicodeWarning)

ldap0._trace_level = web2ldapcnf.ldap_trace_level
ldap0.set_option(ldap0.OPT_DEBUG_LEVEL, web2ldapcnf.ldap_opt_debug_level)
ldap0.set_option(ldap0.OPT_RESTART, 0)
ldap0.set_option(ldap0.OPT_DEREF, 0)
ldap0.set_option(ldap0.OPT_REFERRALS, 0)

STARTUP_TIME = time.time()
