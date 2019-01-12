# -*- coding: utf-8 -*-
"""
web2ldap.log -- Logging

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import os
import sys
import logging
import pprint

import web2ldap.__about__


LOG_LEVEL = os.environ.get('LOG_LEVEL', logging.INFO)

LOG_FORMAT = '%(asctime)s %(levelname)s: %(message)s'

LOG_DATEFMT = '%Y-%m-%d %H:%M:%S'


class LogHelper:
    """
    mix-in class for logging with a class-specific log prefix
    """

    def _log_prefix(self):
        return '%s[%x] ' % (self.__class__.__name__, id(self))

    def log(self, level, msg, *args, **kwargs):
        logger.log(level, ' '.join((self._log_prefix(), msg)), *args, **kwargs)


def log_exception(env, ls, debug=__debug__):
    """
    Write an exception with environment vars, LDAP connection data
    and Python traceback to error log
    """
    # Get exception instance and traceback info
    exc_type, exc_info, exc_trb = sys.exc_info()
    logentry = [
        '------------------- Unhandled error -------------------',
        'web2ldap version: %s' % web2ldap.__about__.__version__,
        'LDAPSession instance: %r' % (ls),
        '%s.%s: %s' % (exc_type.__module__, exc_type.__name__, exc_info),
    ]
    if debug and ls is not None:
        # Log the LDAPSession object attributes
        logentry.append(pprint.pformat(ls.__dict__))
    if debug:
        # Log all environment vars
        logentry.append(pprint.pformat(sorted(env.items())))
    # Write the log entry
    logger.error(os.linesep.join(logentry), exc_info=debug)
    # Avoid memory leaks
    exc_obj = exc_value = exc_traceback = None
    del exc_obj
    del exc_value
    del exc_traceback
    return # log_exception()


def init_logger():
    """
    Create logger instance
    """
    logging.basicConfig(
        level=LOG_LEVEL,
        format=LOG_FORMAT,
        datefmt=LOG_DATEFMT,
    )
    return logging.getLogger()


global logger
logger = init_logger()
