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
import logging

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
