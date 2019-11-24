# -*- coding: utf-8 -*-
"""
web2ldap.app.monitor: Display (SSL) connection data

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import os
import time
import socket
import threading
import pwd

import web2ldapcnf

import web2ldap.__about__
import web2ldap.app.gui
import web2ldap.app.handler
from web2ldap.app.session import session_store, cleanUpThread
from ..ldapsession import LDAPSession
from ..log import logger, EXC_TYPE_COUNTER


try:
    import prometheus_client
except ImportError:
    METRICS_AVAIL = False
    logger.info('prometheus_client not installed => disable metrics!')
else:

    class CounterProxy(prometheus_client.Counter):
        def set(self, value):
            """Set counter to the given value."""
            self._value.set(float(value))

    METRICS_AVAIL = True
    METRICS_CONTENT_TYPE, METRICS_CHARSET = prometheus_client.CONTENT_TYPE_LATEST.split('; charset=')
    # initialize metrics
    METRIC_VERSION = prometheus_client.Info('web2ldap_version', 'web2ldap version')
    METRIC_VERSION.info(
        {
            'combined': web2ldap.__about__.__version__,
            'major': str(web2ldap.__about__.__version_info__.major),
            'minor': str(web2ldap.__about__.__version_info__.minor),
            'micro': str(web2ldap.__about__.__version_info__.micro),
        },
    )
    METRIC_SESSION_COUNTER = CounterProxy('web2ldap_session_count', 'Number of sessions since startup')


def w2l_metrics(app):
    """
    Prometheus Python Client - Custom Collector

    https://github.com/prometheus/client_python/blob/master/README.md#custom-collectors
    """
    METRIC_SESSION_COUNTER.set(session_store.sessionCounter)
    app.outf.set_headers(
        web2ldap.app.gui.gen_headers(
            content_type=METRICS_CONTENT_TYPE,
            charset=METRICS_CHARSET,
        )
    )
    app.outf.write_bytes(prometheus_client.generate_latest())
