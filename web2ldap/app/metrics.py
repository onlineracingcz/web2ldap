# -*- coding: utf-8 -*-
"""
web2ldap.app.metrics: Export several metrics with prometheus_client

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

from ..log import logger, EXC_TYPE_COUNTER

try:
    import prometheus_client
except ImportError:
    METRICS_AVAIL = False
    logger.info('prometheus_client not installed => disable metrics!')
else:
    METRICS_AVAIL = True


if METRICS_AVAIL:
    import web2ldapcnf
    import web2ldap.__about__
    from web2ldap.app.session import session_store, cleanUpThread
    from ..ldapsession import LDAPSession
    import web2ldap.app.gui
    import web2ldap.app.handler

    class CounterProxy(prometheus_client.Counter):

        def set(self, value):
            """Set counter to the given value."""
            self._value.set(float(value))


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
    METRIC_SESSION_MAX = prometheus_client.Gauge('web2ldap_sessions_max', 'Maximum number of concurrent sessions allowed')
    METRIC_SESSION_MAX.set(session_store.max_concurrent_sessions)
    METRIC_SESSION_COUNTER = CounterProxy('web2ldap_sessions_total', 'Number of sessions since startup')
    METRIC_SESSION_REMOVED = CounterProxy('web2ldap_sessions_removed', 'Number of sessions removed by clean-up thread')
    METRIC_CMD_COUNT = CounterProxy(
        'web2ldap_cmd_count',
        'Counters for command URLs',
        ['cmd'],
    )
    METRIC_SESSIONS = prometheus_client.Gauge('web2ldap_sessions_current', 'Number of current sessions', ['state'])


def w2l_metrics(app):
    """
    Prometheus Python Client - Custom Collector

    https://github.com/prometheus/client_python/blob/master/README.md#custom-collectors
    """
    METRIC_SESSION_COUNTER.set(session_store.sessionCounter)
    METRIC_SESSION_REMOVED.set(cleanUpThread.removed_sessions)

    for cmd, cmd_ctr in web2ldap.app.handler.COMMAND_COUNT.items():
        METRIC_CMD_COUNT.labels(cmd=cmd).set(cmd_ctr)

    real_session_count = 0
    fresh_session_count = 0
    for k, i in session_store.sessiondict.items():
        if not k.startswith('__'):
            if isinstance(i[1], LDAPSession) and i[1].uri:
                real_session_count += 1
            else:
                fresh_session_count += 1
    METRIC_SESSIONS.labels(state='active').set(real_session_count)
    METRIC_SESSIONS.labels(state='req').set(fresh_session_count)

    # now send back response
    app.outf.set_headers(
        web2ldap.app.gui.gen_headers(
            content_type=METRICS_CONTENT_TYPE,
            charset=METRICS_CHARSET,
        )
    )
    app.outf.write_bytes(prometheus_client.generate_latest())
