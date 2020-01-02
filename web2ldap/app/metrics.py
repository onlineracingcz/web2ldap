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

import threading

import web2ldap.__about__
from web2ldap.app.session import session_store, cleanUpThread
from ..ldapsession import LDAPSession
import web2ldap.app.gui
import web2ldap.app.handler
from ..log import logger, EXC_TYPE_COUNTER

try:
    import prometheus_client.core
except ImportError:
    METRICS_AVAIL = False
    logger.info('prometheus_client not installed => disable metrics!')
else:
    METRICS_AVAIL = True


if METRICS_AVAIL:

    from prometheus_client import REGISTRY
    from prometheus_client.metrics_core import CounterMetricFamily, GaugeMetricFamily, InfoMetricFamily
    from prometheus_client.openmetrics.exposition import generate_latest

    from web2ldap.app.handler import COMMAND_COUNT

    class MetricsCollector:
        """
        Prometheus Python Client - Custom Collector

        https://github.com/prometheus/client_python/blob/master/README.md#custom-collectors
        """

        def _session_counts(self):
            real_session_count = 0
            fresh_session_count = 0
            for k, i in session_store.sessiondict.items():
                if not k.startswith('__'):
                    if isinstance(i[1], LDAPSession) and i[1].uri:
                        real_session_count += 1
                    else:
                        fresh_session_count += 1
            sessions = GaugeMetricFamily(
                'web2ldap_sessions',
                'Number of sessions',
                labels=('type',),
            )
            sessions.add_metric(('active',), real_session_count)
            sessions.add_metric(('req',), fresh_session_count)
            sessions.add_metric(('max',), session_store.max_concurrent_sessions)
            sessions.add_metric(('total',), session_store.sessionCounter)
            sessions.add_metric(('removed',), cleanUpThread.removed_sessions)
            return sessions

        def _error_counts(self):
            excs = CounterMetricFamily(
                'web2ldap_error',
                'Number of unhandled exceptions',
                labels=('type',),
            )
            for exc_class_name, exc_ctr in EXC_TYPE_COUNTER.items():
                excs.add_metric((exc_class_name,), exc_ctr)
            return excs

        def _cmd_counts(self):
            cmds = CounterMetricFamily(
                'web2ldap_cmd',
                'Counters for command URLs',
                labels=('cmd',),
            )
            for cmd, cmd_ctr in COMMAND_COUNT.items():
                cmds.add_metric((cmd,), cmd_ctr)
            return cmds

        def collect(self):
            info = InfoMetricFamily('web2ldap', 'web2ldap installation information')
            info.add_metric(
                [],
                {
                    'version': web2ldap.__about__.__version__,
                    'major': str(web2ldap.__about__.__version_info__.major),
                    'minor': str(web2ldap.__about__.__version_info__.minor),
                    'patchlevel': str(web2ldap.__about__.__version_info__.micro),
                },
            )
            yield info
            yield self._session_counts()
            yield self._error_counts()
            yield self._cmd_counts()
            yield GaugeMetricFamily('web2ldap_threads', 'Number of current threads', threading.activeCount())
            # end of MetricsCollector.collect()


    METRICS_CONTENT_TYPE, METRICS_CHARSET = prometheus_client.CONTENT_TYPE_LATEST.split('; charset=')

    REGISTRY.register(MetricsCollector())


def w2l_metrics(app):
    """
    Send metrics to client
    """
    app.outf.set_headers(
        web2ldap.app.gui.gen_headers(
            content_type=METRICS_CONTENT_TYPE,
            charset=METRICS_CHARSET,
        )
    )
    app.outf.write_bytes(generate_latest(REGISTRY))
