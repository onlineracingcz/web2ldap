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

from __future__ import absolute_import

import os
import time
import socket
import threading
import pwd

import web2ldapcnf

import web2ldap.__about__
import web2ldap.app.gui
from web2ldap.app.session import session_store, cleanUpThread
from web2ldap.utctime import strftimeiso8601
from ..ldapsession import LDAPSession

MONITOR_TEMPLATE = """
<h1>Monitor</h1>

<h2>System information</h2>

<table summary="System information">
  <tr>
    <td>web2ldap version:</td>
    <td>{text_version}</td>
  </tr>
  <tr>
    <td>Hostname:</td>
    <td>{text_sysfqdn}</td>
  </tr>
  <tr>
    <td>PID / PPID:</td>
    <td>{int_pid} / {int_ppid}</td>
  </tr>
  <tr>
    <td>UID:</td>
    <td>{text_username} ({int_uid})</td>
  </tr>
</table>

<h3>Time information</h3>
<table summary="Time information">
  <tr>
    <td>Current time:</td>
    <td>{text_currenttime}</td>
  </tr>
  <tr>
    <td>Startup time:</td>
    <td>{text_startuptime}</td>
  </tr>
  <tr>
    <td>Uptime:</td>
    <td>{text_uptime}</td>
  </tr>
</table>

<h3>{int_numthreads:d} active threads:</h3>
<ul>
  {text_threadlist}
</ul>

<h2>Session counters</h2>
<table summary="Session counters">
  <tr>
    <td>Web sessions initialized:</td>
    <td>{int_sessioncounter:d}</td>
  </tr>
  <tr>
    <td>Max. concurrent sessions:</td>
    <td>{int_maxconcurrentsessions:d}</td>
  </tr>
  <tr>
    <td>Sessions removed after timeout:</td>
    <td>{int_removedsessions:d}</td>
  </tr>
  <tr>
    <td>Web session limit:</td>
    <td>{int_sessionlimit:d}</td>
  </tr>
  <tr>
    <td>Web session limit per remote IP:</td>
    <td>{int_sessionlimitperip:d}</td>
  </tr>
  <tr>
    <td>Session removal time:</td>
    <td>{int_sessionremoveperiod:d}</td>
  </tr>
  <tr>
    <td>Currently active remote IPs:</td>
    <td>{int_currentnumremoteipaddrs:d}</td>
  </tr>
</table>

<h3>{int_numremoteipaddrs:d} remote IPs seen:</h3>
<table>
  <tr><th>Remote IP</th><th>Count</th><th>Rate</th></tr>
  {text_remoteiphitlist}
</table>

<h2>Active sessions</h2>
"""

MONITOR_CONNECTIONS_TMPL = """
<h3>%d active LDAP connections:</h3>
<table summary="Active LDAP connections">
  <tr>
    <th>Remote IP</th>
    <th>Last access time</th>
    <th>Target URI</th>
    <th>Bound as</th>
  </tr>
  %s
</table>
"""

MONITOR_SESSIONS_JUST_CREATED_TMPL = """
<h3>%d sessions just created:</h3>
<table summary="Sessions not fully initialized">
  <tr>
    <th>Creation time</th>
  </tr>
  %s
</table>
"""


def w2l_Monitor(outf, command, form, env):
    """
    List several general gateway stats
    """

    from .core import STARTUP_TIME

    uptime = (time.time() - STARTUP_TIME) / 60

    posix_uid = os.getuid()
    try:
        posix_username = pwd.getpwuid(posix_uid).pw_name
    except KeyError:
        posix_username = '-/-'

    web2ldap.app.gui.TopSection(
        None, outf, command, form, None, None, 'Monitor',
        web2ldap.app.gui.EntryMainMenu(form, env),
        [],
    )

    outf.write(
        MONITOR_TEMPLATE.format(
            text_version=web2ldap.__about__.__version__,
            text_sysfqdn=socket.getfqdn(),
            int_pid=os.getpid(),
            int_ppid=os.getppid(),
            text_username=form.utf2display(unicode(posix_username)),
            int_uid=posix_uid,
            text_currenttime=strftimeiso8601(time.gmtime(time.time())),
            text_startuptime=strftimeiso8601(time.gmtime(STARTUP_TIME)),
            text_uptime='%02d:%02d' % (int(uptime/60), int(uptime%60)),
            int_numthreads=threading.activeCount(),
            text_threadlist='\n'.join(
                [
                    '<li>%s</li>' % ''.join(
                        [
                            form.utf2display(unicode(repr(t))),
                            ', alive'*t.isAlive(),
                            ', daemon'*t.isDaemon(),
                        ]
                    )
                    for t in threading.enumerate()
                ]
            ),
            int_sessioncounter=session_store.sessionCounter,
            int_maxconcurrentsessions=session_store.max_concurrent_sessions,
            int_removedsessions=cleanUpThread.removed_sessions,
            int_sessionlimit=web2ldapcnf.session_limit,
            int_sessionlimitperip=web2ldapcnf.session_per_ip_limit,
            int_sessionremoveperiod=session_store.session_ttl,
            int_currentnumremoteipaddrs=len(session_store.remote_ip_sessions),
            int_numremoteipaddrs=len(session_store.remote_ip_counter),
            text_remoteiphitlist='\n'.join(
                [
                    '<tr><td>%s</td><td>%d</td><td>%0.4f</td></tr>' % (
                        form.utf2display(ip.decode('ascii')),
                        count,
                        float(count/uptime),
                    )
                    for ip, count in session_store.remote_ip_counter.most_common()
                ]
            ),
        )
    )

    if session_store.sessiondict:

        real_ldap_sessions = []
        fresh_ldap_sessions = []
        for k, i in session_store.sessiondict.items():
            if not k.startswith('__'):
                if isinstance(i[1], LDAPSession) and i[1].uri:
                    real_ldap_sessions.append((k, i))
                else:
                    fresh_ldap_sessions.append((k, i))

        if real_ldap_sessions:
            outf.write(
                MONITOR_CONNECTIONS_TMPL % (
                    len(real_ldap_sessions),
                    '\n'.join([
                        '<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>'.format(
                            form.utf2display(i[1].onBehalf.decode('ascii') or u'unknown'),
                            strftimeiso8601(time.gmtime(i[0])),
                            form.utf2display(i[1].uri.decode('ascii') or u'no connection'),
                            form.utf2display(i[1].who or u'anonymous'),
                        )
                        for k, i in real_ldap_sessions
                    ]),
                )
            )

        if fresh_ldap_sessions:
            outf.write(
                MONITOR_SESSIONS_JUST_CREATED_TMPL % (
                    len(fresh_ldap_sessions),
                    '\n'.join([
                        '<tr><td>{}</td></tr>'.format(strftimeiso8601(time.gmtime(i[0])))
                        for k, i in fresh_ldap_sessions
                    ]),
                )
            )

    else:
        outf.write('No active sessions.\n')

    web2ldap.app.gui.Footer(outf, form)
