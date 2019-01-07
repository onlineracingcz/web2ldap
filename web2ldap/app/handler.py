# -*- coding: utf-8 -*-
"""web2ldap.app.handler: base handler

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
import errno
import time
import traceback
import urlparse
import pprint

from ipaddress import ip_address, ip_network

import ldap0
from ldap0.ldapurl import isLDAPUrl

import web2ldap.web.forms
import web2ldap.web.helper
import web2ldap.web.session

import web2ldapcnf
import web2ldapcnf.hosts

# Import the some base modules
import web2ldap.__about__
import web2ldap.ldaputil.base
import web2ldap.ldaputil.dns
import web2ldap.ldapsession
from web2ldap.ldaputil.extldapurl import ExtendedLDAPUrl
from web2ldap.ldapsession import LDAPSession
from web2ldap.log import logger
# Import the application modules
import web2ldap.app.core
import web2ldap.app.gui
import web2ldap.app.cnf
import web2ldap.app.passwd
import web2ldap.app.dit
import web2ldap.app.searchform
import web2ldap.app.locate
import web2ldap.app.search
import web2ldap.app.addmodifyform
import web2ldap.app.add
import web2ldap.app.modify
import web2ldap.app.dds
import web2ldap.app.delete
import web2ldap.app.ldapparams
import web2ldap.app.read
import web2ldap.app.conninfo
import web2ldap.app.login
import web2ldap.app.connect
import web2ldap.app.referral
import web2ldap.app.monitor
import web2ldap.app.groupadm
import web2ldap.app.rename
import web2ldap.app.bulkmod
import web2ldap.app.srvrr
import web2ldap.app.schema.viewer
from web2ldap.app.gui import ExceptionMsg
from web2ldap.app.form import Web2LDAPForm, FORM_CLASS
from web2ldap.app.session import session_store

SocketErrors = (socket.error, socket.gaierror)


SCOPE2COMMAND = {
    None:'search',
    ldap0.SCOPE_BASE:'read',
    ldap0.SCOPE_ONELEVEL:'search',
    ldap0.SCOPE_SUBTREE:'search',
    ldap0.SCOPE_SUBORDINATE:'search',
}

CONNTYPE2URLSCHEME = {
    0: 'ldap',
    1: 'ldap',
    2: 'ldaps',
    3: 'ldapi',
}

SIMPLE_MSG_HTML = """
<html>
  <head>
    <title>Note</title>
  </head>
  <body>
    {message}
  </body>
</html>
"""


def check_access(env, command):
    remote_addr = ip_address(env['REMOTE_ADDR'].decode('ascii'))
    access_allowed = web2ldapcnf.access_allowed.get(
        command.decode('ascii'),
        web2ldapcnf.access_allowed['_']
    )
    for net in access_allowed:
        if remote_addr in ip_network(net, strict=False):
            return True
    return False


class AppHandler:

    def __init__(self, env, outf):
        self.inf = env['wsgi.input']
        self.outf = outf
        self.env = env
        self.script_name = self.env['SCRIPT_NAME']
        self.command, self.sid = self.path_info(env)
        return

    def guess_client_addr(self):
        """
        Guesses the host name or IP address of the HTTP client by looking
        at various HTTP headers mapped to CGI-BIN environment.
        """
        return self.env.get(
            'FORWARDED_FOR',
            self.env.get(
                'HTTP_X_FORWARDED_FOR',
                self.env.get(
                    'HTTP_X_REAL_IP',
                    self.env.get(
                        'REMOTE_HOST',
                        self.env.get('REMOTE_ADDR', None)))))

    def log_exception(self, ls):
        """
        Write an exception with environment vars, LDAP connection data
        and Python traceback to error log
        """
        # Get exception instance and traceback info
        exc_obj, exc_value, exc_traceback = sys.exc_info()
        # Signals are raised again to trigger handling in main process
        logentry = [
            '------------------- Unhandled error -------------------',
            'web2ldap version: %s' % web2ldap.__about__.__version__,
            'LDAPSession instance: %r' % (ls),
        ]
        if ls:
            # Log the LDAPSession object attributes
            logentry.append(pprint.pformat(ls.__dict__))
            # Log rootDSE attributes as LDIF
            logentry.append(pprint.pformat(ls.rootDSE.data))
        # Log all environment vars
        logentry.append(pprint.pformat(sorted(self.env.items())))
        logentry.append(''.join(traceback.format_exception(exc_obj, exc_value, exc_traceback, 20)))
        # Write the log entry
        logger.error(os.linesep.join(logentry))
        # Avoid memory leaks
        exc_obj = exc_value = exc_traceback = None
        del exc_obj
        del exc_value
        del exc_traceback
        return # log_exception()

    def dispatch(self, connLDAPUrl, ls, dn):
        """Execute function for self.command"""
        assert isinstance(dn, unicode), TypeError("Argument 'dn' must be unicode, was %r" % (dn))
        if self.command == 'searchform':
            web2ldap.app.searchform.w2l_searchform(self.sid, self.outf, self.command, self.form, ls, dn)
        elif self.command == 'search':
            web2ldap.app.search.w2l_Search(self.sid, self.outf, self.command, self.form, ls, dn, connLDAPUrl)
        elif self.command == 'add':
            web2ldap.app.add.w2l_Add(self.sid, self.outf, self.command, self.form, ls, dn)
        elif self.command == 'modify':
            web2ldap.app.modify.w2l_modify(self.sid, self.outf, self.command, self.form, ls, dn)
        elif self.command == 'dds':
            web2ldap.app.dds.w2l_dds(self.sid, self.outf, self.command, self.form, ls, dn)
        elif self.command == 'bulkmod':
            web2ldap.app.bulkmod.w2l_bulkmod(self.sid, self.outf, self.command, self.form, ls, dn, connLDAPUrl)
        elif self.command == 'delete':
            web2ldap.app.delete.w2l_Delete(self.sid, self.outf, self.command, self.form, ls, dn, connLDAPUrl)
        elif self.command == 'dit':
            web2ldap.app.dit.w2l_dit(self.sid, self.outf, self.command, self.form, ls, dn)
        elif self.command == 'rename':
            web2ldap.app.rename.w2l_rename(self.sid, self.outf, self.command, self.form, ls, dn)
        elif self.command == 'passwd':
            web2ldap.app.passwd.w2l_Passwd(self.sid, self.outf, self.command, self.form, ls, dn, connLDAPUrl)
        elif self.command == 'read':
            web2ldap.app.read.w2l_Read(
                self.sid, self.outf, self.command, self.form, ls, dn,
                wanted_attrs={False:connLDAPUrl.attrs, True:[]}[connLDAPUrl.attrs is None],
            )
        elif self.command == 'conninfo':
            web2ldap.app.conninfo.w2l_ConnInfo(self.sid, self.outf, self.command, self.form, ls, dn)
        elif self.command == 'ldapparams':
            web2ldap.app.ldapparams.w2l_LDAPParameters(self.sid, self.outf, self.command, self.form, ls, dn)
        elif self.command == 'login':
            web2ldap.app.login.w2l_login(
                self.sid, self.outf, 'searchform', self.form, ls, dn, connLDAPUrl,
                self.form.getInputValue('login_search_root', [ls.getSearchRoot(dn)])[0],
                login_default_mech=connLDAPUrl.saslMech,
            )
        elif self.command == 'groupadm':
            web2ldap.app.groupadm.w2l_groupadm(self.sid, self.outf, self.command, self.form, ls, dn)
        elif self.command == 'oid':
            web2ldap.app.schema.viewer.w2l_DisplaySchemaElement(self.sid, self.outf, self.command, self.form, ls, dn)
        return # dispatch()

    @staticmethod
    def path_info(env):
        # Extract the command from PATH_INFO env var
        path_info = env.get('PATH_INFO', '/')[1:]
        if not path_info:
            c, s = '', ''
        else:
            # Work around broken web servers which adds the script name
            # to path info as well
            script_name = env['SCRIPT_NAME']
            if path_info.startswith(script_name):
                path_info = path_info[len(script_name):]
            try:
                c, s = path_info.split('/', 1)
            except ValueError:
                c, s = path_info, ''
        return c, s # path_info()

    def simple_msg(self, msg):
        """
        Output HTML text.
        """
        web2ldap.app.gui.Header(self.outf, self.form, 'text/html', self.form.accept_charset)
        self.outf.write(SIMPLE_MSG_HTML.format(message=msg))

    def url_redirect(
            self,
            redirect_msg,
            link_text='Continue&gt;&gt;',
            refresh_time=3,
            target_url=None,
        ):
        """
        Outputs HTML text with redirecting <head> section.
        """
        target_url = target_url or self.script_name
        url_redirect_template_str = web2ldap.app.gui.ReadTemplate(
            self.form, None, None, u'redirect',
            tmpl_filename=web2ldapcnf.redirect_template,
        )
        if refresh_time:
            message_class = 'ErrorMessage'
        else:
            message_class = 'SuccessMessage'
        web2ldap.app.gui.Header(self.outf, self.form, 'text/html', self.form.accept_charset)
        # Write out stub body with just a short redirect HTML snippet
        self.outf.write(
            url_redirect_template_str.format(
                refresh_time=refresh_time,
                target_url=target_url,
                message_class=message_class,
                redirect_msg=self.form.utf2display(redirect_msg),
                link_text=link_text,
            )
        )
        return # url_redirect()

    def _handle_urlredirect(self):
        # accept configured trusted redirect targets no matter what
        redirect_ok = self.form.query_string in web2ldapcnf.good_redirect_targets
        if not redirect_ok:
            # Check for valid target URL syntax
            try:
                tu = urlparse.urlparse(self.form.query_string)
            except:
                redirect_ok = False
                error_msg = u'Rejected non-parseable redirect URL!'
            else:
                redirect_ok = True
                # further checks
                if not tu or not tu.scheme or not tu.netloc:
                    redirect_ok = False
                    error_msg = u'Rejected malformed/suspicious redirect URL!'
                # Check for valid session
                if self.sid not in session_store.sessiondict:
                    redirect_ok = False
                    error_msg = u'Rejected redirect without session-ID!'
        # finally send return redirect to browser
        if redirect_ok:
            # URL redirecting has absolutely nothing to do with rest
            self.url_redirect(
                u'Redirecting to %s...' % (
                    self.form.query_string.decode(self.form.accept_charset)
                ),
                refresh_time=0,
                target_url=self.form.query_string,
            )
        else:
            self.url_redirect(error_msg)
        return # end of handle_urlredirect()

    def _new_session(self):
        """
        create new session
        """
        self.sid = session_store.newSession(self.env)
        ls = LDAPSession(
            self.guess_client_addr(),
            web2ldapcnf.ldap_trace_level,
            web2ldapcnf.ldap_cache_ttl,
        )
        ls.cookie = self.form.setNewCookie(str(id(ls)))
        session_store.storeSession(self.sid, ls)
        return ls # end of _get_session()

    def _get_session(self):
        """
        Restore old or initialize new web session object
        """
        if self.sid:
            # Session ID given => try to restore old session
            try:
                last_session_timestamp, _ = session_store.sessiondict[self.sid]
            except KeyError:
                pass
            ls = session_store.retrieveSession(self.sid, self.env)
            if not isinstance(ls, LDAPSession):
                raise web2ldap.app.session.InvalidSessionInstance()
            if ls.cookie:
                # Check whether HTTP_COOKIE contains the cookie of this particular session
                cookie_name = ''.join((self.form.cookie_name_prefix, str(id(ls))))
                if not (
                        cookie_name in self.form.cookies and
                        ls.cookie[cookie_name].value == self.form.cookies[cookie_name].value
                    ):
                    raise web2ldap.app.session.WrongSessionCookie()
            if web2ldapcnf.session_paranoid and \
               self.current_access_time-last_session_timestamp > web2ldapcnf.session_paranoid:
                # Store session with new session ID
                self.sid = session_store.renameSession(self.sid, self.env)
        else:
            ls = self._new_session()
        return ls # end of _get_session()

    def _handle_del_sid(self):
        """
        if del_sid form parameter is present then delete the obsolete session
        """
        try:
            del_sid = self.form.field['delsid'].value[0]
        except IndexError:
            pass
        else:
            try:
                old_ls = session_store.retrieveSession(del_sid, self.env)
            except web2ldap.web.session.SessionException:
                pass
            else:
                # Remove session cookie
                self.form.unsetCookie(old_ls.cookie)
            # Explicitly remove old session
            session_store.deleteSession(del_sid)
        return # end of _handle_del_sid()

    def _get_ldapconn_params(self):
        """
        Extract parameters either from LDAP URL in query string or real form input
        """
        if isLDAPUrl(self.form.query_string):
            # Extract the connection parameters from a LDAP URL
            try:
                input_ldapurl = ExtendedLDAPUrl(self.form.query_string)
            except ValueError as e:
                raise web2ldap.app.core.ErrorExit(u'Error parsing LDAP URL: %s.' % (
                    self.form.utf2display(unicode(str(e)))
                ))
            else:
                self.command = self.command or SCOPE2COMMAND[input_ldapurl.scope]
                if self.command in ('search', 'read'):
                    input_ldapurl.filterstr = input_ldapurl.filterstr or '(objectClass=*)'
                # Re-instantiate form based on command derived from LDAP URL
                self.form = FORM_CLASS.get(self.command, Web2LDAPForm)(self.inf, self.env)

        else:
            # Extract the connection parameters from form fields
            self.form.getInputFields(ignoreEmptyFields=0)
            self._handle_del_sid()
            if 'ldapurl' in self.form.inputFieldNames:
                # One form parameter with LDAP URL
                ldap_url_input = self.form.field['ldapurl'].value[0]
                try:
                    input_ldapurl = ExtendedLDAPUrl(ldap_url_input.encode('ascii'))
                except ValueError as e:
                    raise web2ldap.app.core.ErrorExit(
                        u'Error parsing LDAP URL: %s.' % (unicode(e, self.form.accept_charset))
                    )
            else:
                input_ldapurl = ExtendedLDAPUrl()
                conntype = int(self.form.getInputValue('conntype', [0])[0])
                input_ldapurl.urlscheme = CONNTYPE2URLSCHEME[conntype]
                input_ldapurl.hostport = self.form.getInputValue('host', [None])[0]
                input_ldapurl.x_startTLS = str(web2ldap.ldapsession.START_TLS_REQUIRED * (conntype == 1))

        # Separate parameters for dn, who, cred and scope
        # have predecence over parameters specified in LDAP URL

        dn = self.form.getInputValue('dn', [input_ldapurl.dn.decode(self.form.accept_charset)])[0]

        who = self.form.getInputValue('who', [None])[0]
        if who is None:
            if input_ldapurl.who is not None:
                who = input_ldapurl.who.decode(self.form.accept_charset)
        else:
            input_ldapurl.who = who.encode(self.form.accept_charset)

        cred = self.form.getInputValue('cred', [None])[0]
        if cred is None:
            if input_ldapurl.cred is not None:
                cred = input_ldapurl.cred.decode(self.form.accept_charset)
        else:
            input_ldapurl.cred = cred.encode(self.form.accept_charset)

        assert isinstance(input_ldapurl.dn, bytes), TypeError(
            "Type of 'input_ldapurl.dn' must be bytes, was %r" % (input_ldapurl.dn)
        )
        assert input_ldapurl.who is None or isinstance(input_ldapurl.who, bytes), TypeError(
            "Type of 'input_ldapurl.who' must be bytes, was %r" % (input_ldapurl.who)
        )
        assert input_ldapurl.cred is None or isinstance(input_ldapurl.cred, bytes), TypeError(
            "Type of 'input_ldapurl.cred' must be bytes, was %r" % (input_ldapurl.cred)
        )
        assert isinstance(dn, unicode), TypeError("Argument 'dn' must be unicode, was %r" % (dn))
        assert who is None or isinstance(who, unicode), TypeError(
            "Type of 'who' must be unicode, was %r" % (who)
        )
        assert cred is None or isinstance(cred, unicode), TypeError(
            "Type of 'cred' must be unicode, was %r" % (cred)
        )

        if not web2ldap.ldaputil.base.is_dn(dn):
            raise web2ldap.app.core.ErrorExit(u'Invalid DN.')

        scope_str = self.form.getInputValue(
            'scope',
            [
                {False:str(input_ldapurl.scope), True:''}[input_ldapurl.scope is None]
            ]
        )[0]
        if scope_str:
            input_ldapurl.scope = int(scope_str)
        else:
            input_ldapurl.scope = None

        return input_ldapurl, dn, who, cred # end of _get_ldapconn_params()

    def run(self):
        """
        Really process the request
        """

        self.current_access_time = time.time()

        ls = None
        dn = None

        #------------------------------------------------------------------------
        # Main try-except block for catching and logging all unhandled exceptions
        #------------------------------------------------------------------------

        try:

            # check for valid command
            if self.command not in FORM_CLASS:
                # We still need a basic form here
                self.form = Web2LDAPForm(self.inf, self.env)
                self.url_redirect(
                    u'Invalid web2ldap command: %s' % (self.command.decode(self.form.accept_charset))
                )
                return

            self.form = FORM_CLASS[self.command](self.inf, self.env)
            self.outf = self.form.outFileObject(self.outf)

            #---------------------------------------------------------------
            # try-except block for gracefully exception handling in the UI
            #---------------------------------------------------------------

            try:

                # Check access here
                if not check_access(self.env, self.command):
                    raise web2ldap.app.core.ErrorExit(u'Access denied.')

                # handle the early-exit commands
                if self.command == 'urlredirect':
                    if isLDAPUrl(self.form.query_string):
                        self.command = ''
                    else:
                        self._handle_urlredirect()
                        return
                elif self.command == 'monitor':
                    # Output simple monitor page. Does not require session handling.
                    web2ldap.app.monitor.w2l_monitor(self.outf, self.command, self.form, self.env)
                    return
                elif self.command == 'locate':
                    self.form.getInputFields(ignoreEmptyFields=0)
                    web2ldap.app.locate.w2l_Locate(self.outf, self.command, self.form, self.env)
                    return
                elif self.command == '':
                    # New connect => remove old session if necessary
                    session_store.deleteSession(self.sid)
                    # Just output a connect form if there was not query string
                    if not self.form.query_string:
                        web2ldap.app.connect.w2l_connect(self.outf, self.form, self.env)
                        return

                self.ls = ls = self._get_session()

                if self.command == 'disconnect':
                    # Remove session cookie
                    self.form.unsetCookie(ls.cookie)
                    # Explicitly remove old session
                    session_store.deleteSession(self.sid)
                    # Redirect to start page to avoid people bookmarking disconnect URL
                    self.url_redirect(u'Disconnecting...', refresh_time=0)
                    return

                input_ldapurl, dn, who, cred = self._get_ldapconn_params()

                self.command = self.command or {
                    None: 'searchform',
                    ldap0.SCOPE_BASE: 'read',
                    ldap0.SCOPE_ONELEVEL: 'search',
                    ldap0.SCOPE_SUBTREE: 'search',
                }[input_ldapurl.scope]

                #-------------------------------------------------
                # Connect to LDAP server
                #-------------------------------------------------

                if input_ldapurl.hostport is not None and \
                   input_ldapurl.hostport == '' and \
                   input_ldapurl.urlscheme == 'ldap' and \
                   ls.uri is None:
                    # Force a SRV RR lookup for dc-style DNs,
                    # create list of URLs to connect to
                    dns_srv_rrs = web2ldap.ldaputil.dns.dcDNSLookup(dn)
                    initializeUrl_list = [
                        ExtendedLDAPUrl(urlscheme='ldap', hostport=host, dn=dn).initializeUrl()
                        for host in dns_srv_rrs
                    ]
                    if not initializeUrl_list:
                        # No host specified in user's input
                        session_store.deleteSession(self.sid)
                        web2ldap.app.connect.w2l_connect(
                            self.outf, self.form, self.env,
                            Msg='Connect failed',
                            ErrorMsg='No host specified.'
                        )
                        return
                    elif len(initializeUrl_list) == 1:
                        initializeUrl = initializeUrl_list[0]
                    else:
                        web2ldap.app.srvrr.w2l_chasesrvrecord(
                            self.sid, self.outf, self.command, self.form, ls, dn,
                            initializeUrl_list
                        )
                        return
                elif not input_ldapurl.hostport is None:
                    initializeUrl = str(input_ldapurl.initializeUrl()[:])
                else:
                    initializeUrl = None

                if initializeUrl and (
                        ls is None or ls.uri is None or initializeUrl != ls.uri
                    ):
                    # Delete current LDAPSession instance and create new
                    del ls
                    ls = LDAPSession(
                        self.guess_client_addr(),
                        web2ldapcnf.ldap_trace_level,
                        web2ldapcnf.ldap_cache_ttl,
                    )
                    ls.cookie = self.form.setNewCookie(str(id(ls)))
                    session_store.storeSession(self.sid, ls)
                    # Check whether access to target LDAP server is allowed
                    if web2ldapcnf.hosts.restricted_ldap_uri_list and \
                       initializeUrl not in web2ldap.app.core.ldap_uri_list_check_dict:
                        raise web2ldap.app.core.ErrorExit(u'Only pre-configured LDAP servers allowed.')
                    startTLSextop = input_ldapurl.get_starttls_extop(
                        web2ldap.app.cnf.GetParam(input_ldapurl, 'starttls', web2ldap.ldapsession.START_TLS_NO)
                    )
                    # Connect to new specified host
                    ls.open(
                        initializeUrl,
                        web2ldap.app.cnf.GetParam(input_ldapurl, 'timeout', -1),
                        startTLSextop,
                        self.env,
                        web2ldap.app.cnf.GetParam(input_ldapurl, 'session_track_control', 0),
                        tls_options=web2ldap.app.cnf.GetParam(input_ldapurl, 'tls_options', {}),
                    )
                    # Set host-/backend-specific timeout
                    ls.timeout = ls.l.timeout = web2ldap.app.cnf.GetParam(ls, 'timeout', 60)
                    # Store session data in case anything goes wrong after here
                    # to give the exception handler a good chance
                    session_store.storeSession(self.sid, ls)

                if ls.uri is None:
                    session_store.deleteSession(self.sid)
                    web2ldap.app.connect.w2l_connect(
                        self.outf, self.form, self.env,
                        Msg='Connect failed',
                        ErrorMsg='No valid LDAP connection.'
                    )
                    return

                # Store session data in case anything goes wrong after here
                # to give the exception handler a good chance
                session_store.storeSession(self.sid, ls)

                login_mech = self.form.getInputValue(
                    'login_mech',
                    [input_ldapurl.saslMech or '']
                )[0].upper() or None

                if who is not None and cred is None and login_mech not in ldap0.sasl.SASL_NONINTERACTIVE_MECHS:
                    # first ask for password in a login form
                    ls.setDN(dn)
                    web2ldap.app.login.w2l_login(
                        self.sid, self.outf, self.command, self.form, ls, dn, input_ldapurl,
                        self.form.getInputValue('login_search_root', [ls.getSearchRoot(dn)])[0],
                        login_msg='',
                        who=who, relogin=0, nomenu=1,
                        login_default_mech=input_ldapurl.saslMech
                    )
                    return

                elif (who is not None and cred is not None) or login_mech in ldap0.sasl.SASL_NONINTERACTIVE_MECHS:
                    # real bind operation
                    login_search_root = self.form.getInputValue('login_search_root', [None])[0]
                    if who is not None and not web2ldap.ldaputil.base.is_dn(who) and login_search_root is None:
                        login_search_root = ls.getSearchRoot(dn)
                    try:
                        ls.bind(
                            who,
                            cred or '',
                            login_mech,
                            ''.join((
                                self.form.getInputValue('login_authzid_prefix', [''])[0],
                                self.form.getInputValue('login_authzid', [input_ldapurl.saslAuthzId or ''])[0],
                            )) or None,
                            self.form.getInputValue('login_realm', [input_ldapurl.saslRealm])[0],
                            binddn_filtertemplate=self.form.getInputValue('login_filterstr', [ur'(uid=%s)'])[0],
                            whoami_filtertemplate=web2ldap.app.cnf.GetParam(ls, 'binddnsearch', ur'(uid=%s)'),
                            loginSearchRoot=login_search_root,
                        )
                    except ldap0.NO_SUCH_OBJECT as e:
                        ls.setDN(dn)
                        web2ldap.app.login.w2l_login(
                            self.sid, self.outf, self.command, self.form, ls, dn,
                            input_ldapurl, login_search_root,
                            login_msg=web2ldap.app.gui.LDAPError2ErrMsg(e, self.form, ls.charset),
                            who=who, relogin=1
                        )
                        return
                else:
                    # anonymous access
                    ls.getRootDSE()

                ls.setDN(dn)

                # Check for valid LDAPSession and connection to provide reasonable
                # error message instead of logging exception in case user is playing
                # with manually generated URLs
                if not isinstance(ls, LDAPSession) or ls.uri is None:
                    self.url_redirect(u'No valid LDAP connection!')
                    return
                # Store session data in case anything goes wrong after here
                # to give the exception handler a good chance
                session_store.storeSession(self.sid, ls)

                # Execute the command module
                try:
                    self.dispatch(input_ldapurl, ls, dn)
                except ldap0.SERVER_DOWN:
                    # Try to reconnect to LDAP server and retry action
                    ls.l.reconnect(ls.uri)
                    self.dispatch(input_ldapurl, ls, dn)
                else:
                    # Store current session
                    session_store.storeSession(self.sid, ls)

            except web2ldap.web.forms.FormException as e:
                if ls is None:
                    dn = None
                else:
                    dn = ls.__dict__.get('_dn', None)
                try:
                    e_msg = unicode(str(e))
                except UnicodeDecodeError:
                    e_msg = unicode(repr(str(e)))
                ExceptionMsg(
                    self.sid, self.outf, self.command, self.form, ls, dn,
                    u'Error parsing form',
                    u'Error parsing form: %s' % (self.form.utf2display(e_msg)),
                )

            except ldap0.SERVER_DOWN as e:
                # Server is down and reconnecting impossible => remove session
                session_store.deleteSession(self.sid)
                # Redirect to entry page
                web2ldap.app.connect.w2l_connect(
                    self.outf, self.form, self.env,
                    Msg='Connect failed',
                    ErrorMsg='Connecting to %s impossible!<br>%s' % (
                        self.form.utf2display((initializeUrl or '-').decode('utf-8')),
                        web2ldap.app.gui.LDAPError2ErrMsg(e, self.form, ls.charset)
                    )
                )

            except ldap0.NO_SUCH_OBJECT as e:

                if __debug__:
                    self.log_exception(ls)

                host_list = web2ldap.ldaputil.dns.dcDNSLookup(dn)
                if (not host_list) or (ExtendedLDAPUrl(ls.uri).hostport in host_list):
                    # Did not find another LDAP server for this naming context
                    try:
                        if isinstance(e.args[0], dict) and e.args[0].has_key('matched'):
                            new_dn = unicode(e.args[0]['matched'], ls.charset)
                        else:
                            new_dn = dn
                    except IndexError:
                        new_dn = dn
                    ExceptionMsg(
                        self.sid, self.outf, self.command, self.form, ls, new_dn,
                        u'No such object',
                        web2ldap.app.gui.LDAPError2ErrMsg(
                            e, self.form, ls.charset,
                            template='{error_msg}<br>%s<br>{matched_dn}' % (
                                web2ldap.app.gui.DisplayDN(self.sid, self.form, ls, dn)
                            )
                        )
                    )
                else:
                    # Found LDAP server for this naming context via DNS SRV RR
                    web2ldap.app.srvrr.w2l_chasesrvrecord(self.sid, self.outf, self.command, self.form, ls, dn, host_list)

            except (ldap0.PARTIAL_RESULTS, ldap0.REFERRAL) as e:
                web2ldap.app.referral.w2l_chasereferral(self.sid, self.outf, self.command, self.form, ls, dn, e)

            except (ldap0.INSUFFICIENT_ACCESS, ldap0.STRONG_AUTH_REQUIRED) as e:
                web2ldap.app.login.w2l_login(
                    self.sid, self.outf, self.command, self.form, ls, dn,
                    input_ldapurl,
                    self.form.getInputValue('login_search_root', [ls.getSearchRoot(dn)])[0],
                    who='',
                    login_msg=web2ldap.app.gui.LDAPError2ErrMsg(e, self.form, ls.charset), relogin=1
                )

            except (
                    ldap0.INAPPROPRIATE_AUTH,
                    ldap0.INVALID_CREDENTIALS,
                    web2ldap.ldapsession.USERNAME_NOT_FOUND,
                ) as e:
                web2ldap.app.login.w2l_login(
                    self.sid, self.outf, self.command, self.form, ls, dn,
                    input_ldapurl,
                    self.form.getInputValue('login_search_root', [ls.getSearchRoot(dn)])[0],
                    login_msg=web2ldap.app.gui.LDAPError2ErrMsg(e, self.form, ls.charset),
                    who=who, relogin=1
                )

            except web2ldap.ldapsession.INVALID_SIMPLE_BIND_DN as e:
                web2ldap.app.login.w2l_login(
                    self.sid, self.outf, self.command, self.form, ls, dn,
                    input_ldapurl,
                    self.form.getInputValue('login_search_root', [ls.getSearchRoot(dn)])[0],
                    login_msg=self.form.utf2display(unicode(e)),
                    who=who, relogin=1
                )

            except web2ldap.ldapsession.PWD_EXPIRATION_WARNING as e:
                # Setup what's required to the case command=='passwd'
                ls.setDN(dn or e.who)
                self.form.addField(
                    web2ldap.web.forms.Select(
                        'passwd_scheme',
                        u'Password hash scheme',
                        1,
                        options=web2ldap.app.passwd.available_hashtypes,
                        default=web2ldap.app.passwd.available_hashtypes[-1],
                    )
                )
                self.form.addField(
                    web2ldap.web.forms.Checkbox(
                        'passwd_ntpasswordsync',
                        u'Sync ntPassword for Samba',
                        1,
                        default="yes",
                        checked=1,
                    )
                )
                self.form.addField(
                    web2ldap.web.forms.Checkbox(
                        'passwd_settimesync',
                        u'Sync password setting times',
                        1,
                        default="yes",
                        checked=1,
                    )
                )
                # Directly generate the change password form
                web2ldap.app.passwd.PasswdForm(
                    self.sid, self.outf, self.form, ls, dn,
                    None, None, e.who.decode(ls.charset), None,
                    'Password change needed',
                    self.form.utf2display(
                        u'Password will expire in %s!' % (
                            web2ldap.app.gui.ts2repr(
                                web2ldap.app.schema.syntaxes.Timespan.time_divisors,
                                u' ',
                                e.timeBeforeExpiration,
                            )
                        )
                    ),
                )

            except web2ldap.ldapsession.PasswordPolicyException as e:
                # Setup what's required to the case command=='passwd'
                ls.setDN(dn or e.who)
                self.form.addField(
                    web2ldap.web.forms.Select(
                        'passwd_scheme',
                        u'Password hash scheme',
                        1,
                        options=web2ldap.app.passwd.available_hashtypes,
                        default=web2ldap.app.passwd.available_hashtypes[-1],
                    )
                )
                self.form.addField(
                    web2ldap.web.forms.Checkbox(
                        'passwd_ntpasswordsync',
                        u'Sync ntPassword for Samba',
                        1,
                        default="yes",
                        checked=1,
                    )
                )
                self.form.addField(
                    web2ldap.web.forms.Checkbox(
                        'passwd_settimesync',
                        u'Sync password setting times',
                        1,
                        default="yes",
                        checked=1,
                    )
                )
                # Directly generate the change password form
                web2ldap.app.passwd.PasswdForm(
                    self.sid, self.outf, self.form, ls, dn,
                    None, None,
                    e.who.decode(ls.charset), None,
                    'Password change needed',
                    self.form.utf2display(unicode(e.desc))
                )

            except web2ldap.ldapsession.USERNAME_NOT_UNIQUE as e:
                login_search_root = self.form.getInputValue('login_search_root', [ls.getSearchRoot(dn)])[0]
                web2ldap.app.login.w2l_login(
                    self.sid, self.outf, self.command, self.form, ls, dn,
                    input_ldapurl,
                    login_search_root,
                    login_msg=web2ldapcnf.command_link_separator.join([
                        web2ldap.app.gui.LDAPError2ErrMsg(e, self.form, ls.charset),
                        self.form.applAnchor(
                            'search', 'Show', self.sid,
                            [
                                ('dn', login_search_root),
                                ('scope', str(ldap0.SCOPE_SUBTREE)),
                                ('filterstr', web2ldap.app.cnf.GetParam(ls, 'binddnsearch', r'(uid=%s)').replace('%s', who))
                            ]
                        ),
                    ]),
                    who=who, relogin=1
                )

            except ldap0.TIMEOUT as e:
                if __debug__:
                    self.log_exception(ls)
                ExceptionMsg(
                    self.sid, self.outf, self.command, self.form, ls, dn,
                    u'LDAP timeout',
                    u'Timeout of %d secs exceeded.' % (web2ldap.app.cnf.GetParam(ls, 'timeout', -1))
                )

            except (
                    ldap0.DECODING_ERROR,
                    ldap0.LOCAL_ERROR,
                    ldap0.PARAM_ERROR,
                    ldap0.OTHER,
                    ldap0.USER_CANCELLED,
                ) as e:
                self.log_exception(ls)
                ExceptionMsg(
                    self.sid, self.outf, self.command, self.form, ls, dn,
                    u'LDAP exception',
                    web2ldap.app.gui.LDAPError2ErrMsg(e, self.form, ls.charset)
                )

            except ldap0.LDAPError as e:
                if __debug__:
                    self.log_exception(ls)
                ExceptionMsg(
                    self.sid, self.outf, self.command, self.form, ls, dn,
                    u'LDAP exception',
                    web2ldap.app.gui.LDAPError2ErrMsg(e, self.form, ls.charset)
                )

            except UnicodeError as e:
                if __debug__:
                    self.log_exception(ls)
                ExceptionMsg(
                    self.sid, self.outf, self.command, self.form, None, None,
                    u'Unicode Error',
                    self.form.utf2display(unicode(str(e), 'ascii'))
                )

            except SocketErrors as e:
                try:
                    socket_errno = e.errno
                except AttributeError:
                    socket_errno = None
                if not socket_errno in [errno.EPIPE, errno.ECONNRESET]:
                    if __debug__:
                        self.log_exception(ls)
                    ExceptionMsg(
                        self.sid, self.outf, self.command, self.form, None, None,
                        u'Socket Error', self.form.utf2display(unicode(str(e), 'ascii'))
                    )
                raise e

            except IOError as e:
                if __debug__:
                    self.log_exception(ls)
                ExceptionMsg(
                    self.sid, self.outf, self.command, self.form, ls, dn,
                    u'I/O Error',
                    'See error log for details',
                )

            except web2ldap.app.core.ErrorExit as e:
                ExceptionMsg(
                    self.sid, self.outf, self.command, self.form, ls, dn,
                    u'Error', e.Msg,
                )

            except web2ldap.web.session.MaxSessionCountExceeded:
                self.simple_msg('Too many web sessions! Try later...')

            except web2ldap.web.session.InvalidSessionId:
                self.url_redirect(u'Session ID not found.')
                return

            except web2ldap.web.session.SessionHijacked:
                if __debug__:
                    self.log_exception(ls)
                self.url_redirect(u'Session hijacking detected. Access denied!')
                return

            except web2ldap.app.session.InvalidSessionInstance:
                self.url_redirect(u'LDAPSession not properly initialized.')
                return

            except web2ldap.app.session.WrongSessionCookie:
                if __debug__:
                    self.log_exception(ls)
                self.url_redirect(u'Session hijacking detected by wrong cookie. Access denied!')
                return

            except web2ldap.web.session.SessionException:
                self.url_redirect(u'Other session handling error.')
                return

        except web2ldap.web.forms.InvalidRequestMethod:
            self.simple_msg('Invalid request method!')

        except Exception:
            # Log unhandled exceptions
            self.log_exception(ls)

        return # run()
