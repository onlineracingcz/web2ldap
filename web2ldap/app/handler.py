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
import inspect
import socket
import errno
import time
import urlparse
import urllib

from ipaddress import ip_address, ip_network

import ldap0
from ldap0.ldapurl import isLDAPUrl

import web2ldapcnf
import web2ldapcnf.hosts

import web2ldap.web.forms
import web2ldap.web.helper
import web2ldap.web.session
import web2ldap.__about__
import web2ldap.ldaputil.base
import web2ldap.ldaputil.dns
import web2ldap.ldapsession
from web2ldap.ldaputil.extldapurl import ExtendedLDAPUrl
from web2ldap.ldapsession import LDAPSession
from web2ldap.log import logger, log_exception
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
from web2ldap.app.form import Web2LDAPForm
from web2ldap.app.session import session_store
from web2ldap.app.schema.syntaxes import syntax_registry
from web2ldap.ldaputil.base import AD_LDAP49_ERROR_CODES, AD_LDAP49_ERROR_PREFIX


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

FORM_CLASS = {
    '': Web2LDAPForm,
    'monitor': Web2LDAPForm,
    'urlredirect': Web2LDAPForm,
    'disconnect': Web2LDAPForm,
}
logger.debug('Registering Form classes')
for _, cls in inspect.getmembers(sys.modules['web2ldap.app.form'], inspect.isclass):
    if cls.__name__.startswith('Web2LDAPForm_') and cls.command is not None:
        logger.debug('Register class %s for command %r', cls.__name__, cls.command)
        FORM_CLASS[cls.command] = cls

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


syntax_registry.check()


def check_access(env, command):
    """
    simple access control based on REMOTE_ADDR
    """
    remote_addr = ip_address(env['REMOTE_ADDR'].decode('ascii'))
    access_allowed = web2ldapcnf.access_allowed.get(
        command.decode('ascii'),
        web2ldapcnf.access_allowed['_']
    )
    for net in access_allowed:
        if remote_addr in ip_network(net, strict=False):
            return True
    return False


class AppHandler(object):

    def __init__(self, env, outf):
        self.inf = env['wsgi.input']
        self.outf = outf
        self.env = env
        self.script_name = self.env['SCRIPT_NAME']
        self.command, self.sid = self.path_info(env)
        self.form = None
        self.ls = None
        self.dn = u''
        self.current_access_time = time.time()
        return

    @property
    def dn(self):
        return self._dn

    @dn.setter
    def dn(self, dn):
        if isinstance(dn, bytes) and self.ls is not None:
            dn = dn.decode(self.ls.charset)
        assert web2ldap.ldaputil.base.is_dn(dn), ValueError(
            'Expected LDAP DN as dn, was %r' % (dn)
        )
        self._dn = web2ldap.ldaputil.base.normalize_dn(dn)
        self._parent_dn = web2ldap.ldaputil.base.parent_dn(self._dn)
        if self.ls:
            ldap_charset = self.ls.charset
            self.naming_context = self.ls.getSearchRoot(self._dn)
            self.ls.setDN(self._dn)
        else:
            ldap_charset = 'utf-8'
            self.naming_context = u''
        assert isinstance(self.naming_context, unicode), TypeError(
            'Expected class attribute naming_context to be unicode , was %r' % (self.naming_context)
        )
        self._ldap_dn = dn.encode(ldap_charset)

    @property
    def parent_dn(self):
        return self._parent_dn

    @property
    def ldap_dn(self):
        return self._ldap_dn

    def anchor(
            self,
            command,
            anchor_text,
            form_parameters,
            target=None,
            title=None,
            anchor_id=None,
        ):
        """
        Build the HTML text of a anchor with form parameters
        """
        assert isinstance(command, bytes), TypeError('command must be string, but was %r', command)
        assert isinstance(anchor_text, bytes), TypeError('anchor_text must be string, but was %r', anchor_text)
        assert anchor_id is None or isinstance(anchor_id, unicode), TypeError('anchor_id must be None or unicode, but was %r', anchor_id)
        assert target is None or isinstance(target, str), TypeError('target must be None or string, but was %r', target)
        assert title is None or isinstance(title, unicode), TypeError('title must be None or unicode, but was %r', title)
        target_attr = ''
        if target:
            target_attr = ' target="%s"' % (target)
        title_attr = ''
        if title:
            title_attr = ' title="%s"' % (self.form.utf2display(title).replace(' ', '&nbsp;'))
        if anchor_id:
            anchor_id = '#%s' % (self.form.utf2display(anchor_id))
        res = '<a class="CommandLink"%s%s href="%s?%s%s">%s</a>' % (
            target_attr,
            title_attr,
            self.form.actionUrlHTML(command, self.sid),
            '&amp;'.join([
                '%s=%s' % (param_name, urllib.quote(self.form.uc_encode(param_value)[0]))
                for param_name, param_value in form_parameters
            ]),
            anchor_id or '',
            anchor_text,
        )
        assert isinstance(res, bytes), TypeError('res must be bytes, was %r', res)
        return res

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

    def dispatch(self, dn, connLDAPUrl):
        """Execute function for self.command"""
        assert isinstance(dn, unicode), TypeError("Argument 'dn' must be unicode, was %r" % (dn))
        self.dn = dn
        if self.command == 'searchform':
            web2ldap.app.searchform.w2l_searchform(self)
        elif self.command == 'search':
            web2ldap.app.search.w2l_search(self, connLDAPUrl)
        elif self.command == 'add':
            web2ldap.app.add.w2l_add(self)
        elif self.command == 'modify':
            web2ldap.app.modify.w2l_modify(self)
        elif self.command == 'dds':
            web2ldap.app.dds.w2l_dds(self)
        elif self.command == 'bulkmod':
            web2ldap.app.bulkmod.w2l_bulkmod(self, connLDAPUrl)
        elif self.command == 'delete':
            web2ldap.app.delete.w2l_delete(self, connLDAPUrl)
        elif self.command == 'dit':
            web2ldap.app.dit.w2l_dit(self)
        elif self.command == 'rename':
            web2ldap.app.rename.w2l_rename(self)
        elif self.command == 'passwd':
            web2ldap.app.passwd.w2l_passwd(self, connLDAPUrl)
        elif self.command == 'read':
            web2ldap.app.read.w2l_read(
                self,
                wanted_attrs={False:connLDAPUrl.attrs, True:[]}[connLDAPUrl.attrs is None],
            )
        elif self.command == 'conninfo':
            web2ldap.app.conninfo.w2l_conninfo(self)
        elif self.command == 'ldapparams':
            web2ldap.app.ldapparams.w2l_ldapparams(self)
        elif self.command == 'login':
            web2ldap.app.login.w2l_login(
                self, connLDAPUrl,
                self.form.getInputValue('login_search_root', [self.ls.getSearchRoot(dn)])[0],
                login_default_mech=connLDAPUrl.saslMech,
            )
        elif self.command == 'groupadm':
            web2ldap.app.groupadm.w2l_groupadm(self)
        elif self.command == 'oid':
            web2ldap.app.schema.viewer.w2l_schema_viewer(self)
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
        if self.form is None:
            self.form = Web2LDAPForm(None, self.env)
        target_url = target_url or self.script_name
        url_redirect_template_str = web2ldap.app.gui.ReadTemplate(
            self, None, u'redirect',
            tmpl_filename=web2ldapcnf.redirect_template,
        )
        if refresh_time:
            message_class = 'ErrorMessage'
        else:
            message_class = 'SuccessMessage'
        web2ldap.app.gui.Header(self, 'text/html', self.form.accept_charset)
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
        session_store.storeSession(self.sid, self.ls)
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
            self.form.getInputFields()
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

    def ldap_error_msg(self, ldap_err, template='{error_msg}<br>{matched_dn}'):
        """
        Converts a LDAPError exception into HTML error message

        ldap_err
          LDAPError instance
        template
          Raw binary string to be used as template
          (must contain only a single placeholder)
        """
        matched_dn = None
        if isinstance(ldap_err, ldap0.TIMEOUT) or not ldap_err.args:
            error_msg = u''
        elif isinstance(ldap_err, ldap0.INVALID_CREDENTIALS) and \
            AD_LDAP49_ERROR_PREFIX in ldap_err.args[0].get('info', ''):
            ad_error_code_pos = ldap_err.args[0]['info'].find(AD_LDAP49_ERROR_PREFIX)+len(AD_LDAP49_ERROR_PREFIX)
            ad_error_code = int(ldap_err.args[0]['info'][ad_error_code_pos:ad_error_code_pos+3], 16)
            error_msg = u'%s:\n%s (%s)' % (
                ldap_err.args[0]['desc'].decode(self.ls.charset),
                ldap_err.args[0].get('info', '').decode(self.ls.charset),
                AD_LDAP49_ERROR_CODES.get(ad_error_code, u'unknown'),
            )
        else:
            try:
                error_msg = u':\n'.join((
                    ldap_err.args[0]['desc'].decode(self.ls.charset),
                    ldap_err.args[0].get('info', '').decode(self.ls.charset),
                ))
            except UnicodeDecodeError:
                error_msg = u':\n'.join((
                    ldap_err.args[0]['desc'].decode(self.ls.charset),
                    repr(ldap_err.args[0].get('info', '')).decode(self.ls.charset),
                ))
            except (TypeError, IndexError):
                error_msg = str(ldap_err).decode(self.ls.charset)
            matched_dn = ldap_err.args[0].get('matched', '').decode(self.ls.charset)
        error_msg = error_msg.replace(u'\r', '').replace(u'\t', '')
        error_msg_html = self.form.utf2display(error_msg, lf_entity='<br>')
        # Add matchedDN to error message HTML if needed
        if matched_dn:
            matched_dn_html = '<br>Matched DN: %s' % (self.form.utf2display(matched_dn))
        else:
            matched_dn_html = ''
        return template.format(
            error_msg=error_msg_html,
            matched_dn=matched_dn_html
        )

    def run(self):
        """
        Really process the request
        """

        # check for valid command
        if self.command not in FORM_CLASS:

            logger.warn('Received invalid command %r', self.command)
            self.url_redirect(u'Invalid web2ldap command')
            return

        self.form = FORM_CLASS[self.command](self.inf, self.env)

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
                web2ldap.app.monitor.w2l_monitor(self)
                return
            elif self.command == 'locate':
                self.form.getInputFields()
                web2ldap.app.locate.w2l_locate(self)
                return
            elif self.command == '':
                # New connect => remove old session if necessary
                session_store.deleteSession(self.sid)
                # Just output a connect form if there was no query string
                if not self.form.query_string:
                    web2ldap.app.connect.w2l_connect(self)
                    return

            self.ls = self._get_session()

            if self.command == 'disconnect':
                # Remove session cookie
                self.form.unsetCookie(self.ls.cookie)
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
               self.ls.uri is None:
                # Force a SRV RR lookup for dc-style DNs,
                # create list of URLs to connect to
                dns_srv_rrs = web2ldap.ldaputil.dns.dcDNSLookup(self.dn)
                initializeUrl_list = [
                    ExtendedLDAPUrl(urlscheme='ldap', hostport=host, dn=dn).initializeUrl()
                    for host in dns_srv_rrs
                ]
                if not initializeUrl_list:
                    # No host specified in user's input
                    session_store.deleteSession(self.sid)
                    web2ldap.app.connect.w2l_connect(
                        self,
                        h1_msg='Connect failed',
                        error_msg='No host specified.'
                    )
                    return
                elif len(initializeUrl_list) == 1:
                    initializeUrl = initializeUrl_list[0]
                else:
                    web2ldap.app.srvrr.w2l_chasesrvrecord(
                        self,
                        initializeUrl_list
                    )
                    return
            elif not input_ldapurl.hostport is None:
                initializeUrl = str(input_ldapurl.initializeUrl()[:])
            else:
                initializeUrl = None

            if initializeUrl and (
                    self.ls is None or self.ls.uri is None or initializeUrl != self.ls.uri
                ):
                # Delete current LDAPSession instance and create new
                del self.ls
                self.ls = LDAPSession(
                    self.guess_client_addr(),
                    web2ldapcnf.ldap_trace_level,
                    web2ldapcnf.ldap_cache_ttl,
                )
                self.ls.cookie = self.form.setNewCookie(str(id(self.ls)))
                session_store.storeSession(self.sid, self.ls)
                # Check whether access to target LDAP server is allowed
                if web2ldapcnf.hosts.restricted_ldap_uri_list and \
                   initializeUrl not in web2ldap.app.core.ldap_uri_list_check_dict:
                    raise web2ldap.app.core.ErrorExit(u'Only pre-configured LDAP servers allowed.')
                startTLSextop = input_ldapurl.get_starttls_extop(
                    web2ldap.app.cnf.GetParam(input_ldapurl, 'starttls', web2ldap.ldapsession.START_TLS_NO)
                )
                # Connect to new specified host
                self.ls.open(
                    initializeUrl,
                    web2ldap.app.cnf.GetParam(input_ldapurl, 'timeout', -1),
                    startTLSextop,
                    self.env,
                    web2ldap.app.cnf.GetParam(input_ldapurl, 'session_track_control', 0),
                    tls_options=web2ldap.app.cnf.GetParam(input_ldapurl, 'tls_options', {}),
                )
                # Set host-/backend-specific timeout
                self.ls.timeout = self.ls.l.timeout = web2ldap.app.cnf.GetParam(self.ls, 'timeout', 60)
                # Store session data in case anything goes wrong after here
                # to give the exception handler a good chance
                session_store.storeSession(self.sid, self.ls)

            if self.ls.uri is None:
                session_store.deleteSession(self.sid)
                web2ldap.app.connect.w2l_connect(
                    self,
                    h1_msg='Connect failed',
                    error_msg='No valid LDAP connection.'
                )
                return

            # Store session data in case anything goes wrong after here
            # to give the exception handler a good chance
            session_store.storeSession(self.sid, self.ls)

            login_mech = self.form.getInputValue(
                'login_mech',
                [input_ldapurl.saslMech or '']
            )[0].upper() or None

            if who is not None and cred is None and login_mech not in ldap0.sasl.SASL_NONINTERACTIVE_MECHS:
                # first ask for password in a login form
                web2ldap.app.login.w2l_login(
                    self,
                    input_ldapurl,
                    self.form.getInputValue('login_search_root', [self.ls.getSearchRoot(dn)])[0],
                    login_msg='',
                    who=who, relogin=0, nomenu=1,
                    login_default_mech=input_ldapurl.saslMech
                )
                return

            elif (who is not None and cred is not None) or login_mech in ldap0.sasl.SASL_NONINTERACTIVE_MECHS:
                # real bind operation
                login_search_root = self.form.getInputValue('login_search_root', [None])[0]
                if who is not None and not web2ldap.ldaputil.base.is_dn(who) and login_search_root is None:
                    login_search_root = self.ls.getSearchRoot(dn)
                try:
                    self.ls.bind(
                        who,
                        cred or '',
                        login_mech,
                        ''.join((
                            self.form.getInputValue('login_authzid_prefix', [''])[0],
                            self.form.getInputValue('login_authzid', [input_ldapurl.saslAuthzId or ''])[0],
                        )) or None,
                        self.form.getInputValue('login_realm', [input_ldapurl.saslRealm])[0],
                        binddn_filtertemplate=self.form.getInputValue('login_filterstr', [ur'(uid=%s)'])[0],
                        whoami_filtertemplate=web2ldap.app.cnf.GetParam(self.ls, 'binddnsearch', ur'(uid=%s)'),
                        loginSearchRoot=login_search_root,
                    )
                except ldap0.NO_SUCH_OBJECT as e:
                    web2ldap.app.login.w2l_login(
                        self,
                        input_ldapurl, login_search_root,
                        login_msg=self.ldap_error_msg(e),
                        who=who, relogin=True
                    )
                    return
            else:
                # anonymous access
                self.ls.init_rootdse()

            # Check for valid LDAPSession and connection to provide reasonable
            # error message instead of logging exception in case user is playing
            # with manually generated URLs
            if not isinstance(self.ls, LDAPSession) or self.ls.uri is None:
                self.url_redirect(u'No valid LDAP connection!')
                return
            # Store session data in case anything goes wrong after here
            # to give the exception handler a good chance
            session_store.storeSession(self.sid, self.ls)

            # Execute the command module
            try:
                self.dispatch(dn, input_ldapurl)
            except ldap0.SERVER_DOWN:
                # Try to reconnect to LDAP server and retry action
                self.ls.l.reconnect(self.ls.uri)
                self.dispatch(dn, input_ldapurl)
            else:
                # Store current session
                session_store.storeSession(self.sid, self.ls)

        except web2ldap.web.forms.FormException as form_error:
            log_exception(self.env, self.ls)
            ExceptionMsg(
                self,
                u'Error parsing form',
                u'Error parsing form: %s' % (
                    self.form.utf2display(str(form_error).decode(self.form.accept_charset)),
                ),
            )

        except ldap0.SERVER_DOWN as e:
            # Server is down and reconnecting impossible => remove session
            session_store.deleteSession(self.sid)
            # Redirect to entry page
            web2ldap.app.connect.w2l_connect(
                self,
                h1_msg='Connect failed',
                error_msg='Connecting to %s impossible!<br>%s' % (
                    self.form.utf2display((initializeUrl or '-').decode('utf-8')),
                    self.ldap_error_msg(e)
                )
            )

        except ldap0.NO_SUCH_OBJECT as ldap_err:

            # first try to lookup dc-style DN via DNS
            host_list = web2ldap.ldaputil.dns.dcDNSLookup(self.dn)
            logger.debug('host_list = %r', host_list)
            if host_list and ExtendedLDAPUrl(self.ls.uri).hostport not in host_list:
                # Found LDAP server for this naming context via DNS SRV RR
                web2ldap.app.srvrr.w2l_chasesrvrecord(self, host_list)
                return

            # Normal error handling
            log_exception(self.env, self.ls)
            failed_dn = self.dn
            if 'matched' in ldap_err.args[0]:
                self.dn = ldap_err.args[0]['matched']
            ExceptionMsg(
                self,
                u'No such object',
                self.ldap_error_msg(
                    ldap_err,
                    template='{{error_msg}}<br>{0}{{matched_dn}}'.format(
                        web2ldap.app.gui.DisplayDN(self, failed_dn)
                    )
                )
            )

        except (ldap0.PARTIAL_RESULTS, ldap0.REFERRAL) as e:
            web2ldap.app.referral.w2l_chasereferral(self, e)

        except (
                ldap0.INSUFFICIENT_ACCESS,
                ldap0.STRONG_AUTH_REQUIRED,
                ldap0.INAPPROPRIATE_AUTH,
                web2ldap.ldapsession.USERNAME_NOT_FOUND,
            ) as e:
            web2ldap.app.login.w2l_login(
                self,
                input_ldapurl,
                self.form.getInputValue('login_search_root', [self.ls.getSearchRoot(dn)])[0],
                who=u'',
                login_msg=self.ldap_error_msg(e),
                relogin=True,
            )

        except (
                ldap0.INVALID_CREDENTIALS,
            ) as e:
            web2ldap.app.login.w2l_login(
                self,
                input_ldapurl,
                self.form.getInputValue('login_search_root', [self.ls.getSearchRoot(dn)])[0],
                who=who,
                login_msg=self.ldap_error_msg(e),
                relogin=True,
            )

        except web2ldap.ldapsession.INVALID_SIMPLE_BIND_DN as e:
            web2ldap.app.login.w2l_login(
                self,
                input_ldapurl,
                self.form.getInputValue('login_search_root', [self.ls.getSearchRoot(dn)])[0],
                login_msg=self.form.utf2display(unicode(e)),
                who=who, relogin=True
            )

        except web2ldap.ldapsession.PWD_EXPIRATION_WARNING as e:
            # Setup what's required for executing command 'passwd'
            self.dn = dn or e.who
            # Output the change password form
            web2ldap.app.passwd.passwd_form(
                self,
                None, None, e.who.decode(self.ls.charset), None,
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
            # Setup what's required for executing command 'passwd'
            self.dn = dn or e.who
            # Output the change password form
            web2ldap.app.passwd.passwd_form(
                self,
                None, None,
                e.who.decode(self.ls.charset), None,
                'Password change needed',
                self.form.utf2display(unicode(e.desc))
            )

        except web2ldap.ldapsession.USERNAME_NOT_UNIQUE as e:
            login_search_root = self.form.getInputValue('login_search_root', [self.ls.getSearchRoot(dn)])[0]
            web2ldap.app.login.w2l_login(
                self,
                input_ldapurl,
                login_search_root,
                login_msg=web2ldapcnf.command_link_separator.join([
                    self.ldap_error_msg(e),
                    self.anchor(
                        'search', 'Show',
                        [
                            ('dn', login_search_root),
                            ('scope', str(ldap0.SCOPE_SUBTREE)),
                            ('filterstr', web2ldap.app.cnf.GetParam(self.ls, 'binddnsearch', r'(uid=%s)').replace('%s', who))
                        ]
                    ),
                ]),
                who=who,
                relogin=True
            )

        except (IOError, UnicodeError) as err:
            log_exception(self.env, self.ls)
            ExceptionMsg(
                self,
                u'Unhandled %s' % err.__class__.__name__.decode('ascii'),
                self.form.utf2display(str(err).decode('ascii')),
            )

        except ldap0.LDAPError as ldap_err:
            log_exception(self.env, self.ls)
            ExceptionMsg(
                self,
                u'Unhandled %s' % ldap_err.__class__.__name__.decode('ascii'),
                self.ldap_error_msg(ldap_err),
            )

        except (
                socket.error,
                socket.gaierror,
            ) as socket_err:
            try:
                socket_errno = socket_err.errno
            except AttributeError:
                socket_errno = None
            if socket_errno not in (errno.EPIPE, errno.ECONNRESET):
                log_exception(self.env, self.ls)
                ExceptionMsg(
                    self,
                    u'Socket Error',
                    self.form.utf2display(str(socket_err).decode('ascii')),
                )
            raise e

        except web2ldap.app.core.ErrorExit as error_exit:
            logger.warn(str(error_exit))
            ExceptionMsg(
                self,
                u'Error',
                error_exit.Msg,
            )

        except web2ldap.web.session.MaxSessionCountExceeded:
            log_exception(self.env, self.ls)
            self.simple_msg(u'Too many web sessions! Try later...')

        except web2ldap.web.session.SessionException:
            log_exception(self.env, self.ls)
            self.url_redirect(u'Session handling error.')
            return

        return # run()
