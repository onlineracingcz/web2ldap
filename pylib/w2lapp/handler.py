# -*- coding: utf-8 -*-
"""w2lapp.handler: base handler

web2ldap - a web-based LDAP Client,
see http://www.web2ldap.de for details

(c) by Michael Stroeder <michael@stroeder.com>

This module is distributed under the terms of the
GPL (GNU GENERAL PUBLIC LICENSE) Version 2
(see http://www.gnu.org/copyleft/gpl.html)
"""

from __future__ import absolute_import

import sys,os,types,socket,errno,time,traceback,urlparse,pprint, \
       ldap,ldif,ldaputil,ldaputil.dns,ldapsession,mssignals, \
       pyweblib.forms,pyweblib.httphelper,pyweblib.sslenv,pyweblib.helper,pyweblib.session, \
       msHTTPHandler

from netaddr import IPNetwork

# Import the application modules
import w2lapp.core,w2lapp.gui,w2lapp.cnf, \
       w2lapp.passwd,w2lapp.dit,w2lapp.searchform,w2lapp.locate, \
       w2lapp.search,w2lapp.addmodifyform,w2lapp.add, \
       w2lapp.modify,w2lapp.dds,w2lapp.delete,w2lapp.ldapparams, \
       w2lapp.read,w2lapp.conninfo,w2lapp.login,w2lapp.connect, \
       w2lapp.referral,w2lapp.monitor,w2lapp.groupadm,w2lapp.rename, \
       w2lapp.bulkmod,w2lapp.srvrr,w2lapp.schema.viewer

from types import UnicodeType,StringType
from ldapurl import isLDAPUrl
from ldaputil.extldapurl import ExtendedLDAPUrl
from ldapsession import LDAPSession
from w2lapp.gui import ExceptionMsg
from w2lapp.form import Web2LDAPForm,FORM_CLASS
from w2lapp.session import session

SocketErrors = (socket.error,socket.gaierror)


LOG_SEPARATOR = '-'*60

SCOPE2COMMAND = {
  None:'search',
  ldap.SCOPE_BASE:'read',
  ldap.SCOPE_ONELEVEL:'search',
  ldap.SCOPE_SUBTREE:'search',
}

try:
  # Check whether constant is present (python-ldap 2.4.15+)
  ldap.SCOPE_SUBORDINATE
except AttributeError:
  pass
else:
  SCOPE2COMMAND[ldap.SCOPE_SUBORDINATE] = 'search'


class AppHandler:

  def __init__(self,inf,outf,errf,env):
    self.inf = inf
    self.outf = outf
    self.errf = errf
    self.env = env
    self.script_name = self.env['SCRIPT_NAME']
    self.command,self.sid = self.path_info()
    return

  def check_sec_level(self,ls):
    required_ssl_level = w2lapp.cnf.GetParam(ls,'ssl_minlevel',0)
    current_ssl_level = pyweblib.sslenv.SecLevel(
      self.env,
      w2lapp.cnf.misc.sec_sslacceptedciphers,
      w2lapp.cnf.GetParam(ls,'ssl_valid_dn',''),
      w2lapp.cnf.GetParam(ls,'ssl_valid_idn','')
    )
    if current_ssl_level < required_ssl_level:
      raise w2lapp.core.ErrorExit(
        u'Access denied. SSL security level %d not sufficient. Must be at least %d.' % (
          current_ssl_level,required_ssl_level
        )
      )
    return # check_sec_level()

  def guess_client_addr(self):
    """
    Guesses the host name or IP address of the HTTP client by looking
    at various HTTP headers mapped to CGI-BIN environment.
    """
    return self.env.get('FORWARDED_FOR',
           self.env.get('HTTP_X_FORWARDED_FOR',
           self.env.get('HTTP_X_REAL_IP',
           self.env.get('REMOTE_HOST',
           self.env.get('REMOTE_ADDR',None)))))

  def log_exception(self,ls):
    """
    Write an exception with environment vars, LDAP connection data
    and Python traceback to errf file object.
    """
    # Get exception instance and traceback info
    exc_obj,exc_value,exc_traceback = sys.exc_info()
    # Signals are raised again to trigger handling in main process
    logentry = [
      LOG_SEPARATOR,
      'Unhandled error at %s' % (
        time.strftime(
          '%Y-%m-%dT%H:%M:%SZ',time.gmtime(time.time())
        ),
      ),
      'web2ldap version: %s' % w2lapp.__version__,
      'LDAPSession instance: %s' % repr(ls),
    ]
    if ls:
      # Log the LDAPSession object attributes
      logentry.append(pprint.pformat(ls.__dict__))
      # Log rootDSE attributes as LDIF
      logentry.append(ldif.CreateLDIF('',ls.rootDSE.data))
    # Log all environment vars
    for k,v in sorted(self.env.items()):
      logentry.append(':'.join((k,repr(v))))
    logentry.append(''.join(traceback.format_exception(exc_obj,exc_value,exc_traceback,20)))
    # Write the log entry to errf file object
    self.errf.write(os.linesep.join(logentry))
    # Avoid memory leaks
    exc_obj=None;exc_value=None;exc_traceback=None
    del exc_obj;del exc_value;del exc_traceback
    return # log_exception()

  def dispatch(self,connLDAPUrl,ls,dn):
    assert type(dn)==UnicodeType, TypeError("Type of argument 'dn' must be UnicodeType: %s" % repr(dn))
    """Execute function for self.command"""
    if self.command=='searchform':
      w2lapp.searchform.w2l_SearchForm(self.sid,self.outf,self.command,self.form,ls,dn)
    elif self.command=='search':
      w2lapp.search.w2l_Search(self.sid,self.outf,self.command,self.form,ls,dn,connLDAPUrl)
    elif self.command=='add':
      w2lapp.add.w2l_Add(self.sid,self.outf,self.command,self.form,ls,dn)
    elif self.command=='modify':
      w2lapp.modify.w2l_Modify(self.sid,self.outf,self.command,self.form,ls,dn)
    elif self.command=='dds':
      w2lapp.dds.w2l_DDS(self.sid,self.outf,self.command,self.form,ls,dn)
    elif self.command=='bulkmod':
      w2lapp.bulkmod.w2l_BulkMod(self.sid,self.outf,self.command,self.form,ls,dn,connLDAPUrl)
    elif self.command=='delete':
      w2lapp.delete.w2l_Delete(self.sid,self.outf,self.command,self.form,ls,dn,connLDAPUrl)
    elif self.command=='dit':
      w2lapp.dit.w2l_DIT(self.sid,self.outf,self.command,self.form,ls,dn)
    elif self.command=='rename':
      w2lapp.rename.w2l_Rename(self.sid,self.outf,self.command,self.form,ls,dn)
    elif self.command=='passwd':
      w2lapp.passwd.w2l_Passwd(self.sid,self.outf,self.command,self.form,ls,dn,connLDAPUrl)
    elif self.command=='read':
      w2lapp.read.w2l_Read(
        self.sid,self.outf,self.command,self.form,ls,dn,
        wanted_attrs={
          0:connLDAPUrl.attrs,1:[]
        }[connLDAPUrl.attrs is None],
      )
    elif self.command=='conninfo':
      w2lapp.conninfo.w2l_ConnInfo(self.sid,self.outf,self.command,self.form,ls,dn)
    elif self.command=='ldapparams':
      w2lapp.ldapparams.w2l_LDAPParameters(self.sid,self.outf,self.command,self.form,ls,dn)
    elif self.command=='login':
      w2lapp.login.w2l_Login(
        self.sid,self.outf,'searchform',self.form,ls,dn,connLDAPUrl,
        self.form.getInputValue('login_search_root',[ls.getSearchRoot(dn)])[0],
        login_default_mech=connLDAPUrl.saslMech
      )
    elif self.command=='groupadm':
      w2lapp.groupadm.w2l_GroupAdm(self.sid,self.outf,self.command,self.form,ls,dn)
    elif self.command=='oid':
      w2lapp.schema.viewer.w2l_DisplaySchemaElement(self.sid,self.outf,self.command,self.form,ls,dn)
    return # dispatch()

  def path_info(self):
    # Extract the command from PATH_INFO env var
    path_info = self.env.get('PATH_INFO','/')[1:]
    if not path_info:
      c,s = '',''
    else:
      # Work around broken web servers which adds the script name
      # to path info as well
      script_name = self.env['SCRIPT_NAME']
      if path_info.startswith(script_name):
        path_info = path_info[len(script_name):]
      try:
        c,s = path_info.split('/',1)
      except ValueError:
        c,s = path_info,''
    return c,s # path_info()

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
    url_redirect_template_str = w2lapp.gui.ReadTemplate(
      self.form,None,None,u'redirect',
      tmpl_filename=w2lapp.cnf.misc.redirect_template
    )
    if refresh_time:
      message_class = 'ErrorMessage'
    else:
      message_class = 'SuccessMessage'
    w2lapp.gui.Header(self.outf,self.form)
    # Write out stub body with just a short redirect HTML snippet
    self.outf.write(url_redirect_template_str.format(
        refresh_time = refresh_time,
        target_url = target_url,
        message_class = message_class,
        redirect_msg = self.form.utf2display(redirect_msg),
        link_text = link_text,
      )
    )
    return # url_redirect()

  def _handle_urlredirect(self):
    try:
      tu = urlparse.urlparse(self.form.query_string)
    except:
      tu = None
    if not tu or not tu.scheme or not tu.netloc:
      self.url_redirect(u'Rejected malformed/suspicious redirect URL!')
    # Check for valid session
    elif session.sessiondict.has_key(self.sid) or \
         self.form.query_string in w2lapp.cnf.misc.good_redirect_targets:
      # URL redirecting has absolutely nothing to do with rest
      self.url_redirect(
        u'Redirecting to %s...' % (
          self.form.query_string.decode(self.form.accept_charset)
        ),
        refresh_time=0,
        target_url=self.form.query_string,
      )
    else:
      self.url_redirect(u'Redirecting without valid session disallowed!')
    return # end of handle_urlredirect()

  def _new_session(self):
    """
    create new session
    """
    self.sid = session.newSession(self.env)
    ls = LDAPSession(
      self.guess_client_addr(),
      w2lapp.cnf.misc.ldap_trace_level,
      self.errf
    )
    ls.cookie = self.form.setNewCookie(str(id(ls)))
    session.storeSession(self.sid,ls)
    return ls # end of _get_session()

  def _get_session(self):
    """
    Restore old or initialize new web session object
    """
    if self.sid:
      # Session ID given => try to restore old session
      try:
        last_session_timestamp,_ = session.sessiondict[self.sid]
      except KeyError:
        pass
      ls = session.retrieveSession(self.sid,self.env)
      if not isinstance(ls,LDAPSession):
        raise w2lapp.session.InvalidSessionInstance()
      if ls.cookie:
        # Check whether HTTP_COOKIE contains the cookie of this particular session
        cookie_name = ''.join((self.form.cookie_name_prefix,str(id(ls))))
        if not (cookie_name in self.form.cookies and ls.cookie[cookie_name].value==self.form.cookies[cookie_name].value):
          raise w2lapp.session.WrongSessionCookie()
      if w2lapp.cnf.misc.session_paranoid and \
         self.current_access_time-last_session_timestamp>w2lapp.cnf.misc.session_paranoid:
        # Store session with new session ID
        self.sid = session.renameSession(self.sid,self.env)
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
        old_ls = session.retrieveSession(del_sid,self.env)
      except pyweblib.session.SessionException:
        pass
      else:
        # Remove session cookie
        self.form.unsetCookie(old_ls.cookie)
      # Explicitly remove old session
      session.deleteSession(del_sid)
    return # end of _handle_del_sid()

  def _get_ldapconn_params(self):
    """
    Extract parameters either from LDAP URL in query string or real form input
    """

    if isLDAPUrl(self.form.query_string):
      # Extract the connection parameters from a LDAP URL
      try:
        inputLDAPUrl = ExtendedLDAPUrl(self.form.query_string)
      except ValueError as e:
        raise w2lapp.core.ErrorExit(u'Error parsing LDAP URL: %s.' % (
          self.form.utf2display(unicode(str(e)))
        ))
      else:
        self.command = self.command or SCOPE2COMMAND[inputLDAPUrl.scope]
        if self.command in ('search','read'):
          inputLDAPUrl.filterstr = inputLDAPUrl.filterstr or '(objectClass=*)'
        # Re-instantiate form based on command derived from LDAP URL
        self.form = FORM_CLASS.get(self.command,Web2LDAPForm)(self.inf,self.env)

    else:

      # Extract the connection parameters from form fields
      self.form.getInputFields(ignoreEmptyFields=0)
      
      self._handle_del_sid()

      if 'ldapurl' in self.form.inputFieldNames:
        # One form parameter with LDAP URL
        ldap_url_input = self.form.field['ldapurl'].value[0]
        try:
          inputLDAPUrl = ExtendedLDAPUrl(ldap_url_input.encode('ascii'))
        except ValueError as e:
          raise w2lapp.core.ErrorExit(u'Error parsing LDAP URL: %s.' % (unicode(str(e),self.form.accept_charset)))
      else:
        inputLDAPUrl = ExtendedLDAPUrl()
        conntype = int(self.form.getInputValue('conntype',[0])[0])
        inputLDAPUrl.urlscheme = w2lapp.form.CONNTYPE2URLSCHEME[conntype]
        inputLDAPUrl.hostport = self.form.getInputValue('host',[None])[0]
        inputLDAPUrl.x_startTLS = str(ldapsession.START_TLS_REQUIRED * (conntype==1))

    # Separate parameters for dn, who, cred and scope
    # have predecence over parameters specified in LDAP URL

    dn = self.form.getInputValue('dn',[unicode(inputLDAPUrl.dn,self.form.accept_charset)])[0]

    who = self.form.getInputValue('who',[None])[0]
    if who==None:
      if inputLDAPUrl.who!=None:
        who = unicode(inputLDAPUrl.who,self.form.accept_charset)
    else:
      inputLDAPUrl.who = who.encode(self.form.accept_charset)

    cred = self.form.getInputValue('cred',[None])[0]
    if cred==None:
      if inputLDAPUrl.cred!=None:
        cred = unicode(inputLDAPUrl.cred,self.form.accept_charset)
    else:
      inputLDAPUrl.cred = cred.encode(self.form.accept_charset)

    assert type(inputLDAPUrl.dn)==StringType, TypeError("Type of variable 'inputLDAPUrl.dn' must be StringType: %s" % repr(inputLDAPUrl.dn))
    assert inputLDAPUrl.who==None or type(inputLDAPUrl.who)==StringType, TypeError("Type of variable 'inputLDAPUrl.who' must be StringType: %s" % repr(inputLDAPUrl.who))
    assert inputLDAPUrl.cred==None or type(inputLDAPUrl.cred)==StringType, TypeError("Type of variable 'inputLDAPUrl.cred' must be StringType: %s" % repr(inputLDAPUrl.cred))

    assert type(dn)==UnicodeType, TypeError("Type of variable 'dn' must be UnicodeType: %s" % repr(dn))
    assert who==None or type(who)==UnicodeType, TypeError("Type of variable 'who' must be UnicodeType: %s" % repr(who))
    assert cred==None or type(cred)==UnicodeType, TypeError("Type of variable 'cred' must be UnicodeType: %s" % repr(cred))

    if not ldaputil.base.is_dn(dn):
      raise w2lapp.core.ErrorExit(u'Invalid DN.')

    scope_str=self.form.getInputValue(
      'scope',
      [
        {0:str(inputLDAPUrl.scope),1:''}[inputLDAPUrl.scope is None]
      ]
     )[0]
    if scope_str:
      inputLDAPUrl.scope=int(scope_str)
    else:
      inputLDAPUrl.scope=None

    return inputLDAPUrl,dn,who,cred # end of _get_ldapconn_params()

  def run(self):

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
        self.form = Web2LDAPForm(self.inf,self.env)
        self.url_redirect(u'Invalid web2ldap command: %s' % (self.command.decode(self.form.accept_charset)))
        return

      self.form = FORM_CLASS[self.command](self.inf,self.env)
      self.outf = self.form.outFileObject(self.outf)

      #---------------------------------------------------------------
      # try-except block for gracefully handling of certain exceptions
      # (mainly w2lapp.core.ErrorExit and ldap.LDAPError)
      #---------------------------------------------------------------

      try:

        # handle the early-exit commands
        if self.command=='urlredirect':
          if isLDAPUrl(self.form.query_string):
            self.command=''
          else:
            self._handle_urlredirect()
            return
        elif self.command=='monitor':
          # Output simple monitor page. Does not require session handling.
          w2lapp.monitor.w2l_Monitor(self.outf,self.command,self.form,self.env)
          return
        elif self.command=='locate':
          self.form.getInputFields(ignoreEmptyFields=0)
          w2lapp.locate.w2l_Locate(self.outf,self.command,self.form)
          return
        elif self.command=='':
          # New connect => remove old session if necessary
          session.deleteSession(self.sid)
          # Just output a connect form if there was not query string
          if not self.form.query_string:
            w2lapp.connect.w2l_Connect(self.outf,self.form,self.env)
            return

        self.ls = ls = self._get_session()

        if self.command=='disconnect':
          # Remove session cookie
          self.form.unsetCookie(ls.cookie)
          # Explicitly remove old session
          session.deleteSession(self.sid)
          # Redirect to start page to avoid people bookmarking disconnect URL
          self.url_redirect(u'Disconnecting...',refresh_time=0)
          return

        inputLDAPUrl,dn,who,cred = self._get_ldapconn_params()

        self.command = self.command or {
          None:'searchform',
          ldap.SCOPE_BASE:'read',
          ldap.SCOPE_ONELEVEL:'search',
          ldap.SCOPE_SUBTREE:'search',
        }[inputLDAPUrl.scope]

        #-------------------------------------------------
        # Connect to LDAP server
        #-------------------------------------------------

        if not inputLDAPUrl.hostport is None and \
           inputLDAPUrl.hostport=='' and \
           inputLDAPUrl.urlscheme=='ldap' and \
           ls.uri is None:
          # Force a SRV RR lookup for dc-style DNs,
          # create list of URLs to connect to
          dns_srv_rrs = ldaputil.dns.dcDNSLookup(dn)
          initializeUrl_list = [
            ExtendedLDAPUrl(urlscheme='ldap',hostport=host,dn=dn).initializeUrl()
            for host in dns_srv_rrs
          ]
          if not initializeUrl_list:
            # No host specified in user's input
            session.deleteSession(self.sid)
            w2lapp.connect.w2l_Connect(
              self.outf,self.form,self.env,
              Msg='Connect failed',
              ErrorMsg='No host specified.'
            )
            return
          elif len(initializeUrl_list)==1:
            initializeUrl = initializeUrl_list[0]
          else:
            w2lapp.srvrr.w2l_ChaseSRVRecord(self.sid,self.outf,self.command,self.form,ls,dn,initializeUrl_list)
            return
        elif not inputLDAPUrl.hostport is None:
          initializeUrl = str(inputLDAPUrl.initializeUrl()[:])
        else:
          initializeUrl = None

        if initializeUrl and (ls==None or ls.uri==None or initializeUrl!=ls.uri):
          # Delete current LDAPSession instance and create new
          del ls
          ls = LDAPSession(
            self.guess_client_addr(),
            w2lapp.cnf.misc.ldap_trace_level,
            self.errf
          )
          ls.cookie = self.form.setNewCookie(str(id(ls)))
          session.storeSession(self.sid,ls)
          # Check whether gateway access to target LDAP server is allowed
          if w2lapp.cnf.hosts.restricted_ldap_uri_list and \
             not initializeUrl in w2lapp.core.ldap_uri_list_check_dict:
            raise w2lapp.core.ErrorExit(u'Only pre-configured LDAP servers allowed.')
          startTLSextop = inputLDAPUrl.getStartTLSOpt(
            w2lapp.cnf.GetParam(inputLDAPUrl,'starttls',ldapsession.START_TLS_NO)
          )
          # Connect to new specified host
          ls.open(
            initializeUrl,
            w2lapp.cnf.GetParam(inputLDAPUrl,'timeout',-1),
            startTLSextop,
            self.env,
            w2lapp.cnf.GetParam(inputLDAPUrl,'session_track_control',0),
            tls_options=w2lapp.cnf.GetParam(inputLDAPUrl,'tls_options',{}),
          )
          ls.l.set_option(ldap.OPT_RESTART,0)
          ls.l.set_option(ldap.OPT_DEREF,0)
          ls.l.set_option(ldap.OPT_REFERRALS,0)
          # Set host-/backend-specific timeout
          ls.timeout = ls.l.timeout = w2lapp.cnf.GetParam(ls,'timeout',60)
          # Store session data in case anything goes wrong after here
          # to give the exception handler a good chance
          session.storeSession(self.sid,ls)

        if ls.uri is None:
          session.deleteSession(self.sid)
          w2lapp.connect.w2l_Connect(
            self.outf,self.form,self.env,
            Msg='Connect failed',
            ErrorMsg='No valid LDAP connection.'
          )
          return

        # Store session data in case anything goes wrong after here
        # to give the exception handler a good chance
        session.storeSession(self.sid,ls)

        login_mech = self.form.getInputValue(
          'login_mech',
          [inputLDAPUrl.saslMech or '']
        )[0].upper() or None

        if who!=None and cred is None and not login_mech in ldapsession.NON_INTERACTIVE_LOGIN_MECHS:
          # first ask for password in a login form
          #---------------------------------------
          ls.setDN(dn)
          w2lapp.login.w2l_Login(
            self.sid,self.outf,self.command,self.form,ls,dn,inputLDAPUrl,
            self.form.getInputValue('login_search_root',[ls.getSearchRoot(dn)])[0],
            login_msg='',
            who=who,relogin=0,nomenu=1,
            login_default_mech=inputLDAPUrl.saslMech
          )
          return

        elif (who!=None and cred!=None) or login_mech in ldapsession.NON_INTERACTIVE_LOGIN_MECHS:
          # real bind operation
          #------------------------------
          login_search_root = self.form.getInputValue('login_search_root',[None])[0]
          if who!=None and not ldaputil.base.is_dn(who) and login_search_root==None:
            login_search_root = ls.getSearchRoot(dn)
          try:
            ls.bind(
              who,
              cred or '',
              login_mech,
              ''.join((
                self.form.getInputValue('login_authzid_prefix',[''])[0],
                self.form.getInputValue('login_authzid',[inputLDAPUrl.saslAuthzId or ''])[0],
              )) or None,
              self.form.getInputValue('login_realm',[inputLDAPUrl.saslRealm])[0],
              binddn_filtertemplate=self.form.getInputValue('login_filterstr',[ur'(uid=%s)'])[0],
              whoami_filtertemplate=w2lapp.cnf.GetParam(ls,'binddnsearch',ur'(uid=%s)'),
              loginSearchRoot = login_search_root,
            )
          except ldap.NO_SUCH_OBJECT as e:
            ls.setDN(dn)
            w2lapp.login.w2l_Login(
              self.sid,self.outf,self.command,self.form,ls,dn,inputLDAPUrl,login_search_root,
              login_msg=w2lapp.gui.LDAPError2ErrMsg(e,self.form,ls.charset),
              who=who,relogin=1
            )
            return
        else:
          # anonymous access
          #------------------------------
          ls.getRootDSE()

        ls.setDN(dn)

        # Check for valid LDAPSession and connection to provide reasonable
        # error message instead of logging exception in case user is playing
        # with manually generated URLs
        if not isinstance(ls,LDAPSession) or ls.uri is None:
          self.url_redirect(u'No valid LDAP connection!')
          return
        # Store session data in case anything goes wrong after here
        # to give the exception handler a good chance
        session.storeSession(self.sid,ls)

        # Check backend specific required SSL level
        self.check_sec_level(ls)

        # Execute the command module
        try:
          self.dispatch(inputLDAPUrl,ls,dn)
        except ldap.SERVER_DOWN:
          # Try to reconnect to LDAP server and retry action
          ls.l.reconnect(ls.uri)
          self.dispatch(inputLDAPUrl,ls,dn)
        else:
          # Store current session
          session.storeSession(self.sid,ls)

      except pyweblib.forms.FormException as e:
        if ls is None:
          dn = None
        else:
          dn = ls.__dict__.get('_dn',None)
        try:
          e_msg = unicode(str(e))
        except UnicodeDecodeError:
          e_msg = unicode(repr(str(e)))
        ExceptionMsg(self.sid,self.outf,self.command,self.form,ls,dn,u'Error parsing form',u'Error parsing form: %s' % (self.form.utf2display(e_msg)))

      except ldap.SERVER_DOWN as e:
        # Server is down and reconnecting impossible => remove session
        session.deleteSession(self.sid)
        # Redirect to entry page
        w2lapp.connect.w2l_Connect(
          self.outf,self.form,self.env,
          Msg='Connect failed',
          ErrorMsg='Connecting to %s impossible!<br>%s' % (
            self.form.utf2display((initializeUrl or '-').decode('utf-8')),
            w2lapp.gui.LDAPError2ErrMsg(e,self.form,ls.charset)
          )
        )

      except ldap.NO_SUCH_OBJECT as e:

        #########################################
        # Generic handler for "No such object"
        #########################################

        if __debug__:
          self.log_exception(ls)

        host_list = ldaputil.dns.dcDNSLookup(dn)
        if (not host_list) or (ExtendedLDAPUrl(ls.uri).hostport in host_list):
          # Did not find another LDAP server for this naming context
          try:
            if type(e.args[0])==types.DictType and e.args[0].has_key('matched'):
              new_dn = unicode(e.args[0]['matched'],ls.charset)
            else:
              new_dn = dn
          except IndexError:
            new_dn = dn
          ExceptionMsg(
            self.sid,self.outf,self.command,self.form,ls,new_dn,u'No such object',
            w2lapp.gui.LDAPError2ErrMsg(
              e,self.form,ls.charset,
              template='{error_msg}<br>%s<br>{matched_dn}' % (w2lapp.gui.DisplayDN(self.sid,self.form,ls,dn))
            )
          )
        else:
          # Found LDAP server for this naming context via DNS SRV RR
          w2lapp.srvrr.w2l_ChaseSRVRecord(self.sid,self.outf,self.command,self.form,ls,dn,host_list)

      except (ldap.PARTIAL_RESULTS,ldap.REFERRAL) as e:
        w2lapp.referral.w2l_ChaseReferral(self.sid,self.outf,self.command,self.form,ls,dn,e)

      except (ldap.INSUFFICIENT_ACCESS,ldap.STRONG_AUTH_REQUIRED) as e:
        w2lapp.login.w2l_Login(
          self.sid,self.outf,self.command,self.form,ls,dn,inputLDAPUrl,
          self.form.getInputValue('login_search_root',[ls.getSearchRoot(dn)])[0],
          who='',
          login_msg=w2lapp.gui.LDAPError2ErrMsg(e,self.form,ls.charset),relogin=1
        )

      except (
        ldap.INAPPROPRIATE_AUTH,
        ldap.INVALID_CREDENTIALS,
        ldapsession.USERNAME_NOT_FOUND,
      ) as e:
        w2lapp.login.w2l_Login(
          self.sid,self.outf,self.command,self.form,ls,dn,inputLDAPUrl,
          self.form.getInputValue('login_search_root',[ls.getSearchRoot(dn)])[0],
          login_msg=w2lapp.gui.LDAPError2ErrMsg(e,self.form,ls.charset),
          who=who,relogin=1
        )

      except ldapsession.INVALID_SIMPLE_BIND_DN as e:
        w2lapp.login.w2l_Login(
          self.sid,self.outf,self.command,self.form,ls,dn,inputLDAPUrl,
          self.form.getInputValue('login_search_root',[ls.getSearchRoot(dn)])[0],
          login_msg=self.form.utf2display(unicode(e)),
          who=who,relogin=1
        )

      except ldapsession.PWD_EXPIRATION_WARNING as e:
        # Setup what's required to the case command=='passwd'
        ls.setDN(dn or e.who)
        self.form.addField(pyweblib.forms.Select('passwd_scheme',u'Password hash scheme',1,options=w2lapp.passwd.available_hashtypes,default=w2lapp.passwd.available_hashtypes[-1]))
        self.form.addField(pyweblib.forms.Checkbox('passwd_ntpasswordsync',u'Sync ntPassword for Samba',1,default="yes",checked=1))
        self.form.addField(pyweblib.forms.Checkbox('passwd_settimesync',u'Sync password setting times',1,default="yes",checked=1))
        # Directly generate the change password form
        w2lapp.passwd.PasswdForm(
          self.sid,self.outf,self.form,ls,dn,None,
          None,e.who.decode(ls.charset),None,
          'Password change needed',
          self.form.utf2display(
            u'Password will expire in %s!' % (
              w2lapp.gui.ts2repr(
                (
                  (u'weeks',604800),
                  (u'days',86400),
                  (u'hours',3600),
                  (u'mins',60),
                  (u'secs',1),
                ),
                u' ',
                e.timeBeforeExpiration,
              )
          )),
        )

      except ldapsession.PasswordPolicyException as e:
        # Setup what's required to the case command=='passwd'
        ls.setDN(dn or e.who)
        self.form.addField(pyweblib.forms.Select('passwd_scheme',u'Password hash scheme',1,options=w2lapp.passwd.available_hashtypes,default=w2lapp.passwd.available_hashtypes[-1]))
        self.form.addField(pyweblib.forms.Checkbox('passwd_ntpasswordsync',u'Sync ntPassword for Samba',1,default="yes",checked=1))
        self.form.addField(pyweblib.forms.Checkbox('passwd_settimesync',u'Sync password setting times',1,default="yes",checked=1))
        # Directly generate the change password form
        w2lapp.passwd.PasswdForm(
          self.sid,self.outf,self.form,ls,dn,None,
          None,e.who.decode(ls.charset),None,
          'Password change needed',
          self.form.utf2display(unicode(e.desc))
        )

      except ldapsession.USERNAME_NOT_UNIQUE as e:
        login_search_root = self.form.getInputValue('login_search_root',[ls.getSearchRoot(dn)])[0]
        w2lapp.login.w2l_Login(
          self.sid,self.outf,self.command,self.form,ls,dn,inputLDAPUrl,
          login_search_root,
          login_msg=w2lapp.cnf.misc.command_link_separator.join([
            w2lapp.gui.LDAPError2ErrMsg(e,self.form,ls.charset),
            self.form.applAnchor(
              'search','Show',self.sid,
              [
                ('dn',login_search_root),
                ('scope',str(ldap.SCOPE_SUBTREE)),
                ('filterstr',w2lapp.cnf.GetParam(ls,'binddnsearch',r'(uid=%s)').replace('%s',who))
              ]
          )]),
          who=who,relogin=1
        )

      except ldap.TIMEOUT as e:
        if __debug__:
          self.log_exception(ls)
        ExceptionMsg(
          self.sid,self.outf,self.command,self.form,ls,dn,
          u'LDAP timeout',
          u'Timeout of %d secs exceeded.' % (w2lapp.cnf.GetParam(ls,'timeout',-1))
        )

      except (
        ldap.DECODING_ERROR,
        ldap.LOCAL_ERROR,
        ldap.PARAM_ERROR,
        ldap.OTHER,
        ldap.USER_CANCELLED
      ) as e:
        self.log_exception(ls)
        ExceptionMsg(self.sid,self.outf,self.command,self.form,ls,dn,u'LDAP exception',w2lapp.gui.LDAPError2ErrMsg(e,self.form,ls.charset))

      except ldap.LDAPError as e:
        if __debug__:
          self.log_exception(ls)
        ExceptionMsg(self.sid,self.outf,self.command,self.form,ls,dn,u'LDAP exception',w2lapp.gui.LDAPError2ErrMsg(e,self.form,ls.charset))

      except mssignals.SigPipeException:
        # SIGPIPE received
        if __debug__:
          self.log_exception(ls)

      except UnicodeError as e:
        if __debug__:
          self.log_exception(ls)
        ExceptionMsg(self.sid,self.outf,self.command,self.form,None,None,u'Unicode Error',self.form.utf2display(unicode(str(e),'ascii')))

      except SocketErrors as e:
        try:
          socket_errno = e.errno
        except AttributeError:
          socket_errno = None
        if not socket_errno in [errno.EPIPE,errno.ECONNRESET]:
          ExceptionMsg(self.sid,self.outf,self.command,self.form,None,None,u'Socket Error',self.form.utf2display(unicode(str(e),'ascii')))
        raise e

      except IOError as e:
        if __debug__:
          self.log_exception(ls)
        ExceptionMsg(self.sid,self.outf,self.command,self.form,ls,dn,u'I/O Error','See error log for details')

      except w2lapp.core.ErrorExit as e:
        ExceptionMsg(self.sid,self.outf,self.command,self.form,ls,dn,u'Error',e.Msg)

      except pyweblib.session.MaxSessionCountExceeded:
        pyweblib.httphelper.SimpleMsg(self.outf,'Too many web sessions! Try later...')

      except pyweblib.session.SessionExpired:
        self.url_redirect(u'Session expired.')
        return

      except pyweblib.session.InvalidSessionId:
        self.url_redirect(u'Session ID not found.')
        return

      except pyweblib.session.SessionHijacked:
        if __debug__:
          self.log_exception(ls)
        self.url_redirect(u'Session hijacking detected. Access denied!')
        return

      except w2lapp.session.InvalidSessionInstance:
        self.url_redirect(u'LDAPSession not properly initialized.')
        return

      except w2lapp.session.WrongSessionCookie:
        if __debug__:
          self.log_exception(ls)
        self.url_redirect(u'Session hijacking detected by wrong cookie. Access denied!')
        return

      except pyweblib.session.SessionException:
        self.url_redirect(u'Other session handling error.')
        return

    except pyweblib.forms.InvalidRequestMethod:
      pyweblib.httphelper.SimpleMsg(self.outf,'Invalid request method!')

    except:
      # Log unhandled exceptions
      self.log_exception(ls)

    self.outf.flush()
    self.errf.flush()

    # Clean up things
    del self.sid,self.inf,self.outf,self.errf,self.command

    return # handle_request()


class Web2ldapHTTPHandler(msHTTPHandler.HTTPHandlerClass):
  script_name = w2lapp.cnf.standalone.base_url or '/web2ldap'
  base_url = w2lapp.cnf.standalone.base_url
  server_signature = w2lapp.cnf.standalone.server_signature
  server_env = {
    'SERVER_SOFTWARE':'web2ldap %s' % w2lapp.__version__,
    'SERVER_ADMIN':w2lapp.cnf.standalone.server_admin,
    'DOCUMENT_ROOT':w2lapp.cnf.standalone.document_root,
    'SCRIPT_NAME':w2lapp.cnf.standalone.base_url or '/web2ldap',
  }
  dir_listing_allowed = w2lapp.cnf.standalone.dir_listing_allowed
  reverse_lookups = w2lapp.cnf.standalone.reverse_lookups
  access_allowed   = map(IPNetwork,w2lapp.cnf.standalone.access_allowed)
  extensions_map = msHTTPHandler.get_mime_types(w2lapp.cnf.standalone.mime_types)

  # Start web2ldap itself.
  def run_app(self,http_env):
    msHTTPHandler.HTTPHandlerClass.run_app(self,http_env)
    # Call web2ldap application handler
    app = AppHandler(self.rfile,self.wfile,self.error_log,http_env)
    app.run()
    return # end of web2ldapHTTPHandlerClass.run_app()
