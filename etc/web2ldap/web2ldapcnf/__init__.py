# -*- coding: utf-8 -*-
"""
Module web2ldapcnf
(c) by Michael Stroeder <michael@stroeder.com>

Some variables to configure the basic behaviour of web2ldap.py
"""

from __future__ import absolute_import

import sys,os

from web2ldap.app.core import etc_dir,templates_dir

#---------------------------------------------------------------------------
# General options
#---------------------------------------------------------------------------

# Trace output of the LDAP connection can be written to error
# output (if not started with python -O).
# Set to non-zero if you want debug your LDAP connection.
# Warning! Passwords (credentials) are written to this trace log!
# If unsure leave zero! Only set to non-zero if you have protected logs!
ldap_trace_level = 0

# If non-zero this turns on debug output of the OpenLDAP libs.
# Warning! Confidential information might be disclosed to the log!
# If unsure leave zero! Only set to non-zero if you have protected logs!
ldap_opt_debug_level = 0

# Maximum length of LDIF data in the <TEXTAREA> of addform/modifyform
ldif_maxbytes = 200000

# List of URL schemes to process in LDIF input.
# !!! Beware, this can be a security nightmare! Think twice!
# If unsure leave as empty list to ignore all URLs in LDIF.
#ldif_url_schemes = ['http','ftp']
ldif_url_schemes = []

# Maximum count of input attribute fields in addform/modifyform
input_maxattrs=3000

# Maximum length of attribute values in input fields in addform/modifyform
input_maxfieldlen = 600000

# maximum count of search parameters in a search form
max_searchparams = 20

# Path name to dumpasn1.cfg. Grab it from
# https://www.cs.auckland.ac.nz/~pgut001/dumpasn1.cfg
dumpasn1cfg = os.path.join(etc_dir,'dumpasn1.cfg')

#---------------------------------------------------------------------------
# Global HTML options (templates etc.)
#---------------------------------------------------------------------------

# Template for initial connect dialogue
connect_template = os.path.join(templates_dir,'connect.html')

# Template for redirect page
redirect_template = os.path.join(templates_dir,'redirect.html')

# Separator to be used between internal web2ldap links in the middle area
command_link_separator = ' &bull; '

#---------------------------------------------------------------------------
# Global security options
#---------------------------------------------------------------------------

# Maximum number of concurrent web sessions stored
session_limit = 40

# Maximum number of concurrent web sessions per remote IP
session_per_ip_limit = 8

# Amount of time in seconds after which inactive sessions will be expired
# and the session data is removed silently without the possibility to relogin.
session_remove = 1800

# List of environment variables assumed to be constant throughout
# web sessions with the same ID if existent.
# These env vars are cross-checked each time when restoring an
# web session to reduce the risk of session-hijacking.
session_checkvars = (
  # REMOTE_ADDR and REMOTE_HOST might not be constant if the client
  # access comes through a network of web proxy siblings.
  'REMOTE_ADDR','REMOTE_HOST',
  'REMOTE_IDENT','REMOTE_USER',
  # If the proxy sets them but can be easily spoofed
  'FORWARDED_FOR','HTTP_X_FORWARDED_FOR',
  # These few are not really secure but better than nothing
  'HTTP_USER_AGENT','HTTP_ACCEPT_CHARSET',
  'HTTP_ACCEPT_LANGUAGE',
  'HTTP_HOST',
  # SSL parameters negotiated within a SSL connection
  'SSL_CIPHER_ALGKEYSIZE','HTTPS_KEYSIZE','SSL_KEYSIZE','SSL_SERVER_KEY_SIZE',
  'SSL_CIPHER_EXPORT','HTTPS_EXPORT','SSL_EXPORT',
  'SSL_CIPHER','HTTPS_CIPHER','SSL_PROTOCOL',
  'SSL_CIPHER_USEKEYSIZE','HTTPS_SECRETKEYSIZE','SSL_SECKEYSIZE',
  'SSL_TLS_SNI','SSL_SECURE_RENEG','SSL_CLIENT_VERIFY',
  # env vars of client certs used for SSL strong authentication
  'SSL_CLIENT_V_START','SSL_CLIENT_V_END',
  'SSL_CLIENT_I_DN','SSL_CLIENT_IDN',
  'SSL_CLIENT_S_DN','SSL_CLIENT_SDN',
  'SSL_CLIENT_M_SERIAL','SSL_CLIENT_CERT_SERIAL',
  # HTTP_ACCEPT_ENCODING disabled because of Google Chrome
#  'HTTP_ACCEPT_ENCODING',
  # SSL session ID if running on SSL server capable
  # of reusing SSL sessions (needs server configuration)
  # not usable with newer TLS implementations though
#  'SSL_SESSION_ID',
)

# Static dict of HTTP headers to be always sent to the browser
http_headers = {
  'Pragma':'no-cache',
  'Cache-Control':'no-store,no-cache,max-age=0,must-revalidate',
  'X-XSS-Protection':'1; mode=block',
  # Disable DNS prefetching
  'X-DNS-Prefetch-Control':'off',
  # disable MIME sniffing in MS IE
  'X-Content-Type-Options':'nosniff',
  # frames not used at all (see also draft-ietf-websec-x-frame-options)
  'X-Frame-Options':'deny',
  'Frame-Options':'DENY',
  # break out of frames
  'Window-Target':'_top',
  # Referer sending policy (see also https://www.w3.org/TR/referrer-policy/)
  'Referrer-Policy':'no-referrer',
  # Content Security Policy
  'Content-Security-Policy':' '.join((
      "child-src 'none';",
      "connect-src 'none';",
      "default-src 'none';",
      "font-src 'self';",
      "form-action 'self';",
      "frame-ancestors 'none';",
      "frame-src 'none';",
      "img-src 'self' data:;",
      "script-src 'none';",
      "style-src 'self';",
#    "report-uri https://logger.example.com/csp-error-handler",
  )),
}
http_headers['X-Webkit-CSP'] = http_headers['Content-Security-Policy']
http_headers['X-Content-Security-Policy'] = http_headers['Content-Security-Policy']

# Number of chars to use for cookie
# 0 or None disables using cookies
cookie_length = 2*42

# Cookie lifetime in seconds
cookie_max_age = 86400

# Cookie domain to send with Set-Cookie (DNS name)
# None lets web2ldap send the hostname
cookie_domain = None

# If non-zero this is the time-span in seconds after which a
# new session ID is generated.
# Disadvantage: The browser's back button does not work anymore.
session_paranoid = 0

# Specifies a list of the acceptable symmetric key ciphers to
# reach security level 1.
sec_sslacceptedciphers = (
  # some PFS ciphers
  'ECDHE-RSA-AES256-GCM-SHA384',
  'ECDHE-RSA-AES256-SHA384',
  'ECDHE-RSA-AES256-SHA',
  'DHE-RSA-AES256-GCM-SHA384',
  'DHE-RSA-AES256-SHA256',
  'DHE-RSA-AES256-SHA',
  'ECDH-RSA-AES256-GCM-SHA384',
  'ECDHE-RSA-AES128-GCM-SHA256',
  'ECDHE-RSA-AES128-SHA256',
  'ECDHE-RSA-AES128-SHA',
  'DHE-RSA-AES128-GCM-SHA256',
  'DHE-RSA-AES128-SHA256',
  'DHE-RSA-AES128-SHA',
  'ECDH-RSA-AES128-GCM-SHA256',
)

# unsuspicious target URLs accept by redirector even without a session
good_redirect_targets=set((
  'https://web2ldap.de/',
  'https://www.web2ldap.de/',
))

# Dictionary specifying accepted address/net mask strings of
# accepted client addresses for certain URL commands.
# Use [u'0.0.0.0/0.0.0.0',u'::0'] to allow access to every client but think twice!
# IPv6 network addresses without brackets!
access_allowed = {
  u'_':[
#    u'0.0.0.0/0.0.0.0',u'::0',
    u'127.0.0.0/255.0.0.0',
    u'::1',
    u'fe00::0',
#    u'10.0.0.0/255.0.0.0',
  ],
  u'monitor':[
    u'127.0.0.0/255.0.0.0',
    u'::1',
    u'fe00::0',
  ],
  u'locate':[
#    u'0.0.0.0/0.0.0.0',u'::0',
    u'127.0.0.0/255.0.0.0',
    u'::1',
    u'fe00::0',
#    u'10.0.0.0/255.0.0.0',
  ],
}

#---------------------------------------------------------------------------
# Import plugins in sub-config
#---------------------------------------------------------------------------

import web2ldapcnf.plugins

#---------------------------------------------------------------------------
# Optionally import a local sub-config file
#---------------------------------------------------------------------------

try:
  import web2ldapcnf.local
except ImportError,e:
  sys.stderr.write('WARNING: Importing local config failed: %s\n' % (str(e)))
