# -*- coding: utf-8 -*-
"""
web2ldapcnf/standalone.py
Options for web2ldap running as stand-alone HTTP server

(c) by Michael Stroeder <michael@stroeder.com>

Note that these options does not affect FastCGI mode at all!
"""

# Leave this alone
import os,web2ldapcnf

# The address to bind to 'host:port'
# Set to '0.0.0.0:1760' to listen on port 1760 of every interface
# in your system
bind_address = '127.0.0.1:1760' # IPv4

# List of accepted address/net mask strings of
# accepted client addresses.
# Use ['0.0.0.0/0.0.0.0','::0'] to allow access to every client but think twice!
# IPv6 network addresses without brackets!
access_allowed = [
  '127.0.0.0/255.0.0.0',
  '::1',
  'fe00::0',
#  '10.0.0.0/255.0.0.0',
#  '0.0.0.0/0.0.0.0','::0',
]

# User account name to setuid after being started as root
run_username = 'web2ldap'

# Contact mail address of the server admin when running stand-alone
server_admin = 'feedback@web2ldap.de'

# Server signature when running stand-alone, HTML snippet,
server_signature = """<ADDRESS>%(SERVER_SOFTWARE)s at
<A HREF="mailto:%(SERVER_ADMIN)s">%(SERVER_NAME)s</A>
Port %(SERVER_PORT)s</ADDRESS>
"""

# Listing of directory content (0=disabled, 1=enabled)
dir_listing_allowed = 0

# Reverse lookup of client address (0=disabled, 1=enabled)
reverse_lookups = 0

# Set a base URL of the application (handy for running via reverse proxy)
# Set None to let web2ldap determine the base URL automatically from
# CGI-BIN environment var SCRIPT_NAME
#base_url = 'http://localhost/web2ldap-rev'
base_url = None

########################################################################
# Misc. path names of needed files and directories
########################################################################

# Path name of PID file
pid_file = os.path.join(web2ldapcnf.var_run,'web2ldap-standalone.pid')

# Path name of access log file
access_log = os.path.join(web2ldapcnf.var_log,'web2ldap_access_log')

# Path name of error log file
error_log = os.path.join(web2ldapcnf.var_log,'web2ldap_error_log')

# Path name of debug log file
debug_log = os.path.join(web2ldapcnf.var_log,'web2ldap_debug_log')

# Where static documents reside
document_root = os.path.join(web2ldapcnf.web2ldap_dir,'htdocs')

# Path name of mime.types file
mime_types = '/etc/mime.types'

