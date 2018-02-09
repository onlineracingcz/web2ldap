#!/usr/bin/python2.7 -ROO
# -*- coding: utf-8 -*-
"""
This script checks all the prerequisites for running
a particular release version of web2ldap.
"""

import sys,os,imp,socket,pprint,platform
from distutils.version import StrictVersion

MINIMUM_PYTHON_VERSION = (2,7,0)

print '*** Checking installation prerequisites for web2ldap ***'

exec_startdir = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0])))
sys.path.insert(0,os.path.join(exec_startdir,'pylib'))

print """Make sure to run this script with the same Python
interpreter executable you plan to invoke web2ldap with!

***Python interpreter***"""

print 'sys.executable',repr(sys.executable)
print 'sys.prefix',repr(sys.prefix)
print 'sys.exec_prefix',repr(sys.exec_prefix)
print 'sys.version',repr(sys.version)
print 'sys.maxunicode',sys.maxunicode,hex(sys.maxunicode)
minimum_major,minimum_minor,minimum_micro = MINIMUM_PYTHON_VERSION
if sys.version_info.minor > minimum_major:
  print 'Python 3 not supported.'
if not (sys.version_info.major==minimum_major and sys.version_info[1]>=minimum_minor):
  print 'Python %s or newer is required! Detected %s.' % ('.'.join(map(str,MINIMUM_PYTHON_VERSION)),repr(sys.version))

print 'sys.platform',repr(sys.platform)
print 'platform.platform()',repr(platform.platform())
print 'os.name',repr(os.name)
print 'socket.has_ipv6',repr(socket.has_ipv6)

if sys.platform=='linux2':
  print 'platform.linux_distribution()',repr(platform.linux_distribution())
  print 'platform.libc_ver()',repr(platform.libc_ver())

try:
  import sysconfig
except ImportError:
  pass
else:
  print '*** sysconfig.get_paths() ***'
  print pprint.pformat(sysconfig.get_paths())
  print '*** sys.path ***'
  print pprint.pformat(sys.path)
  print 'sysconfig.get_python_version()',sysconfig.get_python_version()
  print 'sysconfig.get_platform():',sysconfig.get_platform()
  print 'sysconfig.is_python_build()',sysconfig.is_python_build()

print '*** Installed modules ***'

modules = {}
missing = []

for modulename,mandantory,min_version,url,desc in [
  ('w2lapp',1,None,'https://www.web2ldap.de','Internal web2ldap application module'),
  ('ldap',1,'2.4.0','https://www.python-ldap.org','Module package for accessing LDAP servers'),
  ('ldapurl',1,'2.4.0','https://www.python-ldap.org','LDAP URL support'),
  ('ldif',1,'2.4.0','https://www.python-ldap.org','LDIF support'),
  ('pyasn1',1,None,'http://pyasn1.sf.net','ASN.1 module'),
  ('pyasn1_modules',1,None,'http://pyasn1.sf.net','ASN.1 LDAP module'),
  ('netaddr',1,None,'https://pypi.python.org/pypi/netaddr','IP address module'),
  ('xml.sax',1,None,'https://www.python.org',"Python's built-in XML support"),
  ('xml.sax.handler',1,None,'https://www.python.org',"Python's built-in XML support"),
  ('hashlib',1,None,'https://www.python.org','Module useful for generating hashed LDAP passwords'),
  ('xml.etree',0,None,'http://effbot.org/zone/element.htm','ElementTree XML parser'),
  ('pyweblib',1,'1.3.8','http://www.stroeder.com/pylib/PyWebLib/','Yet another web application module package'),
  ('fcgi',0,None,'http://alldunn.com/python/fcgi.py','FCGI module (e.g., Apache with mod_fastcgi)'),
  ('crypt',0,None,'https://www.python.org','Unix crypt hash module for client-side hashed LDAP passwords'),
  ('DNS',0,None,'http://pydns.sf.net','module for DNS lookups, e.g. SRV RRs'),
  ('M2Crypto',0,None,'https://pypi.python.org/pypi/M2Crypto','Python wrapper module for OpenSSL'),
  ('paramiko',0,None,'https://pypi.python.org/pypi/paramiko','Python implementation of SSH protocol'),
  ('PIL',0,None,'http://www.pythonware.com/products/pil/index.htm','Python Imaging Library'),
  ('pyExcelerator',0,None,'http://pyexcelerator.sourceforge.net/','Generates/imports Excel files'),
]:
  error_text_prefix={0:'Warning!',1:'Fatal Error!'}[mandantory]
  m_list = modulename.split('.')
  i = 0
  while i<len(m_list):
    m = m_list[i]
    f = None
    try:
      f, pathname, description = imp.find_module(m,sys.path)
    except ImportError,e:
      missing.append(m)
      print '%s Module %s (%s) not found: %s' % (error_text_prefix,modulename,desc,str(e))
    else:
      if i+1<len(m_list):
        sys.path.append(pathname)
        i += 1
        continue
      try:
        modules[m] = imp.load_module(m, f, pathname, description)
      except ImportError,e:
        missing.append(m)
        print '%s Unable to load module %s (%s): %s' % (error_text_prefix,modulename,desc,str(e))
      else:
        try:
          version = modules[m].__version__
        except AttributeError:
          version = 'unspecified'
        if min_version!=None and version!='unspecified' and StrictVersion(version)<StrictVersion(min_version):
          print '%s Imported module %s version %s too old. Need at least %s: %s' % (error_text_prefix,modulename,version,min_version,desc)
        else:
          print 'Module %s (version %s) successfully imported: %s' % (modulename,version,desc)
    if f:
      f.close()
    i += 1

try:
  import ldap,_ldap
except ImportError:
  pass
else:
  # Display version numbers of OpenLDAP libs
  print '*** OpenLDAP libs ***'
  print 'ldap.API_VERSION: %s' % (ldap.API_VERSION)
  print 'ldap.VENDOR_VERSION: %s' % (ldap.VENDOR_VERSION)
  # Check whether built with SSL/TLS (OpenSSL)
  print '*** Suport for SSL/TLS ***'
  if hasattr(ldap,'TLS_AVAIL'):
    if hasattr(ldap,'OPT_X_TLS_PACKAGE'):
      tls_package = ' (%s)' % ldap.get_option(ldap.OPT_X_TLS_PACKAGE)
    else:
      tls_package = ''
    print 'ldap.TLS_AVAIL: %s%s' % ({0:'no',1:'yes'}[ldap.TLS_AVAIL],tls_package)
  # Check whether built with SASL (Cyrus-SASL)
  print '*** Suport for SASL ***'
  if hasattr(ldap,'SASL_AVAIL'):
    print 'ldap.SASL_AVAIL: %s' % ({0:'no',1:'yes'}[ldap.SASL_AVAIL])
  print '*** ldap.OPT_API_INFO ***'
  if hasattr(ldap,'OPT_API_INFO'):
    pprint.pprint(ldap.get_option(ldap.OPT_API_INFO))
