# -*- coding: utf-8 -*-
"""
Plugin modules must be registered here by importing them

Many modules are imported by default which works most of the times.

Some features might be too special so consider this file to be subject
of local configuration and tweak it to your needs.
"""

from __future__ import absolute_import

import re

#---------------------------------------------------------------------------
# Standard enforcement quirks
#---------------------------------------------------------------------------

import web2ldap.app.plugins.quirks

#---------------------------------------------------------------------------
# X.500 DSAs
#---------------------------------------------------------------------------

import web2ldap.app.plugins.x500dsa

#---------------------------------------------------------------------------
# Subentries (see RFC 3672)
#---------------------------------------------------------------------------

import web2ldap.app.plugins.subentries

#---------------------------------------------------------------------------
# NIS (see RFC 2307) and NSS
#---------------------------------------------------------------------------

import web2ldap.app.plugins.nis
import web2ldap.app.plugins.ldapns

#---------------------------------------------------------------------------
# Extended plugin classes for NIS attributes with auto-generated
# input values (experimental)
#---------------------------------------------------------------------------

import web2ldap.app.plugins.posixautogen
web2ldap.app.plugins.posixautogen.HomeDirectory.homeDirectoryTemplate = '/home/{uid}'
web2ldap.app.plugins.posixautogen.AutogenUIDNumber.minNewValue = 10000L
web2ldap.app.plugins.posixautogen.AutogenUIDNumber.maxNewValue = 19999L
web2ldap.app.plugins.posixautogen.AutogenGIDNumber.minNewValue = 10000L
web2ldap.app.plugins.posixautogen.AutogenGIDNumber.maxNewValue = 19999L

#---------------------------------------------------------------------------
# sudo-ldap
#---------------------------------------------------------------------------

import web2ldap.app.plugins.sudoers

# If you solely want to reference group names in 'sudoUser' uncomment following lines
#web2ldap.app.schema.syntaxes.syntax_registry.registerAttrType(
#  web2ldap.app.plugins.sudoers.SudoUserGroup.oid,[
#    '1.3.6.1.4.1.15953.9.1.1', # sudoUser
#  ]
#)

#---------------------------------------------------------------------------
# pilotPerson
#---------------------------------------------------------------------------

import web2ldap.app.plugins.pilotperson

#---------------------------------------------------------------------------
# Just an example for person's schema of stroeder.com
#---------------------------------------------------------------------------

import web2ldap.app.plugins.msperson

#---------------------------------------------------------------------------
# Various syntaxes and attribute types for OpenLDAP
#---------------------------------------------------------------------------

import web2ldap.app.plugins.openldap

#---------------------------------------------------------------------------
# Various syntaxes and attribute types for OpenDS
#---------------------------------------------------------------------------

import web2ldap.app.plugins.opends

#---------------------------------------------------------------------------
# Various syntaxes and work-arounds for MS Active Directory and Exchange 5.5
#---------------------------------------------------------------------------

import web2ldap.app.plugins.activedirectory
import web2ldap.app.plugins.exchange
#import web2ldap.app.plugins.mssfu30

#---------------------------------------------------------------------------
# Various syntaxes and attribute types for Entrust PKI
#---------------------------------------------------------------------------

import web2ldap.app.plugins.entrust

#---------------------------------------------------------------------------
# Various syntaxes and attribute types for Novell eDirectory
#---------------------------------------------------------------------------

import web2ldap.app.plugins.edirectory

#---------------------------------------------------------------------------
# Various syntaxes and work-arounds for Domino/LDAP
#---------------------------------------------------------------------------

import web2ldap.app.plugins.lotusdomino

#---------------------------------------------------------------------------
# Various syntaxes and attribute types for IBM Tivoliy Directory Server
#---------------------------------------------------------------------------

import web2ldap.app.plugins.ibmds

#---------------------------------------------------------------------------
# Various syntaxes and attribute types for Samba
#---------------------------------------------------------------------------

import web2ldap.app.plugins.samba

#---------------------------------------------------------------------------
# Various syntaxes and attribute types for VPIM
#---------------------------------------------------------------------------

import web2ldap.app.plugins.vpim

#---------------------------------------------------------------------------
# For attributes defined in draft-behera-ldap-password-policy
#---------------------------------------------------------------------------

import web2ldap.app.plugins.ppolicy

#---------------------------------------------------------------------------
# For attributes defined in draft-vchu-ldap-pwd-policy
#---------------------------------------------------------------------------

import web2ldap.app.plugins.vchupwdpolicy

#---------------------------------------------------------------------------
# Various syntaxes and attribute types for Kerberos V
#---------------------------------------------------------------------------

import web2ldap.app.plugins.krb5

#---------------------------------------------------------------------------
# Various attribute types for PGP key server
#---------------------------------------------------------------------------

import web2ldap.app.plugins.pgpkeysrv

#---------------------------------------------------------------------------
# Various attribute types for DHCP server
#---------------------------------------------------------------------------

import web2ldap.app.plugins.dhcp

#---------------------------------------------------------------------------
# Various attribute types for eduPerson
#---------------------------------------------------------------------------

import web2ldap.app.plugins.eduperson

#---------------------------------------------------------------------------
# Various attribute types for SCHAC
#---------------------------------------------------------------------------

import web2ldap.app.plugins.schac

#---------------------------------------------------------------------------
# Various attribute types for DE-Mail
#---------------------------------------------------------------------------

import web2ldap.app.plugins.demail

#---------------------------------------------------------------------------
# Various ASN.1 data objects
#---------------------------------------------------------------------------

import web2ldap.app.plugins.asn1objects

#---------------------------------------------------------------------------
# X.509-related LDAP syntaxes defined in RFC 4523
#---------------------------------------------------------------------------

import web2ldap.app.plugins.x509

#---------------------------------------------------------------------------
# X.509 cert/CRL schema
#---------------------------------------------------------------------------

import web2ldap.app.plugins.pkcschema

#---------------------------------------------------------------------------
# Attribute types for OpenSSL-LPK
#---------------------------------------------------------------------------

import web2ldap.app.plugins.opensshlpk

#---------------------------------------------------------------------------
# Syntaxes, attribute types for ACP-133
#---------------------------------------------------------------------------

import web2ldap.app.plugins.acp133

#---------------------------------------------------------------------------
# Syntaxes, attribute types for OpenDirectory for Mac OS X
#---------------------------------------------------------------------------

import web2ldap.app.plugins.apple

#---------------------------------------------------------------------------
# Syntaxes, attribute types for Dynamic Groups
#---------------------------------------------------------------------------

import web2ldap.app.plugins.dyngroup

#---------------------------------------------------------------------------
# Syntaxes, attribute types for Dynamic Entries
#---------------------------------------------------------------------------

import web2ldap.app.plugins.dds

#---------------------------------------------------------------------------
# Attribute types for FreeRADIUS/LDAP
#---------------------------------------------------------------------------

import web2ldap.app.plugins.freeradius

#---------------------------------------------------------------------------
# Syntaxes, attribute types for DNS
#---------------------------------------------------------------------------

import web2ldap.app.plugins.dns

# to allow trailing dot in fully-qualified domain names in all plugin
# classes derived from syntax base class DNSDomain
#import re, web2ldap.app.schema.syntaxes
#web2ldap.app.schema.syntaxes.DNSDomain.reObj = re.compile('^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]*)*$')

#---------------------------------------------------------------------------
# Univention Corporate Server
#---------------------------------------------------------------------------

import web2ldap.app.plugins.ucs

#---------------------------------------------------------------------------
# Group related attributes
#---------------------------------------------------------------------------

import web2ldap.app.plugins.groups

#---------------------------------------------------------------------------
# H.350 Directory Services
#---------------------------------------------------------------------------

import web2ldap.app.plugins.h350

#---------------------------------------------------------------------------
# Æ-DIR
#---------------------------------------------------------------------------

import web2ldap.app.plugins.aedir

#web2ldap.app.plugins.aedir.AETicketId.reObj = re.compile('^[A-Z]+-[0-9]+$')
#web2ldap.app.plugins.aedir.AETicketId.html_tmpl = '<a href="https://issues.example.com/browse/{av}">{av}</a>'

#web2ldap.app.plugins.aedir.AEHostname.html_tmpl = """{av} /
#<a href="telnet://{av}"
#   title="Connect via Telnet">Telnet</a> /
#<a href="ssh://{av}"
#   title="Connect via SSH">SSH</a> /
#<a href="https://cmdb.example.com/hosts/{av}"
#   title="Lookup in Configuration Management Database">CMDB</a> /
#<a href="https://monitoring.example.com/hosts/{av}"
#   title="Monitoring system">Mon</a> /
#<a href="https://dnsadmin.example.com/dns/{av}"
#   title="DNS entry">DNS</a>
#"""

# for mapping username to bind-DN of form
#import ldapsession
#ldapsession.LDAPSession = web2ldap.app.plugins.aedir.AEDirLDAPSession
#web2ldap.app.plugins.aedir.AEDirLDAPSession.binddn_tmpl = u'uid={username},ou=ae-dir'

# Parameters for generating user names
#web2ldap.app.plugins.aedir.AEUserUid.maxLen = 4
#web2ldap.app.plugins.aedir.AEUserUid.maxCollisionChecks = 15

#---------------------------------------------------------------------------
# Composed attributes for..
#---------------------------------------------------------------------------

# ..object class inetOrgPerson
#import web2ldap.app.plugins.inetorgperson
#syntax_registry.registerAttrType(
#  web2ldap.app.plugins.inetorgperson.CNInetOrgPerson.oid,[
#    '2.5.4.3', # commonName
#  ],
#  structural_oc_oids=['2.16.840.1.113730.3.2.2'], # inetOrgPerson
#)
#syntax_registry.registerAttrType(
#  web2ldap.app.plugins.inetorgperson.DisplayNameInetOrgPerson.oid,[
#    '2.16.840.1.113730.3.1.241', # displayName
#  ],
#  structural_oc_oids=['2.16.840.1.113730.3.2.2'], # inetOrgPerson
#)

#---------------------------------------------------------------------------
# FreeIPA
#---------------------------------------------------------------------------

import web2ldap.app.plugins.freeipa

#---------------------------------------------------------------------------
# OATH-LDAP
#---------------------------------------------------------------------------

import web2ldap.app.plugins.oath

#---------------------------------------------------------------------------
# Password self-service stuff (msPwdReset*)
#---------------------------------------------------------------------------

import web2ldap.app.plugins.mspwdreset

#---------------------------------------------------------------------------
# Add more local plugins here
#---------------------------------------------------------------------------

