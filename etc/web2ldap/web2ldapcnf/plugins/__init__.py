# -*- coding: utf-8 -*-
"""
Plugin modules must be registered here by importing them

Many modules are imported by default which works most of the times.

Some features might be too special so consider this file to be subject
of local configuration and tweak it to your needs.
"""

import re

#---------------------------------------------------------------------------
# Standard enforcement quirks
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.quirks

#---------------------------------------------------------------------------
# X.500 DSAs
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.x500dsa

#---------------------------------------------------------------------------
# Subentries (see RFC 3672)
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.subentries

#---------------------------------------------------------------------------
# NIS (see RFC 2307) and NSS
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.nis
import w2lapp.schema.plugins.ldapns

#---------------------------------------------------------------------------
# Extended plugin classes for NIS attributes with auto-generated
# input values (experimental)
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.posixautogen
w2lapp.schema.plugins.posixautogen.HomeDirectory.homeDirectoryTemplate = '/home/{uid}'
w2lapp.schema.plugins.posixautogen.AutogenUIDNumber.minNewValue = 10000L
w2lapp.schema.plugins.posixautogen.AutogenUIDNumber.maxNewValue = 19999L
w2lapp.schema.plugins.posixautogen.AutogenGIDNumber.minNewValue = 10000L
w2lapp.schema.plugins.posixautogen.AutogenGIDNumber.maxNewValue = 19999L

#---------------------------------------------------------------------------
# sudo-ldap
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.sudoers

# If you solely want to reference group names in 'sudoUser' uncomment following lines
#w2lapp.schema.syntaxes.syntax_registry.registerAttrType(
#  w2lapp.schema.plugins.sudoers.SudoUserGroup.oid,[
#    '1.3.6.1.4.1.15953.9.1.1', # sudoUser
#  ]
#)

#---------------------------------------------------------------------------
# pilotPerson
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.pilotperson

#---------------------------------------------------------------------------
# Just an example for person's schema of stroeder.com
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.msperson

#---------------------------------------------------------------------------
# Various syntaxes and attribute types for OpenLDAP
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.openldap

#---------------------------------------------------------------------------
# Various syntaxes and attribute types for OpenDS
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.opends

#---------------------------------------------------------------------------
# Various syntaxes and work-arounds for MS Active Directory and Exchange 5.5
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.activedirectory
import w2lapp.schema.plugins.exchange
#import w2lapp.schema.plugins.mssfu30

#---------------------------------------------------------------------------
# Various syntaxes and attribute types for Entrust PKI
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.entrust

#---------------------------------------------------------------------------
# Various syntaxes and attribute types for Novell eDirectory
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.edirectory

#---------------------------------------------------------------------------
# Various syntaxes and work-arounds for Domino/LDAP
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.lotusdomino

#---------------------------------------------------------------------------
# Various syntaxes and attribute types for IBM Tivoliy Directory Server
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.ibmds

#---------------------------------------------------------------------------
# Various syntaxes and attribute types for Samba
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.samba

#---------------------------------------------------------------------------
# Various syntaxes and attribute types for VPIM
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.vpim

#---------------------------------------------------------------------------
# For attributes defined in draft-behera-ldap-password-policy
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.ppolicy

#---------------------------------------------------------------------------
# For attributes defined in draft-vchu-ldap-pwd-policy
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.vchupwdpolicy

#---------------------------------------------------------------------------
# Various syntaxes and attribute types for Kerberos V
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.krb5

#---------------------------------------------------------------------------
# Various attribute types for PGP key server
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.pgpkeysrv

#---------------------------------------------------------------------------
# Various attribute types for DHCP server
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.dhcp

#---------------------------------------------------------------------------
# Various attribute types for eduPerson
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.eduperson

#---------------------------------------------------------------------------
# Various attribute types for SCHAC
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.schac

#---------------------------------------------------------------------------
# Various attribute types for DE-Mail
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.demail

#---------------------------------------------------------------------------
# Various ASN.1 data objects
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.asn1objects

#---------------------------------------------------------------------------
# X.509-related LDAP syntaxes defined in RFC 4523
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.x509

#---------------------------------------------------------------------------
# X.509 cert/CRL schema
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.pkcschema

#---------------------------------------------------------------------------
# Attribute types for OpenSSL-LPK
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.opensshlpk

#---------------------------------------------------------------------------
# Syntaxes, attribute types for ACP-133
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.acp133

#---------------------------------------------------------------------------
# Syntaxes, attribute types for OpenDirectory for Mac OS X
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.apple

#---------------------------------------------------------------------------
# Syntaxes, attribute types for Dynamic Groups
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.dyngroup

#---------------------------------------------------------------------------
# Syntaxes, attribute types for Dynamic Entries
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.dds

#---------------------------------------------------------------------------
# Attribute types for FreeRADIUS/LDAP
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.freeradius

#---------------------------------------------------------------------------
# Syntaxes, attribute types for DNS
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.dns

#---------------------------------------------------------------------------
# Univention Corporate Server
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.ucs

#---------------------------------------------------------------------------
# Group related attributes
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.groups

#---------------------------------------------------------------------------
# H.350 Directory Services
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.h350

#---------------------------------------------------------------------------
# Æ-DIR
#---------------------------------------------------------------------------

#import w2lapp.schema.plugins.aedir

#w2lapp.schema.plugins.aedir.AETicketId.reObj = re.compile('^[A-Z]+-[0-9]+$')
#w2lapp.schema.plugins.aedir.AETicketId.html_tmpl = '<a href="https://issues.example.com/browse/{av}">{av}</a>'

#w2lapp.schema.plugins.aedir.AEHostname.html_tmpl = """{av} /
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

#w2lapp.schema.syntaxes.syntax_registry.registerAttrType(
#  w2lapp.schema.plugins.aedir.AEPersonManager.oid,[
#    '0.9.2342.19200300.100.1.10', # manager
#  ],
#  structural_oc_oids=[
#    w2lapp.schema.plugins.aedir.AE_PERSON_OID, # aePerson
#  ],
#)

# for mapping username to bind-DN of form 
#import ldapsession
#ldapsession.LDAPSession = w2lapp.schema.plugins.aedir.AEDirLDAPSession
#w2lapp.schema.plugins.aedir.AEDirLDAPSession.binddn_tmpl = u'uid={username},ou=ae-dir'

# Parameters for generating user names
#w2lapp.schema.plugins.aedir.AEUserId.maxLen = 4
#w2lapp.schema.plugins.aedir.AEUserId.maxCollisionChecks = 15

#---------------------------------------------------------------------------
# Composed attributes for..
#---------------------------------------------------------------------------

# ..object class inetOrgPerson
#import w2lapp.schema.plugins.inetorgperson
#syntax_registry.registerAttrType(
#  w2lapp.schema.plugins.inetorgperson.CNInetOrgPerson.oid,[
#    '2.5.4.3', # commonName
#  ],
#  structural_oc_oids=['2.16.840.1.113730.3.2.2'], # inetOrgPerson
#)
#syntax_registry.registerAttrType(
#  w2lapp.schema.plugins.inetorgperson.DisplayNameInetOrgPerson.oid,[
#    '2.16.840.1.113730.3.1.241', # displayName
#  ],
#  structural_oc_oids=['2.16.840.1.113730.3.2.2'], # inetOrgPerson
#)

#---------------------------------------------------------------------------
# FreeIPA
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.freeipa

#---------------------------------------------------------------------------
# OATH-LDAP
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.oath

#---------------------------------------------------------------------------
# Password self-service stuff (msPwdReset*)
#---------------------------------------------------------------------------

import w2lapp.schema.plugins.mspwdreset

#---------------------------------------------------------------------------
# Add more local or experimental plugins from
# etc/web2ldap/web2ldapcnf/plugins/ here
#---------------------------------------------------------------------------

