# -*- coding: utf-8 -*-
"""
web2ldap.app.schema.syntaxes: classes for known attribute types

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
import re
import imghdr
import sndhdr
import urllib
import uuid
import datetime
import time
import json
import inspect
import warnings
import xml.etree.ElementTree
from xml.etree.ElementTree import ParseError as XMLParseError
from collections import defaultdict
from io import BytesIO

# Detect Python Imaging Library (PIL)
try:
    from PIL import Image as PILImage
except ImportError:
    PILImage = None
else:
    warnings.simplefilter('error', PILImage.DecompressionBombWarning)

import ipaddress

import ldap0
import ldap0.ldapurl
import ldap0.schema.models

import web2ldapcnf

from web2ldap.pisces import asn1

import web2ldap.web.forms
import web2ldap.msbase
import web2ldap.mspki.asn1helper
import web2ldap.ldaputil
import web2ldap.app.gui
import web2ldap.utctime
from web2ldap.utctime import strftimeiso8601
from web2ldap.ldaputil import is_dn
from web2ldap.ldaputil.oidreg import OID_REG
from web2ldap.log import logger


class SyntaxRegistry(object):
    """
    syntax registry used to register plugin classes
    """

    def __init__(self):
        self.oid2syntax = ldap0.cidict.cidict()
        self.at2syntax = defaultdict(dict)

    def reg_syntax(self, cls):
        """
        register a syntax classes for an OID
        """
        logger.debug('Register syntax class %r with OID %r', cls.__name__, cls.oid)
        # FIX ME!
        # A better approach for unique syntax plugin class registration which
        # allows overriding older registration is needed.
        if cls.oid in self.oid2syntax and cls != self.oid2syntax[cls.oid]:
            raise ValueError(
                (
                    'Failed to register syntax class %s.%s with OID %s,'
                    ' already registered by %s.%s'
                ) % (
                    cls.__module__,
                    cls.__name__,
                    repr(cls.oid),
                    self.oid2syntax[cls.oid].__module__,
                    self.oid2syntax[cls.oid].__name__,
                )
            )
        self.oid2syntax[cls.oid] = cls

    def reg_syntaxes(self, modulename):
        """
        register all syntax classes found in given module
        """
        logger.debug('Register syntax classes from module %r', modulename)
        for _, cls in inspect.getmembers(sys.modules[modulename], inspect.isclass):
            if hasattr(cls, 'oid'):
                self.reg_syntax(cls)

    def reg_at(self, syntax_oid, attr_types, structural_oc_oids=None):
        """
        register an attribute type (by OID) to explicitly use a certain LDAPSyntax class
        """
        structural_oc_oids = filter(None, map(str.strip, structural_oc_oids or [])) or [None]
        for a in attr_types:
            a = a.strip()
            for oc_oid in structural_oc_oids:
                # FIX ME!
                # A better approach for unique attribute type registration which
                # allows overriding older registration is needed.
                if a in self.at2syntax and oc_oid in self.at2syntax[a]:
                    logger.warn(
                        (
                            'Registering attribute type %r with syntax %r'
                            ' overrides existing registration with syntax %r'
                        ),
                        a,
                        syntax_oid,
                        self.at2syntax[a],
                    )
                self.at2syntax[a][oc_oid] = syntax_oid

    def get_syntax(self, schema, attrtype_nameoroid, structural_oc=None):
        """
        returns LDAPSyntax class for given attribute type
        """
        attrtype_oid = schema.getoid(
            ldap0.schema.models.AttributeType,
            attrtype_nameoroid.strip(),
        )
        if structural_oc:
            structural_oc_oid = schema.getoid(
                ldap0.schema.models.ObjectClass,
                structural_oc.strip(),
            )
        else:
            structural_oc_oid = None
        syntax_oid = LDAPSyntax.oid
        try:
            syntax_oid = self.at2syntax[attrtype_oid][structural_oc_oid]
        except KeyError:
            try:
                syntax_oid = self.at2syntax[attrtype_oid][None]
            except KeyError:
                attrtype_se = schema.get_inheritedobj(
                    ldap0.schema.models.AttributeType,
                    attrtype_oid,
                    ['syntax'],
                )
                if attrtype_se and attrtype_se.syntax:
                    syntax_oid = attrtype_se.syntax
        try:
            syntax_class = self.oid2syntax[syntax_oid]
        except KeyError:
            syntax_class = LDAPSyntax
        return syntax_class

    def get_at(self, app, dn, schema, attrType, attrValue, entry=None):
        """
        returns LDAPSyntax instance fully initialized for given attribute
        """
        if entry:
            structural_oc = entry.get_structural_oc()
        else:
            structural_oc = None
        syntax_class = self.get_syntax(schema, attrType, structural_oc)
        attr_instance = syntax_class(app, dn, schema, attrType, attrValue, entry)
        return attr_instance

    def check(self):
        """
        check whether attribute registry dict contains references by OID
        for which no LDAPSyntax class are registered
        """
        logger.debug(
            'Checking %d LDAPSyntax classes and %d attribute type mappings',
            len(self.oid2syntax),
            len(self.at2syntax),
        )
        for at in self.at2syntax:
            for oc in self.at2syntax[at]:
                if self.at2syntax[at][oc] not in self.oid2syntax:
                    logger.warn('No LDAPSyntax registered for (%r, %r)', at, oc)


####################################################################
# Classes of known syntaxes
####################################################################


class LDAPSyntaxValueError(ValueError):
    pass


class LDAPSyntaxRegexNoMatch(LDAPSyntaxValueError):
    pass


class LDAPSyntax(object):
    oid = ''
    desc = 'Any LDAP syntax'
    inputSize = 50
    maxLen = web2ldapcnf.input_maxfieldlen
    maxValues = web2ldapcnf.input_maxattrs
    mimeType = 'application/octet-stream'
    fileExt = 'bin'
    editable = 1
    reObj = None
    input_pattern = None
    searchSep = '<br>'
    readSep = '<br>'
    fieldSep = '<br>'
    fieldCountAssert = 1
    simpleSanitizers = tuple()
    showValueButton = True

    def __init__(self, app, dn, schema, attrType, attrValue, entry=None):
        if not entry:
            entry = ldap0.schema.models.Entry(schema, dn.encode(app.ls.charset), {})
        assert isinstance(dn, unicode), \
            TypeError("Argument 'dn' must be unicode, was %r" % (dn))
        assert isinstance(attrType, bytes) or attrType is None, \
            TypeError("Argument 'attrType' must be bytes or None, was %r" % (attrType))
        assert isinstance(attrValue, bytes) or attrValue is None, \
            TypeError("Argument 'attrValue' must be bytes or None, was %r" % (attrValue))
        assert entry is None or isinstance(entry, ldap0.schema.models.Entry), \
            TypeError('entry must be ldaputil.schema.Entry, was %r' % (entry))
        self._at = attrType
        self._av = attrValue
        self._app = app
        self._schema = schema
        self._dn = dn
        self._entry = entry

    def sanitize(self, attrValue):
        """
        Transforms the HTML form input field values into LDAP string
        representations and returns raw binary string.

        This is the inverse of LDAPSyntax.formValue().

        When using this method one MUST NOT assume that the whole entry is
        present.
        """
        for sani_func in self.simpleSanitizers:
            attrValue = sani_func(attrValue)
        return attrValue

    def transmute(self, attrValues):
        """
        This method can be implemented to transmute attribute values and has
        to handle LDAP string representations (raw binary strings).

        This method has access to the whole entry after processing all input.

        Implementors should be prepared that this method could be called
        more than once. If there's nothing to change then simply return the
        same value list.

        Exceptions KeyError or IndexError are caught by the calling code to
        re-iterate invoking this method.
        """
        return attrValues

    def _regexValidate(self, attrValue):
        if self.reObj and (self.reObj.match(attrValue) is None):
            raise LDAPSyntaxRegexNoMatch, \
                "Class %s: %r does not match pattern %r." % (
                    self.__class__.__name__,
                    attrValue,
                    self.reObj.pattern,
                )
        return # _regexValidate()

    def _validate(self, attrValue):
        return True

    def validate(self, attrValue):
        if attrValue:
            if not self._validate(attrValue):
                raise LDAPSyntaxValueError, \
                  "Class %s: %r does not comply to syntax (attr type %r)." % (
                      self.__class__.__name__,
                      attrValue,
                      self._at,
                  )
            self._regexValidate(attrValue)

    def valueButton(self, command, row, mode, link_text=None):
        """
        return HTML markup of [+] or [-] submit buttons for adding/removing
        attribute values

        row
          row number in input table
        mode
          '+' or '-'
        link_text
          optionally override displayed link link_text
        """
        link_text = link_text or mode
        if (
                not self.showValueButton or
                self.maxValues <= 1 or
                len(self._entry.get(self._at, [])) >= self.maxValues
            ):
            return ''
        se = self._schema.get_obj(ldap0.schema.models.AttributeType, self._at)
        if se and se.single_value:
            return ''
        return (
            '<button'
            ' formaction="%s#in_a_%s"'
            ' type="submit"'
            ' name="in_mr"'
            ' value="%s%d">%s'
            '</button>'
        ) % (
            self._app.form.action_url(command, self._app.sid),
            self._app.form.utf2display(self._app.ls.uc_decode(self._at)[0]),
            mode, row, link_text
        )

    def formValue(self):
        """
        Transform LDAP string representations to HTML form input field
        values. Returns Unicode string to be encoded with the browser's
        accepted charset.

        This is the inverse of LDAPSyntax.sanitize().
        """
        try:
            result = self._app.ls.uc_decode(self._av or '')[0]
        except UnicodeDecodeError:
            result = u'!!!snipped because of UnicodeDecodeError!!!'
        return result

    def formFields(self):
        return (self.formField(),)

    def formField(self):
        input_field = web2ldap.web.forms.Input(
            self._at,
            ': '.join([self._at, self.desc]),
            self.maxLen,
            self.maxValues,
            self.input_pattern,
            default=None,
            size=min(self.maxLen, self.inputSize),
        )
        input_field.charset = self._app.form.accept_charset
        input_field.set_default(self.formValue())
        return input_field

    def getMimeType(self):
        return self.mimeType

    def displayValue(self, valueindex=0, commandbutton=False):
        if ldap0.ldapurl.isLDAPUrl(self._av):
            displayer_class = LDAPUrl
        elif Uri.reObj.match(self._av) is not None:
            displayer_class = Uri
        elif GeneralizedTime.reObj.match(self._av) is not None:
            displayer_class = GeneralizedTime
        elif RFC822Address.reObj.match(self._av) is not None:
            displayer_class = RFC822Address
        else:
            displayer_class = DirectoryString
        # Crude hack
        self_class = self.__class__
        self.__class__ = displayer_class
        result = displayer_class.displayValue(self, valueindex, commandbutton)
        self.__class__ = self_class
        return result


class Binary(LDAPSyntax):
    oid = '1.3.6.1.4.1.1466.115.121.1.5'
    desc = 'Binary'
    editable = 0

    def formField(self):
        f = web2ldap.web.forms.File(
            self._at,
            ': '.join([self._at, self.desc]),
            self.maxLen, self.maxValues, None, default=self._av, size=50
        )
        f.mimeType = self.mimeType
        return f

    def displayValue(self, valueindex=0, commandbutton=False):
        return '%d bytes | %s' % (
            len(self._av),
            self._app.anchor(
                'read', 'View/Load',
                [
                    ('dn', self._dn),
                    ('read_attr', self._at),
                    ('read_attrindex', str(valueindex)),
                ],
            )
        )


class Audio(Binary):
    oid = '1.3.6.1.4.1.1466.115.121.1.4'
    desc = 'Audio'
    mimeType = 'audio/basic'
    fileExt = 'au'

    def _validate(self, attrValue):
        fileobj = BytesIO(attrValue)
        res = sndhdr.test_au(attrValue, fileobj)
        return res is not None

    def displayValue(self, valueindex=0, commandbutton=False):
        mimetype = self.getMimeType()
        return """
            <embed
              type="%s"
              autostart="false"
              src="%s/read/%s?dn=%s&amp;read_attr=%s&amp;read_attrindex=%d"
            >
            %d bytes of audio data (%s)
            """ % (
                mimetype,
                self._app.form.script_name, self._app.sid,
                urllib.quote(self._dn.encode(self._app.form.accept_charset)),
                urllib.quote(self._at),
                valueindex,
                len(self._av),
                mimetype
            )


class DirectoryString(LDAPSyntax):
    oid = '1.3.6.1.4.1.1466.115.121.1.15'
    desc = 'Directory String'
    html_tmpl = '{av}'

    @property
    def av_u(self):
        try:
            return self._av_u
        except AttributeError:
            self._av_u = self._app.ls.uc_decode(self._av)[0]
        return self._av_u

    def _validate(self, attrValue):
        try:
            _ = self._app.ls.uc_encode(self._app.ls.uc_decode(attrValue)[0])[0]
        except UnicodeError:
            return False
        return True

    def sanitize(self, attrValue):
        return LDAPSyntax.sanitize(
            self,
            self._app.ls.uc_encode(self._app.form.uc_decode(attrValue)[0])[0],
        )

    def displayValue(self, valueindex=0, commandbutton=False):
        return self.html_tmpl.format(
            av=self._app.form.utf2display(self.av_u)
        )


class DistinguishedName(DirectoryString):
    oid = '1.3.6.1.4.1.1466.115.121.1.12'
    desc = 'Distinguished Name'
    isBindDN = False
    hasSubordinates = False
    noSubordinateAttrs = set(map(
        str.lower,
        [
            'subschemaSubentry',
        ],
    ))
    ref_attrs = None

    def _validate(self, attrValue):
        return is_dn(self._app.ls.uc_decode(attrValue)[0])

    def _has_subordinates(self):
        return self.hasSubordinates and not self._at.lower() in self.noSubordinateAttrs

    def _additional_links(self):
        r = []
        if self._at.lower() != 'entrydn':
            r.append(
                self._app.anchor(
                    'read', 'Read',
                    [('dn', self.av_u)],
                )
            )
        if self._has_subordinates():
            r.append(self._app.anchor(
                'search', 'Down',
                (
                    ('dn', self.av_u),
                    ('scope', web2ldap.app.searchform.SEARCH_SCOPE_STR_ONELEVEL),
                    ('filterstr', u'(objectClass=*)'),
                )
            ))
        if self.isBindDN:
            ldap_url_obj = self._app.ls.ldapUrl('', add_login=False)
            r.append(
                self._app.anchor(
                    'login',
                    'Bind as',
                    [
                        ('ldapurl', str(ldap_url_obj).decode('ascii')),
                        ('dn', self._dn),
                        ('login_who', self.av_u),
                    ],
                    title=u'Connect and bind new session as\r\n%s' % (self.av_u)
                ),
            )
        # If self.ref_attrs is not empty then add links for searching back-linking entries
        for ref_attr_tuple in self.ref_attrs or tuple():
            try:
                ref_attr, ref_text, ref_dn, ref_oc, ref_title = ref_attr_tuple
            except ValueError:
                ref_oc = None
                ref_attr, ref_text, ref_dn, ref_title = ref_attr_tuple
            ref_attr = ref_attr or self._at
            ref_dn = ref_dn or self._dn
            ref_title = ref_title or u'Search %s entries referencing entry %s in attribute %s' % (
                ref_oc, self.av_u, ref_attr,
            )
            r.append(self._app.anchor(
                'search', self._app.form.utf2display(ref_text),
                (
                    ('dn', ref_dn),
                    ('search_root', self._app.naming_context),
                    ('searchform_mode', 'adv'),
                    ('search_attr', 'objectClass'),
                    (
                        'search_option',
                        {
                            True: web2ldap.app.searchform.SEARCH_OPT_ATTR_EXISTS,
                            False: web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL,
                        }[ref_oc is None]
                    ),
                    ('search_string', ref_oc or u''),
                    ('search_attr', ref_attr),
                    ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                    ('search_string', self.av_u),
                ),
                title=ref_title,
            ))
        return r

    def displayValue(self, valueindex=0, commandbutton=False):
        r = [self._app.form.utf2display(self.av_u or u'- World -')]
        if commandbutton:
            r.extend(self._additional_links())
        return web2ldapcnf.command_link_separator.join(r)


class BindDN(DistinguishedName):
    oid = 'BindDN-oid'
    desc = 'A Distinguished Name used to bind to a directory'
    isBindDN = True


class AuthzDN(DistinguishedName):
    oid = 'AuthzDN-oid'
    desc = 'Authz Distinguished Name'

    def displayValue(self, valueindex=0, commandbutton=False):
        result = DistinguishedName.displayValue(self, valueindex, commandbutton)
        if commandbutton:
            simple_display_str = DistinguishedName.displayValue(
                self,
                valueindex,
                commandbutton=False,
            )
            whoami_display_str = web2ldap.app.gui.display_authz_dn(
                self._app,
                who=self.av_u
            )
            if whoami_display_str != simple_display_str:
                result = '<br>'.join((whoami_display_str, result))
        return result


class NameAndOptionalUID(DistinguishedName):
    oid = '1.3.6.1.4.1.1466.115.121.1.34'
    desc = 'Name And Optional UID'

    def _split_dn_and_uid(self, val):
        try:
            sep_ind = val.rindex(u'#')
        except ValueError:
            dn = val
            uid = None
        else:
            dn = val[0:sep_ind]
            uid = val[sep_ind+1:]
        return dn, uid

    def _validate(self, attrValue):
        dn, _ = self._split_dn_and_uid(self._app.ls.uc_decode(attrValue)[0])
        return is_dn(dn)

    def displayValue(self, valueindex=0, commandbutton=False):
        value = self._av.split('#')
        dn_str = self._app.display_dn(
            self.av_u,
            commandbutton=commandbutton,
        )
        if len(value) == 1 or not value[1]:
            return dn_str
        return web2ldapcnf.command_link_separator.join([
            self._app.form.utf2display(self._app.ls.uc_decode(value[1])),
            dn_str,
        ])


class BitString(DirectoryString):
    oid = '1.3.6.1.4.1.1466.115.121.1.6'
    desc = 'Bit String'
    reObj = re.compile("^'[01]+'B$")


class IA5String(DirectoryString):
    oid = '1.3.6.1.4.1.1466.115.121.1.26'
    desc = 'IA5 String'

    def _validate(self, attrValue):
        try:
            _ = attrValue.decode('ascii').encode('ascii')
        except UnicodeError:
            return False
        return True


class GeneralizedTime(IA5String):
    oid = '1.3.6.1.4.1.1466.115.121.1.24'
    desc = 'Generalized Time'
    inputSize = 24
    maxLen = 24
    reObj = re.compile(r'^([0-9]){12,14}((\.|,)[0-9]+)*(Z|(\+|-)[0-9]{4})$')
    timeDefault = None
    notBefore = None
    notAfter = None
    formValueFormat = r'%Y-%m-%dT%H:%M:%SZ'
    dtFormats = (
        r'%Y%m%d%H%M%SZ',
        r'%Y-%m-%dT%H:%M:%SZ',
        r'%Y-%m-%dT%H:%MZ',
        r'%Y-%m-%dT%H:%M:%S+00:00',
        r'%Y-%m-%dT%H:%M:%S-00:00',
        r'%Y-%m-%d %H:%M:%SZ',
        r'%Y-%m-%d %H:%MZ',
        r'%Y-%m-%d %H:%M',
        r'%Y-%m-%d %H:%M:%S+00:00',
        r'%Y-%m-%d %H:%M:%S-00:00',
        r'%d.%m.%YT%H:%M:%SZ',
        r'%d.%m.%YT%H:%MZ',
        r'%d.%m.%YT%H:%M:%S+00:00',
        r'%d.%m.%YT%H:%M:%S-00:00',
        r'%d.%m.%Y %H:%M:%SZ',
        r'%d.%m.%Y %H:%MZ',
        r'%d.%m.%Y %H:%M',
        r'%d.%m.%Y %H:%M:%S+00:00',
        r'%d.%m.%Y %H:%M:%S-00:00',
    )
    acceptableDateformats = (
        r'%Y-%m-%d',
        r'%d.%m.%Y',
        r'%m/%d/%Y',
    )
    dtDisplayFormat = (
        '<time datetime="%Y-%m-%dT%H:%M:%SZ">'
        '%A (%W. week) %Y-%m-%d %H:%M:%S+00:00'
        '</time>'
    )

    def _validate(self, attrValue):
        try:
            dt = web2ldap.utctime.strptime(attrValue)
        except ValueError:
            return False
        return (self.notBefore is None or self.notBefore <= dt) and \
               (self.notAfter is None or self.notAfter >= dt)

    def formValue(self):
        if not self._av:
            return u''
        try:
            dt = datetime.datetime.strptime(self._av, r'%Y%m%d%H%M%SZ')
        except ValueError:
            result = IA5String.formValue(self)
        else:
            result = unicode(datetime.datetime.strftime(dt, self.formValueFormat))
        return result

    def sanitize(self, attrValue):
        attrValue = attrValue.strip().upper()
        # Special cases first
        if attrValue in ('N', 'NOW', '0'):
            return datetime.datetime.strftime(datetime.datetime.utcnow(), r'%Y%m%d%H%M%SZ')
        # a single integer value is interpreted as seconds relative to now
        try:
            float_val = float(attrValue)
        except ValueError:
            pass
        else:
            return datetime.datetime.strftime(
                datetime.datetime.utcnow()+datetime.timedelta(seconds=float_val),
                r'%Y%m%d%H%M%SZ',
            )
        if self.timeDefault:
            date_format = r'%Y%m%d'+self.timeDefault+'Z'
            if attrValue in ('T', 'TODAY'):
                return datetime.datetime.strftime(
                    datetime.datetime.utcnow(),
                    date_format,
                )
            elif attrValue in ('Y', 'YESTERDAY'):
                return datetime.datetime.strftime(
                    datetime.datetime.today()-datetime.timedelta(days=1),
                    date_format,
                )
            elif attrValue in ('T', 'TOMORROW'):
                return datetime.datetime.strftime(
                    datetime.datetime.today()+datetime.timedelta(days=1),
                    date_format,
                )
        # Try to parse various datetime syntaxes
        for time_format in self.dtFormats:
            try:
                dt = datetime.datetime.strptime(attrValue, time_format)
            except ValueError:
                result = None
            else:
                result = datetime.datetime.strftime(dt, r'%Y%m%d%H%M%SZ')
                break
        if result is None and self.timeDefault:
            for time_format in self.acceptableDateformats or []:
                try:
                    dt = datetime.datetime.strptime(attrValue, time_format)
                except ValueError:
                    result = IA5String.sanitize(self, attrValue)
                else:
                    result = datetime.datetime.strftime(dt, r'%Y%m%d'+self.timeDefault+'Z')
                    break
        return result # sanitize()

    def displayValue(self, valueindex=0, commandbutton=False):
        try:
            dt_utc = web2ldap.utctime.strptime(self._av)
        except ValueError:
            return IA5String.displayValue(self, valueindex, commandbutton)
        try:
            dt_utc_str = dt_utc.strftime(self.dtDisplayFormat)
        except ValueError:
            return IA5String.displayValue(self, valueindex, commandbutton)
        if not commandbutton:
            return dt_utc_str
        current_time = datetime.datetime.utcnow()
        time_span = (current_time-dt_utc).total_seconds()
        return '{dt_utc} ({av})<br>{timespan_disp} {timespan_comment}'.format(
            dt_utc=dt_utc_str,
            av=self._app.form.utf2display(self.av_u),
            timespan_disp=self._app.form.utf2display(
                web2ldap.app.gui.ts2repr(Timespan.time_divisors, u' ', abs(time_span))
            ),
            timespan_comment={
                1: 'ago',
                0: '',
                -1: 'ahead',
            }[cmp(time_span, 0)]
        )


class NotBefore(GeneralizedTime):
    oid = 'NotBefore-oid'
    desc = 'A not-before timestamp by default starting at 00:00:00'
    timeDefault = '000000'


class NotAfter(GeneralizedTime):
    oid = 'NotAfter-oid'
    desc = 'A not-after timestamp by default ending at 23:59:59'
    timeDefault = '235959'


class UTCTime(GeneralizedTime):
    oid = '1.3.6.1.4.1.1466.115.121.1.53'
    desc = 'UTC Time'


class NullTerminatedDirectoryString(DirectoryString):
    oid = 'NullTerminatedDirectoryString-oid'
    desc = 'Directory String terminated by null-byte'

    def sanitize(self, attrValue):
        return attrValue+chr(0)

    def _validate(self, attrValue):
        return attrValue.endswith(chr(0))

    def formValue(self):
        return self._app.ls.uc_decode((self._av or chr(0))[:-1])[0]

    def displayValue(self, valueindex=0, commandbutton=False):
        return self._app.form.utf2display(
            self._app.ls.uc_decode((self._av or chr(0))[:-1])[0]
        )


class OtherMailbox(DirectoryString):
    oid = '1.3.6.1.4.1.1466.115.121.1.39'
    desc = 'Other Mailbox'
    charset = 'ascii'


class Integer(IA5String):
    oid = '1.3.6.1.4.1.1466.115.121.1.27'
    desc = 'Integer'
    inputSize = 12
    minValue = None
    maxValue = None

    def __init__(self, app, dn, schema, attrType, attrValue, entry=None):
        IA5String.__init__(self, app, dn, schema, attrType, attrValue, entry)
        if self.maxValue is not None:
            self.maxLen = len(str(self.maxValue))

    def _maxlen(self, form_value):
        min_value_len = max_value_len = form_value_len = 0
        if self.minValue is not None:
            min_value_len = len(str(self.minValue))
        if self.maxValue is not None:
            max_value_len = len(str(self.maxValue))
        if form_value is not None:
            form_value_len = len(form_value.encode(self._app.ls.charset))
        return max(self.inputSize, form_value_len, min_value_len, max_value_len)

    def _validate(self, attrValue):
        try:
            intValue = int(attrValue)
        except ValueError:
            return False
        min_value, max_value = self.minValue, self.maxValue
        return (
            (min_value is None or intValue >= min_value) and
            (max_value is None or intValue <= max_value)
        )

    def sanitize(self, attrValue):
        try:
            return str(int(attrValue))
        except ValueError:
            return attrValue

    def formField(self):
        form_value = self.formValue()
        max_len = self._maxlen(form_value)
        return web2ldap.web.forms.Input(
            self._at,
            ': '.join([self._at, self.desc]),
            max_len,
            self.maxValues,
            '^[0-9]*$',
            default=form_value,
            size=min(self.inputSize, max_len),
        )


class IPHostAddress(IA5String):
    oid = 'IPHostAddress-oid'
    desc = 'string representation of IPv4 or IPv6 address'
    # Class in module ipaddr which parses address/network values
    addr_class = None
    simpleSanitizers = (
        str.strip,
    )

    def _validate(self, attrValue):
        try:
            addr = ipaddress.ip_address(attrValue.decode('ascii'))
        except Exception:
            return False
        return self.addr_class == None or isinstance(addr, self.addr_class)


class IPv4HostAddress(IPHostAddress):
    oid = 'IPv4HostAddress-oid'
    desc = 'string representation of IPv4 address'
    addr_class = ipaddress.IPv4Address


class IPv6HostAddress(IPHostAddress):
    oid = 'IPv6HostAddress-oid'
    desc = 'string representation of IPv6 address'
    addr_class = ipaddress.IPv6Address


class IPNetworkAddress(IPHostAddress):
    oid = 'IPNetworkAddress-oid'
    desc = 'string representation of IPv4 or IPv6 network address/mask'

    def _validate(self, attrValue):
        try:
            addr = ipaddress.ip_network(attrValue.decode('ascii'), strict=False)
        except Exception:
            return False
        return self.addr_class is None or isinstance(addr, self.addr_class)


class IPv4NetworkAddress(IPNetworkAddress):
    oid = 'IPv4NetworkAddress-oid'
    desc = 'string representation of IPv4 network address/mask'
    addr_class = ipaddress.IPv4Network


class IPv6NetworkAddress(IPNetworkAddress):
    oid = 'IPv6NetworkAddress-oid'
    desc = 'string representation of IPv6 network address/mask'
    addr_class = ipaddress.IPv6Network


class IPServicePortNumber(Integer):
    oid = 'IPServicePortNumber-oid'
    desc = 'Port number for an UDP- or TCP-based service'
    minValue = 0
    maxValue = 65535


class MacAddress(IA5String):
    oid = 'MacAddress-oid'
    desc = 'MAC address in hex-colon notation'
    minLen = 17
    maxLen = 17
    reObj = re.compile(r'^([0-9a-f]{2}\:){5}[0-9a-f]{2}$')

    def sanitize(self, attrValue):
        attr_value = attrValue.translate(None, '.-: ').lower().strip()
        if len(attr_value) == 12:
            return ':'.join([attr_value[i*2:i*2+2] for i in range(6)])
        return attrValue


class Uri(DirectoryString):
    """
    see RFC 2079
    """
    oid = 'Uri-OID'
    desc = 'URI'
    reObj = re.compile(r'^(ftp|http|https|news|snews|ldap|ldaps|mailto):(|//)[^ ]*')
    simpleSanitizers = (
        str.strip,
    )

    def displayValue(self, valueindex=0, commandbutton=False):
        attr_value = self.av_u
        try:
            url, label = attr_value.split(u' ', 1)
        except ValueError:
            url, label = attr_value, attr_value
            display_url = u''
        else:
            display_url = u' (%s)' % (url)
        if ldap0.ldapurl.isLDAPUrl(url):
            return '<a href="%s?%s">%s%s</a>' % (
                self._app.form.script_name,
                self._app.form.utf2display(url),
                self._app.form.utf2display(label),
                self._app.form.utf2display(display_url),
            )
        elif url.lower().find('javascript:') >= 0:
            return '<code>%s</code>' % (
                DirectoryString.displayValue(self, valueindex=False, commandbutton=False)
            )
        return '<a href="%s/urlredirect/%s?%s">%s%s</a>' % (
            self._app.form.script_name,
            self._app.sid,
            self._app.form.utf2display(url),
            self._app.form.utf2display(label),
            self._app.form.utf2display(display_url),
        )


class Image(Binary):
    oid = 'Image-OID'
    desc = 'Image base class'
    mimeType = 'application/octet-stream'
    fileExt = 'bin'
    imageFormat = None
    inline_maxlen = 630 # max. number of bytes to use data: URI instead of external URL

    def _validate(self, attrValue):
        return imghdr.what(None, attrValue) == self.imageFormat.lower()

    def sanitize(self, attrValue):
        if not self._validate(attrValue) and PILImage:
            imgfile = BytesIO(attrValue)
            try:
                im = PILImage.open(imgfile)
                imgfile.seek(0)
                im.save(imgfile, self.imageFormat)
            except Exception as err:
                logger.warn(
                    'Error converting image data (%d bytes) to %s: %r',
                    len(attrValue),
                    self.imageFormat,
                    err,
                )
            else:
                attrValue = imgfile.getvalue()
        return attrValue

    def displayValue(self, valueindex=0, commandbutton=False):
        maxwidth, maxheight = 100, 150
        width, height = None, None
        size_attr_html = ''
        if PILImage:
            f = BytesIO(self._av)
            try:
                im = PILImage.open(f)
            except IOError:
                pass
            else:
                width, height = im.size
                if width > maxwidth:
                    size_attr_html = 'width="%d" height="%d"' % (
                        maxwidth,
                        int(float(maxwidth)/width*height),
                    )
                elif height > maxheight:
                    size_attr_html = 'width="%d" height="%d"' % (
                        int(float(maxheight)/height*width),
                        maxheight,
                    )
                else:
                    size_attr_html = 'width="%d" height="%d"' % (width, height)
        attr_value_len = len(self._av)
        img_link = (
            '%s/read/%s'
            '?dn=%s&amp;read_attr=%s&amp;read_attrindex=%d&amp;read_attrmode=load'
        ) % (
            self._app.form.script_name, self._app.sid,
            urllib.quote(self._dn.encode(self._app.form.accept_charset)),
            urllib.quote(self._at),
            valueindex,
        )
        if attr_value_len <= self.inline_maxlen:
            return (
                '<a href="%s">'
                '<img src="data:%s;base64,\n%s" alt="%d bytes of image data" %s>'
                '</a>'
            ) % (
                img_link,
                self.mimeType,
                self._av.encode('base64'),
                attr_value_len,
                size_attr_html,
            )
        return '<a href="%s"><img src="%s" alt="%d bytes of image data" %s></a>' % (
            img_link,
            img_link,
            attr_value_len,
            size_attr_html,
        )


class JPEGImage(Image):
    oid = '1.3.6.1.4.1.1466.115.121.1.28'
    desc = 'JPEG image'
    mimeType = 'image/jpeg'
    fileExt = 'jpg'
    imageFormat = 'JPEG'


class PhotoG3Fax(Binary):
    oid = '1.3.6.1.4.1.1466.115.121.1.23'
    desc = 'Photo (G3 fax)'
    mimeType = 'image/g3fax'
    fileExt = 'tif'


# late import of schema_anchor()
from web2ldap.app.schema.viewer import schema_anchor

class OID(IA5String):
    oid = '1.3.6.1.4.1.1466.115.121.1.38'
    desc = 'OID'
    reObj = re.compile(r'^([a-zA-Z]+[a-zA-Z0-9;-]*|[0-2]?\.([0-9]+\.)*[0-9]+)$')

    def valueButton(self, command, row, mode, link_text=None):
        at = self._at.lower()
        if at in {'objectclass', 'structuralobjectclass', '2.5.4.0', '2.5.21.9'}:
            return ''
        return IA5String.valueButton(self, command, row, mode, link_text=link_text)

    def sanitize(self, attrValue):
        attrValue = attrValue.strip()
        if attrValue.startswith('{') and attrValue.endswith('}'):
            try:
                attrValue = web2ldap.ldaputil.ietf_oid_str(attrValue)
            except ValueError:
                pass
        return attrValue

    def displayValue(self, valueindex=0, commandbutton=False):
        try:
            name, description, reference = OID_REG[self._av]
        except (KeyError, ValueError):
            try:
                se = self._schema.get_obj(
                    ldap0.schema.models.ObjectClass,
                    self._av,
                    raise_keyerror=1,
                )
            except KeyError:
                try:
                    se = self._schema.get_obj(
                        ldap0.schema.models.AttributeType,
                        self._av,
                        raise_keyerror=1,
                    )
                except KeyError:
                    return IA5String.displayValue(self, valueindex, commandbutton)
                return schema_anchor(
                    self._app,
                    self._av,
                    ldap0.schema.models.AttributeType,
                    name_template=r'%s',
                    link_text='&raquo',
                )
            name_template = {
                0: r'%s <em>STRUCTURAL</em>',
                1: r'%s <em>ABSTRACT</em>',
                2: r'%s <em>AUXILIARY</em>'
            }[se.kind]
            # objectClass attribute is displayed with different function
            return schema_anchor(
                self._app,
                self._av,
                ldap0.schema.models.ObjectClass,
                name_template=name_template,
                link_text='&raquo',
            )
        return '<strong>%s</strong> (%s):<br>%s (see %s)' % (
            self._app.form.utf2display(name),
            IA5String.displayValue(self, valueindex, commandbutton),
            self._app.form.utf2display(description),
            self._app.form.utf2display(reference)
        )


class LDAPUrl(Uri):
    oid = 'LDAPUrl-oid'
    desc = 'LDAP URL'

    def _command_ldap_url(self, ldap_url):
        return ldap_url

    def displayValue(self, valueindex=0, commandbutton=False):
        try:
            if commandbutton:
                commandbuttonstr = web2ldap.app.gui.ldap_url_anchor(
                    self._app,
                    self._command_ldap_url(self._av),
                )
            else:
                commandbuttonstr = ''
        except ValueError:
            return '<strong>Not a valid LDAP URL:</strong> %s' % (
                self._app.form.utf2display(repr(self._av).decode('ascii'))
            )
        return '<table><tr><td>%s</td><td><a href="%s">%s</a></td></tr></table>' % (
            commandbuttonstr,
            self._app.form.utf2display(self.av_u),
            self._app.form.utf2display(self.av_u)
        )


class OctetString(Binary):
    oid = '1.3.6.1.4.1.1466.115.121.1.40'
    desc = 'Octet String'
    editable = 1
    minInputRows = 1  # minimum number of rows for input field
    maxInputRows = 15 # maximum number of rows for in input field
    bytes_split = 16

    def sanitize(self, attrValue):
        attrValue = attrValue.translate(None, ': ,\r\n')
        try:
            result_str = attrValue.decode('hex')
        except TypeError as e:
            raise LDAPSyntaxValueError('Illegal human-readable OctetString representation: %s' % e)
        return result_str

    def displayValue(self, valueindex=0, commandbutton=False):
        lines = [
            (
                '<tr>'
                '<td><code>%0.6X</code></td>'
                '<td><code>%s</code></td>'
                '<td><code>%s</code></td>'
                '</tr>'
            ) % (
                i*self.bytes_split,
                ':'.join(x.encode('hex').upper() for x in c),
                self._app.form.utf2display(unicode(web2ldap.msbase.ascii_dump(c), 'ascii')),
            )
            for i, c in enumerate(web2ldap.msbase.chunks(self._av, self.bytes_split))
        ]
        return '\n<table class="HexDump">\n%s\n</table>\n' % ('\n'.join(lines))

    def formValue(self):
        return unicode('\r\n'.join(
            web2ldap.msbase.chunks(
                ':'.join(x.encode('hex').upper() for x in self._av or ''),
                self.bytes_split*3
            )
        ))

    def formField(self):
        form_value = self.formValue()
        return web2ldap.web.forms.Textarea(
            self._at,
            ': '.join([self._at, self.desc]),
            10000, 1,
            None,
            default=form_value,
            rows=max(self.minInputRows, min(self.maxInputRows, form_value.count('\r\n'))),
            cols=49
        )


class MultilineText(DirectoryString):
    oid = 'MultilineText-oid'
    desc = 'Multiple lines of text'
    reObj = re.compile('^.*$', re.S+re.M)
    lineSep = u'\r\n'
    mimeType = 'text/plain'
    cols = 66
    minInputRows = 1  # minimum number of rows for input field
    maxInputRows = 30 # maximum number of rows for in input field

    def _split_lines(self, value):
        if self.lineSep:
            return value.split(self.lineSep)
        return [value]

    def sanitize(self, attrValue):
        return attrValue.replace(
            u'\r', u''
        ).replace(
            u'\n', self.lineSep
        ).encode(self._app.ls.charset)

    def displayValue(self, valueindex=0, commandbutton=False):
        lines = [
            self._app.form.utf2display(l)
            for l in self._split_lines(self.av_u)
        ]
        return '<br>'.join(lines)

    def formValue(self):
        splitted_lines = self._split_lines(self._app.ls.uc_decode(self._av or '')[0])
        return u'\r\n'.join(splitted_lines)

    def formField(self):
        form_value = self.formValue()
        return web2ldap.web.forms.Textarea(
            self._at,
            ': '.join([self._at, self.desc]),
            self.maxLen, self.maxValues,
            None,
            default=form_value,
            rows=max(self.minInputRows, min(self.maxInputRows, form_value.count('\r\n'))),
            cols=self.cols
        )


class PreformattedMultilineText(MultilineText):
    oid = 'PreformattedMultilineText-oid'
    cols = 66
    tab_identiation = '&nbsp;&nbsp;&nbsp;&nbsp;'

    def displayValue(self, valueindex=0, commandbutton=False):
        lines = [
            self._app.form.utf2display(l, self.tab_identiation)
            for l in self._split_lines(self.av_u)
        ]
        return '<code>%s</code>' % '<br>'.join(lines)


class PostalAddress(MultilineText):
    oid = '1.3.6.1.4.1.1466.115.121.1.41'
    desc = 'Postal Address'
    lineSep = ' $ '
    cols = 40

    def _split_lines(self, value):
        return [
            v.strip()
            for v in value.split(self.lineSep.strip())
        ]

    def sanitize(self, attrValue):
        return attrValue.replace('\r', '').replace('\n', self.lineSep)


class PrintableString(DirectoryString):
    oid = '1.3.6.1.4.1.1466.115.121.1.44'
    desc = 'Printable String'
    reObj = re.compile("^[a-zA-Z0-9'()+,.=/:? -]*$")
    charset = 'ascii'


class NumericString(PrintableString):
    oid = '1.3.6.1.4.1.1466.115.121.1.36'
    desc = 'Numeric String'
    reObj = re.compile('^[ 0-9]+$')


class EnhancedGuide(PrintableString):
    oid = '1.3.6.1.4.1.1466.115.121.1.21'
    desc = 'Enhanced Search Guide'


class Guide(EnhancedGuide):
    oid = '1.3.6.1.4.1.1466.115.121.1.25'
    desc = 'Search Guide'


class TelephoneNumber(PrintableString):
    oid = '1.3.6.1.4.1.1466.115.121.1.50'
    desc = 'Telephone Number'
    reObj = re.compile('^[0-9+x(). /-]+$')


class FacsimileTelephoneNumber(TelephoneNumber):
    oid = '1.3.6.1.4.1.1466.115.121.1.22'
    desc = 'Facsimile Number'
    reObj = re.compile(
        r'^[0-9+x(). /-]+'
        r'(\$'
        r'(twoDimensional|fineResolution|unlimitedLength|b4Length|a3Width|b4Width|uncompressed)'
        r')*$'
    )


class TelexNumber(PrintableString):
    oid = '1.3.6.1.4.1.1466.115.121.1.52'
    desc = 'Telex Number'
    reObj = re.compile("^[a-zA-Z0-9'()+,.=/:?$ -]*$")


class TeletexTerminalIdentifier(PrintableString):
    oid = '1.3.6.1.4.1.1466.115.121.1.51'
    desc = 'Teletex Terminal Identifier'


class ObjectGUID(LDAPSyntax):
    oid = 'ObjectGUID-oid'
    desc = 'Object GUID'
    charset = 'ascii'

    def displayValue(self, valueindex=0, commandbutton=False):
        objectguid_str = ''.join([
            '%02X' % ord(c)
            for c in self._av
        ])
        return ldap0.ldapurl.LDAPUrl(
            ldapUrl=self._app.ls.uri,
            dn='GUID=%s' % (objectguid_str),
            who=None, cred=None
        ).htmlHREF(
            hrefText=objectguid_str,
            hrefTarget=None
        )


class Date(IA5String):
    oid = 'Date-oid'
    desc = 'Date in syntax specified by class attribute storageFormat'
    maxLen = 10
    storageFormat = '%Y-%m-%d'
    acceptableDateformats = (
        '%Y-%m-%d',
        '%d.%m.%Y',
        '%m/%d/%Y',
    )

    def _validate(self, attrValue):
        try:
            datetime.datetime.strptime(attrValue, self.storageFormat)
        except ValueError:
            return False
        return True

    def sanitize(self, attrValue):
        attrValue = attrValue.strip()
        result = attrValue
        for time_format in self.acceptableDateformats:
            try:
                time_tuple = datetime.datetime.strptime(attrValue, time_format)
            except ValueError:
                pass
            else:
                result = datetime.datetime.strftime(time_tuple, self.storageFormat)
                break
        return result # sanitize()


class NumstringDate(Date):
    oid = 'NumstringDate-oid'
    desc = 'Date in syntax YYYYMMDD'
    reObj = re.compile('^[0-9]{4}[0-1][0-9][0-3][0-9]$')
    storageFormat = '%Y%m%d'


class ISO8601Date(Date):
    oid = 'ISO8601Date-oid'
    desc = 'Date in syntax YYYY-MM-DD, see ISO 8601'
    reObj = re.compile('^[0-9]{4}-[0-1][0-9]-[0-3][0-9]$')
    storageFormat = '%Y-%m-%d'


class DateOfBirth(ISO8601Date):
    oid = 'DateOfBirth-oid'
    desc = 'Date of birth: syntax YYYY-MM-DD, see ISO 8601'

    @staticmethod
    def _age(birth_dt):
        birth_date = datetime.date(
            year=birth_dt.year,
            month=birth_dt.month,
            day=birth_dt.day,
        )
        current_date = datetime.date.today()
        age = current_date.year - birth_date.year
        if birth_date.month > current_date.month or \
           (birth_date.month == current_date.month and birth_date.day > current_date.day):
            age = age - 1
        return age

    def _validate(self, attrValue):
        try:
            birth_dt = datetime.datetime.strptime(attrValue, self.storageFormat)
        except ValueError:
            return False
        return self._age(birth_dt) >= 0

    def displayValue(self, valueindex=0, commandbutton=False):
        raw_date = ISO8601Date.displayValue(self, valueindex, commandbutton)
        try:
            birth_dt = datetime.datetime.strptime(self._av, self.storageFormat)
        except ValueError:
            return raw_date
        return '%s (%s years old)' % (raw_date, self._age(birth_dt))


class SecondsSinceEpoch(Integer):
    oid = 'SecondsSinceEpoch-oid'
    desc = 'Seconds since epoch (1970-01-01 00:00:00)'
    minValue = 0

    def displayValue(self, valueindex=0, commandbutton=False):
        int_str = Integer.displayValue(self, valueindex, commandbutton)
        try:
            return '%s (%s)' % (
                strftimeiso8601(time.gmtime(float(self._av))).encode('ascii'),
                int_str,
            )
        except ValueError:
            return int_str


class DaysSinceEpoch(Integer):
    oid = 'DaysSinceEpoch-oid'
    desc = 'Days since epoch (1970-01-01)'
    minValue = 0

    def displayValue(self, valueindex=0, commandbutton=False):
        int_str = Integer.displayValue(self, valueindex, commandbutton)
        try:
            return '%s (%s)' % (
                strftimeiso8601(time.gmtime(float(self._av)*86400)).encode('ascii'),
                int_str,
            )
        except ValueError:
            return int_str


class Timespan(Integer):
    oid = 'Timespan-oid'
    desc = 'Time span in seconds'
    inputSize = LDAPSyntax.inputSize
    minValue = 0
    time_divisors = (
        (u'weeks', 604800),
        (u'days', 86400),
        (u'hours', 3600),
        (u'mins', 60),
        (u'secs', 1),
    )
    sep = u','

    def sanitize(self, attrValue):
        if attrValue:
            try:

                result = str(web2ldap.app.gui.repr2ts(self.time_divisors, self.sep, attrValue))
            except ValueError:
                result = Integer.sanitize(self, attrValue)
        else:
            result = attrValue
        return result

    def formValue(self):
        if not self._av:
            return self._av
        try:
            result = web2ldap.app.gui.ts2repr(self.time_divisors, self.sep, int(self._av))
        except ValueError:
            result = Integer.formValue(self)
        return result

    def displayValue(self, valueindex=0, commandbutton=False):
        try:
            result = self._app.form.utf2display('%s (%s)' % (
                web2ldap.app.gui.ts2repr(self.time_divisors, self.sep, int(self._av)),
                Integer.displayValue(self, valueindex, commandbutton)
            ))
        except ValueError:
            result = Integer.displayValue(self, valueindex, commandbutton)
        return result


class SelectList(DirectoryString):
    """
    Base class for dictionary based select lists which
    should not be used directly
    """
    oid = 'SelectList-oid'
    attr_value_dict = {}  # Mapping attribute value to attribute description
    input_fallback = True # Fallback to normal input field if attr_value_dict is empty

    def _get_attr_value_dict(self):
        # Enable empty value in any case
        attr_value_dict = {u'': u'-/-'}
        attr_value_dict.update(self.attr_value_dict)
        return attr_value_dict

    def _sorted_select_options(self):
        # First generate a set of all other currently available attribute values
        form_value = DirectoryString.formValue(self)
        # Initialize a dictionary with all options
        d = self._get_attr_value_dict()
        # Remove other existing values from the options dict
        for v in self._entry.get(self._at, []):
            v = self._app.ls.uc_decode(v)[0]
            if v != form_value:
                try:
                    del d[v]
                except KeyError:
                    pass
        # Add the current attribute value if needed
        if not form_value in d:
            d[form_value] = form_value
        # Finally return the sorted option list
        result = []
        for k, v in d.items():
            if isinstance(v, unicode):
                result.append((k, v, None))
            elif isinstance(v, tuple):
                result.append((k, v[0], v[1]))
        return sorted(
            result,
            key=lambda x: x[1].lower(),
        )

    def _validate(self, attrValue):
        attr_value_dict = self._get_attr_value_dict()
        return self._app.ls.uc_decode(attrValue)[0] in attr_value_dict

    def displayValue(self, valueindex=0, commandbutton=False):
        attr_value_str = DirectoryString.displayValue(self, valueindex, commandbutton)
        attr_value_dict = self._get_attr_value_dict()
        try:
            attr_value_desc = attr_value_dict[self._av]
        except KeyError:
            return attr_value_str
        try:
            attr_text, attr_title = attr_value_desc
        except ValueError:
            attr_text, attr_title = attr_value_desc, None
        if attr_text == attr_value_str:
            return attr_value_str
        if attr_title:
            tag_tmpl = '<span title="{attr_title}">{attr_text}: {attr_value}</span>'
        else:
            tag_tmpl = '{attr_text}: {attr_value}'
        return tag_tmpl.format(
            attr_value=attr_value_str,
            attr_text=self._app.form.utf2display(attr_text),
            attr_title=self._app.form.utf2display(attr_title or u'')
        )

    def formField(self):
        attr_value_dict = self._get_attr_value_dict()
        if self.input_fallback and \
           (not attr_value_dict or not filter(None, attr_value_dict.keys())):
            return DirectoryString.formField(self)
        field = web2ldap.web.forms.Select(
            self._at,
            ': '.join([self._at, self.desc]),
            1,
            options=self._sorted_select_options(),
            default=self.formValue(),
            required=0
        )
        field.charset = self._app.form.accept_charset
        return field


class PropertiesSelectList(SelectList):
    oid = 'PropertiesSelectList-oid'
    properties_pathname = None
    properties_charset = 'utf-8'
    properties_delimiter = u'='

    def _get_attr_value_dict(self):
        attr_value_dict = SelectList._get_attr_value_dict(self)
        real_path_name = web2ldap.app.gui.GetVariantFilename(
            self.properties_pathname,
            self._app.form.accept_language
        )
        with open(real_path_name, 'rb') as f:
            for line in f.readlines():
                line = line.decode(self.properties_charset).strip()
                if line and not line.startswith('#'):
                    key, value = line.split(self.properties_delimiter, 1)
                    attr_value_dict[key.strip()] = value.strip()
        return attr_value_dict # _get_attr_value_dict()


class DynamicValueSelectList(SelectList, DirectoryString):
    oid = 'DynamicValueSelectList-oid'
    ldap_url = None
    valuePrefix = ''
    valueSuffix = ''

    def __init__(self, app, dn, schema, attrType, attrValue, entry=None):
        self.lu_obj = ldap0.ldapurl.LDAPUrl(self.ldap_url)
        self.minLen = len(self.valuePrefix)+len(self.valueSuffix)
        SelectList.__init__(self, app, dn, schema, attrType, attrValue, entry)

    def _filterstr(self):
        return self.lu_obj.filterstr or '(objectClass=*)'

    def _search_ref(self, attrValue):
        attr_value = attrValue[len(self.valuePrefix):-len(self.valueSuffix) or None]
        search_filter = '(&%s(%s=%s))' % (
            self._filterstr(),
            self.lu_obj.attrs[0],
            attr_value,
        )
        try:
            ldap_result = self._app.ls.l.search_s(
                self._search_root(),
                self.lu_obj.scope,
                search_filter,
                attrlist=self.lu_obj.attrs,
                sizelimit=2,
            )
        except (
                ldap0.NO_SUCH_OBJECT,
                ldap0.CONSTRAINT_VIOLATION,
                ldap0.INSUFFICIENT_ACCESS,
                ldap0.REFERRAL,
                ldap0.SIZELIMIT_EXCEEDED,
                ldap0.TIMELIMIT_EXCEEDED,
            ):
            return None
        # Filter out LDAP referrals
        ldap_result = [
            (dn, entry)
            for dn, entry in ldap_result
            if dn is not None
        ]
        if ldap_result and len(ldap_result) == 1:
            return ldap_result[0]
        return None

    def _validate(self, attrValue):
        if (
                not attrValue.startswith(self.valuePrefix) or
                not attrValue.endswith(self.valueSuffix) or
                len(attrValue) < self.minLen or
                (self.maxLen is not None and len(attrValue) > self.maxLen)
            ):
            return False
        return self._search_ref(attrValue) is not None

    def displayValue(self, valueindex=0, commandbutton=False):
        if commandbutton and self.lu_obj.attrs:
            ref_result = self._search_ref(self._av)
            if ref_result:
                ref_dn, ref_entry = ref_result
                try:
                    attr_value_desc = self._app.ls.uc_decode(ref_entry[self.lu_obj.attrs[1]][0])[0]
                except (KeyError, IndexError):
                    display_text, link_html = '', ''
                else:
                    if self.lu_obj.attrs[0].lower() == self.lu_obj.attrs[1].lower():
                        display_text = ''
                    else:
                        display_text = self._app.form.utf2display(attr_value_desc+u':')
                    if commandbutton:
                        link_html = self._app.anchor(
                            'read', '&raquo;',
                            [('dn', self._app.ls.uc_decode(ref_dn)[0])],
                        )
                    else:
                        link_html = ''
            else:
                display_text, link_html = '', ''
        else:
            display_text, link_html = '', ''
        return ' '.join((
            display_text,
            DirectoryString.displayValue(self, valueindex, commandbutton),
            link_html,
        ))

    def _search_root(self):
        ldap_url_dn = self._app.ls.uc_decode(self.lu_obj.dn)[0]
        if ldap_url_dn == u'_':
            result_dn = self._app.naming_context
        elif ldap_url_dn == u'.':
            result_dn = self._dn
        elif ldap_url_dn == u'..':
            result_dn = web2ldap.ldaputil.parent_dn(self._dn)
        elif ldap_url_dn.endswith(u',_'):
            result_dn = u','.join((ldap_url_dn[:-2], self._app.naming_context))
        elif ldap_url_dn.endswith(u',.'):
            result_dn = u','.join((ldap_url_dn[:-2], self._dn))
        elif ldap_url_dn.endswith(u',..'):
            result_dn = u','.join((ldap_url_dn[:-3], web2ldap.ldaputil.parent_dn(self._dn)))
        else:
            result_dn = ldap_url_dn
        if result_dn.endswith(u','):
            result_dn = result_dn[:-1]
        return self._app.ls.uc_encode(result_dn)[0]
        # end of _search_root()

    def _get_attr_value_dict(self):
        attr_value_dict = SelectList._get_attr_value_dict(self)
        if self.lu_obj.hostport:
            raise ValueError(
                'Connecting to other server not supported! hostport attribute was %r' % (
                    self.lu_obj.hostport
                )
            )
        search_scope = self.lu_obj.scope or ldap0.SCOPE_BASE
        search_attrs = (self.lu_obj.attrs or []) + ['description', 'info']
        # Use the existing LDAP connection as current user
        try:
            ldap_result = self._app.ls.l.search_s(
                self._search_root(),
                search_scope,
                filterstr=self._filterstr(),
                attrlist=search_attrs,
            )
        except (
                ldap0.NO_SUCH_OBJECT,
                ldap0.SIZELIMIT_EXCEEDED,
                ldap0.TIMELIMIT_EXCEEDED,
                ldap0.PARTIAL_RESULTS,
                ldap0.INSUFFICIENT_ACCESS,
                ldap0.CONSTRAINT_VIOLATION,
                ldap0.REFERRAL,
            ):
            return {}
        if search_scope == ldap0.SCOPE_BASE:
            # When reading a single entry we build the map from a single multi-valued attribute
            dn_r, entry_r = ldap_result[0]
            assert len(self.lu_obj.attrs or []) == 1, \
                ValueError("attrlist in ldap_url must be of length 1 if scope is base")
            list_attr = self.lu_obj.attrs[0]
            attr_values_u = [
                ''.join((
                    self.valuePrefix,
                    self._app.ls.uc_decode(attr_value)[0],
                    self.valueSuffix,
                ))
                for attr_value in entry_r[list_attr]
            ]
            attr_value_dict = dict([(u, u) for u in attr_values_u])
        else:
            if not self.lu_obj.attrs:
                option_value_map, option_text_map = (None, None)
            elif len(self.lu_obj.attrs) == 1:
                option_value_map, option_text_map = (None, self.lu_obj.attrs[0])
            elif len(self.lu_obj.attrs) >= 2:
                option_value_map, option_text_map = self.lu_obj.attrs[:2]
            for dn_r, entry_r in ldap_result:
                # Check whether it's a real search result (ignore search continuations)
                if not dn_r is None:
                    entry_r[None] = [dn_r]
                    try:
                        option_value = ''.join((
                            self.valuePrefix,
                            self._app.ls.uc_decode(entry_r[option_value_map][0])[0],
                            self.valueSuffix,
                        ))
                    except KeyError:
                        pass
                    else:
                        try:
                            option_text = self._app.ls.uc_decode(entry_r[option_text_map][0])[0]
                        except KeyError:
                            option_text = option_value
                        option_title = entry_r.get('description', entry_r.get('info', ['']))[0]
                        if option_title:
                            option_title = self._app.ls.uc_decode(option_title)[0]
                            attr_value_dict[option_value] = (option_text, option_title)
                        else:
                            attr_value_dict[option_value] = option_text
        return attr_value_dict # _get_attr_value_dict()


class DynamicDNSelectList(DynamicValueSelectList, DistinguishedName):
    oid = 'DynamicDNSelectList-oid'

    def _get_ref_entry(self, dn):
        try:
            ref_entry = self._app.ls.l.read_s(
                dn,
                attrlist=self.lu_obj.attrs,
                filterstr=self._filterstr(),
            )
        except (
                ldap0.NO_SUCH_OBJECT,
                ldap0.CONSTRAINT_VIOLATION,
                ldap0.INSUFFICIENT_ACCESS,
                ldap0.INVALID_DN_SYNTAX,
                ldap0.REFERRAL,
            ):
            return None
        return ref_entry

    def _validate(self, attrValue):
        return self._get_ref_entry(attrValue) is not None

    def displayValue(self, valueindex=0, commandbutton=False):
        if commandbutton and self.lu_obj.attrs:
            ref_entry = self._get_ref_entry(self._av) or {}
            try:
                attr_value_desc = self._app.ls.uc_decode(ref_entry[self.lu_obj.attrs[0]][0])[0]
            except (KeyError, IndexError):
                display_text = ''
            else:
                display_text = self._app.form.utf2display(attr_value_desc+u': ')
        else:
            display_text = ''
        return ''.join((
            display_text,
            DistinguishedName.displayValue(self, valueindex, commandbutton)
        ))


class Boolean(SelectList, IA5String):
    oid = '1.3.6.1.4.1.1466.115.121.1.7'
    desc = 'Boolean'
    attr_value_dict = {
        u'TRUE': u'TRUE',
        u'FALSE': u'FALSE',
    }

    def _get_attr_value_dict(self):
        attr_value_dict = SelectList._get_attr_value_dict(self)
        if self._av and self._av.lower() == self._av:
            for key, val in attr_value_dict.items():
                del attr_value_dict[key]
                attr_value_dict[key.lower()] = val.lower()
        return attr_value_dict

    def _validate(self, attrValue):
        if not self._av and attrValue.lower() == attrValue:
            return SelectList._validate(self, attrValue.upper())
        return SelectList._validate(self, attrValue)

    def displayValue(self, valueindex=0, commandbutton=False):
        return IA5String.displayValue(self, valueindex, commandbutton)


class CountryString(PropertiesSelectList):
    oid = '1.3.6.1.4.1.1466.115.121.1.11'
    desc = 'Two letter country string as listed in ISO 3166-2'
    properties_pathname = os.path.join(
        web2ldapcnf.etc_dir, 'properties', 'attribute_select_c.properties'
    )
    simpleSanitizers = (
        str.strip,
    )


class DeliveryMethod(PrintableString):
    oid = '1.3.6.1.4.1.1466.115.121.1.14'
    desc = 'Delivery Method'
    pdm = '(any|mhs|physical|telex|teletex|g3fax|g4fax|ia5|videotex|telephone)'
    reObj = re.compile('^%s[ $]*%s$' % (pdm, pdm))


class BitArrayInteger(MultilineText, Integer):
    oid = 'BitArrayInteger-oid'
    flag_desc_table = tuple()
    true_false_desc = {
        False:'-',
        True:'+',
    }

    def __init__(self, app, dn, schema, attrType, attrValue, entry=None):
        Integer.__init__(self, app, dn, schema, attrType, attrValue, entry)
        self.flag_desc2int = dict(self.flag_desc_table)
        self.flag_int2desc = dict([(j, i) for i, j in self.flag_desc_table])
        self.maxValue = sum([j for i, j in self.flag_desc_table])
        self.minInputRows = self.maxInputRows = max(len(self.flag_desc_table), 1)

    def sanitize(self, attrValue):
        try:
            result = int(attrValue)
        except ValueError:
            result = 0
            for row in attrValue.split('\n'):
                row = row.strip()
                try:
                    flag_set, flag_desc = row[0], row[1:]
                except IndexError:
                    pass
                else:
                    if flag_set == '+':
                        try:
                            result = result|self.flag_desc2int[flag_desc]
                        except KeyError:
                            pass
        return str(result)

    def formValue(self):
        attr_value_int = int(self._av or 0)
        flag_lines = [
            ''.join((
                self.true_false_desc[int((attr_value_int&flag_int) > 0)],
                flag_desc
            ))
            for flag_desc, flag_int in self.flag_desc_table
        ]
        return u'\r\n'.join(flag_lines)

    def formField(self):
        form_value = self.formValue()
        return web2ldap.web.forms.Textarea(
            self._at,
            ': '.join([self._at, self.desc]),
            self.maxLen, self.maxValues,
            None,
            default=form_value,
            rows=max(self.minInputRows, min(self.maxInputRows, form_value.count('\n'))),
            cols=max([len(desc) for desc, _ in self.flag_desc_table])+1
        )

    def displayValue(self, valueindex=0, commandbutton=False):
        attrValue_int = int(self._av)
        return (
            '%s<br>'
            '<table summary="Flags">'
            '<tr><th>Property flag</th><th>Value</th><th>Status</th></tr>'
            '%s'
            '</table>'
        ) % (
            Integer.displayValue(self, valueindex, commandbutton),
            '\n'.join([
                '<tr><td>%s</td><td>%s</td><td>%s</td></tr>' % (
                    self._app.form.utf2display(desc),
                    hex(flag_value),
                    {False:'-', True:'on'}[int((attrValue_int & flag_value) > 0)]
                )
                for desc, flag_value in self.flag_desc_table
            ])
        )


class GSER(DirectoryString):
    oid = 'GSER-oid'
    desc = 'GSER syntax (see RFC 3641)'


class UUID(IA5String):
    oid = '1.3.6.1.1.16.1'
    desc = 'UUID'
    reObj = re.compile(
        '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$'
    )

    def sanitize(self, attrValue):
        try:
            return str(uuid.UUID(attrValue.replace(':', '')))
        except ValueError:
            return attrValue


class DNSDomain(IA5String):
    oid = 'DNSDomain-oid'
    desc = 'DNS domain name (see RFC 1035)'
    reObj = re.compile(r'^(\*|[a-zA-Z0-9_-]+)(\.[a-zA-Z0-9_-]+)*$')
    maxLen = min(255, IA5String.maxLen) # (see https://tools.ietf.org/html/rfc2181#section-11)
    simpleSanitizers = (
        str.lower,
        str.strip,
    )

    def sanitize(self, attrValue):
        attrValue = IA5String.sanitize(self, attrValue)
        return '.'.join([
            dc.encode('idna')
            for dc in attrValue.decode(self._app.form.accept_charset).split(u'.')
        ])

    def formValue(self):
        try:
            result = u'.'.join([
                dc.decode('idna')
                for dc in (self._av or '').split('.')
            ])
        except UnicodeDecodeError:
            result = u'!!!snipped because of UnicodeDecodeError!!!'
        return result

    def displayValue(self, valueindex=0, commandbutton=False):
        if self._av.decode('ascii') != self._av.decode('idna'):
            return '%s (%s)' % (
                IA5String.displayValue(self, valueindex, commandbutton),
                self._app.form.utf2display(self.formValue())
            )
        return IA5String.displayValue(self, valueindex, commandbutton)


class RFC822Address(DNSDomain, IA5String):
    oid = 'RFC822Address-oid'
    desc = 'RFC 822 mail address'
    reObj = re.compile(r'^[\w@.+=/_ ()-]+@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*$')
    html_tmpl = '<a href="mailto:{av}">{av}</a>'

    def __init__(self, app, dn, schema, attrType, attrValue, entry=None):
        IA5String.__init__(self, app, dn, schema, attrType, attrValue, entry)

    def formValue(self):
        if not self._av:
            return IA5String.formValue(self)
        try:
            localpart, domainpart = self._av.rsplit('@')
        except ValueError:
            return IA5String.formValue(self)
        dns_domain = DNSDomain(
            self._app, self._dn, self._schema, None, domainpart,
        )
        return '@'.join((
            localpart.decode(self._app.ls.charset),
            dns_domain.formValue()
        ))

    def sanitize(self, attrValue):
        try:
            localpart, domainpart = attrValue.rsplit('@')
        except ValueError:
            return attrValue
        else:
            return '@'.join((
                localpart,
                DNSDomain.sanitize(self, domainpart)
            ))


class DomainComponent(DNSDomain):
    oid = 'DomainComponent-oid'
    desc = 'DNS domain name component'
    reObj = re.compile(r'^(\*|[a-zA-Z0-9_-]+)$')
    maxLen = min(63, DNSDomain.maxLen) # (see https://tools.ietf.org/html/rfc2181#section-11)


class YesNoIntegerFlag(SelectList):
    oid = 'YesNoIntegerFlag-oid'
    desc = '0 means no, 1 means yes'
    attr_value_dict = {
        u'0': u'no',
        u'1': u'yes',
    }


class OnOffFlag(SelectList):
    oid = 'OnOffFlag-oid'
    desc = 'Only values "on" or "off" are allowed'
    attr_value_dict = {
        u'on': u'on',
        u'off': u'off',
    }


class JSONValue(PreformattedMultilineText):
    oid = 'JSONValue-oid'
    desc = 'JSON data'
    lineSep = '\n'
    mimeType = 'application/json'

    def _validate(self, attrValue):
        try:
            json.loads(attrValue)
        except ValueError:
            return False
        return True

    def _split_lines(self, value):
        try:
            obj = json.loads(value)
        except ValueError:
            return PreformattedMultilineText._split_lines(self, value)
        return PreformattedMultilineText._split_lines(
            self,
            self._app.ls.uc_decode(
                json.dumps(
                    obj,
                    indent=4,
                    separators=(',', ': ')
                )
            )[0]
        )


class XmlValue(PreformattedMultilineText):
    oid = 'XmlValue-oid'
    desc = 'XML data'
    lineSep = '\n'
    mimeType = 'text/xml'

    def _validate(self, attrValue):
        try:
            xml.etree.ElementTree.XML(attrValue)
        except XMLParseError:
            return False
        return True


class ASN1Object(Binary):
    oid = 'ASN1Object-oid'
    desc = 'BER encoded ASN.1 data'

    def displayValue(self, valueindex=0, commandbutton=False):
        asn1obj = asn1.parse(self._av)
        return ''.join((
            '<code>',
            self._app.form.utf2display(
                str(asn1obj).decode('utf-8').replace('{', '\n{').replace('}', '}\n')
            ).replace('  ', '&nbsp;&nbsp;').replace('\n', '<br>'),
            '</code>'
        ))


class DumpASN1CfgOID(OID):
    oid = 'DumpASN1Cfg-oid'
    desc = "OID registered in Peter Gutmann's dumpasn1.cfg"

    def displayValue(self, valueindex=0, commandbutton=False):
        attrValue = self._av.encode('ascii')
        try:
            pisces_oid = asn1.OID(tuple(map(int, attrValue.split('.'))))
            desc = web2ldap.mspki.asn1helper.GetOIDDescription(
                pisces_oid,
                web2ldap.mspki.asn1helper.oids,
                includeoid=1
            )
        except ValueError:
            return self._app.form.utf2display(self._av)
        return desc


class AlgorithmOID(OID):
    """
    This base-class class is used for OIDs of cryptographic algorithms
    """
    oid = 'AlgorithmOID-oid'


class HashAlgorithmOID(SelectList, AlgorithmOID):
    oid = 'HashAlgorithmOID-oid'
    desc = 'values from https://www.iana.org/assignments/hash-function-text-names/'
    attr_value_dict = {
        u'1.2.840.113549.2.2': u'md2',         # [RFC3279]
        u'1.2.840.113549.2.5': u'md5',         # [RFC3279]
        u'1.3.14.3.2.26': u'sha-1',            # [RFC3279]
        u'2.16.840.1.101.3.4.2.4': u'sha-224', # [RFC4055]
        u'2.16.840.1.101.3.4.2.1': u'sha-256', # [RFC4055]
        u'2.16.840.1.101.3.4.2.2': u'sha-384', # [RFC4055]
        u'2.16.840.1.101.3.4.2.3': u'sha-512', # [RFC4055]
    }


class HMACAlgorithmOID(SelectList, AlgorithmOID):
    oid = 'HMACAlgorithmOID-oid'
    desc = 'values from RFC 8018'
    attr_value_dict = {
        # from RFC 8018
        u'1.2.840.113549.2.7': u'hmacWithSHA1',
        u'1.2.840.113549.2.8': u'hmacWithSHA224',
        u'1.2.840.113549.2.9': u'hmacWithSHA256',
        u'1.2.840.113549.2.10': u'hmacWithSHA384',
        u'1.2.840.113549.2.11': u'hmacWithSHA512',
    }


class ComposedAttribute(LDAPSyntax):
    """
    This mix-in plugin class composes attribute values from other attribute values.

    One can define an ordered sequence of string templates in class
    attribute ComposedDirectoryString.compose_templates.
    See examples in module web2ldap.app.plugins.inetorgperson.

    Obviously this only works for single-valued attributes,
    more precisely only the "first" attribute value is used.
    """
    oid = 'ComposedDirectoryString-oid'
    compose_templates = ()

    class single_value_dict(dict):
        """
        dictionary-like class which only stores and returns the
        first value of an attribute value list
        """

        def __init__(self, entry=None):
            dict.__init__(self)
            entry = entry or {}
            for key, val in entry.items():
                self.__setitem__(key, val)

        def __setitem__(self, key, val):
            if val and val[0]:
                dict.__setitem__(self, key, val[0])

    def formValue(self):
        """
        Return a dummy value that attribute is returned from input form and
        then seen by .transmute()
        """
        return u''

    def transmute(self, attrValues):
        """
        always returns a list with a single value based on the first
        successfully applied compose template
        """
        entry = self.single_value_dict(self._entry)
        for template in self.compose_templates:
            try:
                attr_values = [template.format(**entry)]
            except KeyError:
                continue
            else:
                break
        else:
            attr_values = attrValues
        return attr_values

    def formField(self):
        """
        composed attributes must only have hidden input field
        """
        input_field = web2ldap.web.forms.HiddenInput(
            self._at,
            ': '.join([self._at, self.desc]),
            self.maxLen,
            self.maxValues,
            None,
            default=self.formValue(),
        )
        input_field.charset = self._app.form.accept_charset
        return input_field


class LDAPv3ResultCode(SelectList):
    oid = 'LDAPResultCode-oid'
    desc = 'LDAPv3 declaration of resultCode in (see RFC 4511)'
    attr_value_dict = {
        u'0': u'success',
        u'1': u'operationsError',
        u'2': u'protocolError',
        u'3': u'timeLimitExceeded',
        u'4': u'sizeLimitExceeded',
        u'5': u'compareFalse',
        u'6': u'compareTrue',
        u'7': u'authMethodNotSupported',
        u'8': u'strongerAuthRequired',
        u'9': u'reserved',
        u'10': u'referral',
        u'11': u'adminLimitExceeded',
        u'12': u'unavailableCriticalExtension',
        u'13': u'confidentialityRequired',
        u'14': u'saslBindInProgress',
        u'16': u'noSuchAttribute',
        u'17': u'undefinedAttributeType',
        u'18': u'inappropriateMatching',
        u'19': u'constraintViolation',
        u'20': u'attributeOrValueExists',
        u'21': u'invalidAttributeSyntax',
        u'32': u'noSuchObject',
        u'33': u'aliasProblem',
        u'34': u'invalidDNSyntax',
        u'35': u'reserved for undefined isLeaf',
        u'36': u'aliasDereferencingProblem',
        u'48': u'inappropriateAuthentication',
        u'49': u'invalidCredentials',
        u'50': u'insufficientAccessRights',
        u'51': u'busy',
        u'52': u'unavailable',
        u'53': u'unwillingToPerform',
        u'54': u'loopDetect',
        u'64': u'namingViolation',
        u'65': u'objectClassViolation',
        u'66': u'notAllowedOnNonLeaf',
        u'67': u'notAllowedOnRDN',
        u'68': u'entryAlreadyExists',
        u'69': u'objectClassModsProhibited',
        u'70': u'reserved for CLDAP',
        u'71': u'affectsMultipleDSAs',
        u'80': u'other',
    }


# Set up the central syntax registry instance
syntax_registry = SyntaxRegistry()

# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
