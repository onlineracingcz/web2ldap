# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for OATH-LDAP

see https://www.stroeder.com/oath-ldap.html
"""

import re
import datetime
import base64

from ldap0 import LDAPError

import web2ldap.app.gui
from web2ldap.utctime import strptime
from web2ldap.app.schema.syntaxes import \
    DirectoryString, \
    DynamicDNSelectList, \
    GeneralizedTime, \
    HMACAlgorithmOID, \
    JSONValue, \
    LDAPv3ResultCode, \
    OctetString, \
    SelectList, \
    Timespan, \
    syntax_registry
from web2ldap import cmp


syntax_registry.reg_at(
    JSONValue.oid, [
        '1.3.6.1.4.1.5427.1.389.4226.4.12', # oathEncKey
        '1.3.6.1.4.1.5427.1.389.4226.4.14', # oathTokenPIN
    ]
)


class OathOTPLength(SelectList):
    oid: str = 'OathOTPLength-oid'
    desc: str = 'number of OTP digits'
    attr_value_dict = {
        '6': '6',
        '8': '8',
    }

syntax_registry.reg_at(
    OathOTPLength.oid, [
        '1.3.6.1.4.1.5427.1.389.4226.4.5', # oathOTPLength
    ]
)


class OathHOTPParams(DynamicDNSelectList):
    oid: str = 'OathHOTPParams-oid'
    desc: str = 'DN of the oathHOTPParams entry'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=oathHOTPParams)'
    ref_attrs = (
        (None, 'Same params', None, None),
    )

syntax_registry.reg_at(
    OathHOTPParams.oid, [
        '1.3.6.1.4.1.5427.1.389.4226.4.5.1', # oathHOTPParams
    ]
)


class OathResultCode(LDAPv3ResultCode):
    oid: str = 'OathResultCode-oid'

syntax_registry.reg_at(
    OathResultCode.oid, [
        '1.3.6.1.4.1.5427.1.389.4226.4.13.1', # oathSuccessResultCode
        '1.3.6.1.4.1.5427.1.389.4226.4.13.2', # oathFailureResultCode
    ]
)


class OathHOTPToken(DynamicDNSelectList):
    oid: str = 'OathHOTPToken-oid'
    desc: str = 'DN of the oathHOTPToken entry'
    ldap_url = 'ldap:///_?oathTokenSerialNumber?sub?(objectClass=oathHOTPToken)'
    ref_attrs = (
        (None, 'Users', None, None),
    )

syntax_registry.reg_at(
    OathHOTPToken.oid, [
        '1.3.6.1.4.1.5427.1.389.4226.4.9.1', # oathHOTPToken
    ]
)


class OathTOTPParams(DynamicDNSelectList):
    oid: str = 'OathTOTPParams-oid'
    desc: str = 'DN of the oathTOTPParams entry'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=oathTOTPParams)'
    ref_attrs = (
        (None, 'Same params', None, None),
    )

syntax_registry.reg_at(
    OathTOTPParams.oid, [
        '1.3.6.1.4.1.5427.1.389.4226.4.5.2', # oathTOTPParams
    ]
)


class OathTOTPToken(DynamicDNSelectList):
    oid: str = 'OathTOTPToken-oid'
    desc: str = 'DN of the oathTOTPToken entry'
    ldap_url = 'ldap:///_?oathTokenSerialNumber?sub?(objectClass=oathTOTPToken)'
    ref_attrs = (
        (None, 'Users', None, None),
    )

syntax_registry.reg_at(
    OathTOTPToken.oid, [
        '1.3.6.1.4.1.5427.1.389.4226.4.9.2', # oathTOTPToken
    ]
)


class OathTokenIdentifier(DirectoryString):
    """
    see http://openauthentication.org/specification/tokenSpecs
    """
    oid: str = 'OathTokenIdentifier-oid'
    desc: str = 'Globally unique token identifier'
    maxLen: str = 12
    reObj = re.compile(r'^[a-zA-Z0-9]{12}$')

syntax_registry.reg_at(
    OathTokenIdentifier.oid, [
        '1.3.6.1.4.1.5427.1.389.4226.4.3', # oathTokenIdentifier
    ]
)


class OathInitPwAlphabet(DirectoryString):
    oid: str = 'OathInitPwAlphabet-oid'
    desc: str = 'Alphabet used to generate init passwords'

    def sanitize(self, attrValue: bytes) -> bytes:
        return ''.join([
            self._app.ls.uc_encode(c)[0]
            for c in sorted(set(
                self._app.ls.uc_decode(attrValue or '')[0].replace(' ', '')
            ))
        ])


syntax_registry.reg_at(
    HMACAlgorithmOID.oid, [
        '1.3.6.1.4.1.5427.1.389.4226.4.6',  # oathHMACAlgorithm
    ]
)


syntax_registry.reg_at(
    Timespan.oid, [
        '1.3.6.1.4.1.5427.1.389.4226.4.4.1', # oathTOTPTimeStepPeriod
        '1.3.6.1.4.1.5427.1.389.4226.4.8',   # oathSecretMaxAge
    ]
)


class OathSecret(OctetString):
    oid: str = 'OathSecret-oid'
    desc: str = 'OATH shared secret'

    def display(self, valueindex=0, commandbutton=False) -> str:
        return '<br>'.join((
            self._app.form.utf2display(base64.b32encode(self._av).decode('ascii')),
            OctetString.display(self, valueindex, commandbutton),
        ))

syntax_registry.reg_at(
    OathSecret.oid, [
        '1.3.6.1.4.1.5427.1.389.4226.4.1',  # oathSecret
    ]
)


class OathSecretTime(GeneralizedTime):
    oid: str = 'OathSecretTime-oid'
    desc: str = 'OATH secret change time'
    time_divisors = Timespan.time_divisors

    def display(self, valueindex=0, commandbutton=False) -> str:
        ocs = self._entry.object_class_oid_set()
        gt_disp_html = GeneralizedTime.display(self, valueindex, commandbutton)
        if 'oathHOTPToken' in ocs:
            oath_params_dn_attr = 'oathHOTPParams'
        elif 'oathTOTPToken' in ocs:
            oath_params_dn_attr = 'oathTOTPParams'
        else:
            return gt_disp_html
        try:
            oath_secret_time_dt = strptime(self._av)
        except ValueError:
            return gt_disp_html
        try:
            oath_params_dn = self._entry[oath_params_dn_attr][0].decode(self._app.ls.charset)
        except KeyError:
            return gt_disp_html
        try:
            oath_params = self._app.ls.l.read_s(oath_params_dn, attrlist=['oathSecretMaxAge'])
        except LDAPError:
            return gt_disp_html
        try:
            oath_secret_max_age_secs = int(oath_params.entry_s['oathSecretMaxAge'][0])
        except KeyError:
            expire_msg = 'will never expire'
        except ValueError:
            return gt_disp_html
        else:
            if oath_secret_max_age_secs:
                oath_secret_max_age = datetime.timedelta(seconds=oath_secret_max_age_secs)
                current_time = datetime.datetime.utcnow()
                expire_dt = oath_secret_time_dt+oath_secret_max_age
                expired_since = (expire_dt-current_time).total_seconds()
                expire_cmp = cmp(expire_dt, current_time)
                expire_msg = '%s %s (%s %s)' % (
                    {
                        -1: 'expired since',
                        0: '',
                        1: 'will expire',
                    }[expire_cmp],
                    expire_dt.strftime('%c'),
                    self._app.form.utf2display(
                        web2ldap.app.gui.ts2repr(
                            self.time_divisors,
                            ' ',
                            abs(expired_since),
                        )
                    ),
                    {
                        -1: 'ago',
                        0: '',
                        1: 'ahead',
                    }[expire_cmp],
                )
            else:
                expire_msg = 'will never expire'
        return self.readSep.join((gt_disp_html, expire_msg))


syntax_registry.reg_at(
    OathSecretTime.oid, [
        '1.3.6.1.4.1.5427.1.389.4226.4.7.3', # oathSecretTime
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
