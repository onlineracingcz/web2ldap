# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for attributes defined in draft-behera-ldap-password-policy
"""

import time
import datetime

from ldap0 import LDAPError

import web2ldap.app.searchform
from web2ldap.utctime import strptime
from web2ldap.app.schema.syntaxes import \
    SelectList, \
    DynamicDNSelectList, \
    Timespan, \
    GeneralizedTime, \
    syntax_registry
from web2ldap.app.plugins.quirks import UserPassword
from web2ldap import cmp


class PwdCheckQuality(SelectList):
    oid: str = 'PwdCheckQuality-oid'
    desc: str = 'Password quality checking enforced'
    attr_value_dict = {
        u'0': u'quality checking not be enforced',
        u'1': u'quality checking enforced, accepting un-checkable passwords',
        u'2': u'quality checking always enforced',
    }

syntax_registry.reg_at(
    PwdCheckQuality.oid, [
        '1.3.6.1.4.1.42.2.27.8.1.5', # pwdCheckQuality
    ]
)


class PwdAttribute(SelectList):
    oid: str = 'PwdAttribute-oid'
    desc: str = 'Password attribute'
    attr_value_dict = {
        u'2.5.4.35': u'userPassword',
    }

    def _validate(self, attrValue: bytes) -> bool:
        return (
            not attrValue or
            attrValue.lower() in {b'2.5.4.35', b'userpassword'}
        )

syntax_registry.reg_at(
    PwdAttribute.oid, [
        '1.3.6.1.4.1.42.2.27.8.1.1', # pwdAttribute
    ]
)


class PwdPolicySubentry(DynamicDNSelectList):
    oid: str = 'PwdPolicySubentry-oid'
    desc: str = 'DN of the pwdPolicy entry to be used for a certain entry'
    ldap_url = 'ldap:///_??sub?(|(objectClass=pwdPolicy)(objectClass=ds-cfg-password-policy))'

syntax_registry.reg_at(
    PwdPolicySubentry.oid, [
        '1.3.6.1.4.1.42.2.27.8.1.23', # pwdPolicySubentry
    ]
)


class PwdMaxAge(Timespan):
    oid: str = 'PwdMaxAge-oid'
    desc: str = 'pwdPolicy entry: Maximum age of user password'
    link_text = 'Search expired'
    title_text = u'Search for entries with this password policy and expired password'

    @staticmethod
    def _search_timestamp(diff_secs):
        return time.strftime('%Y%m%d%H%M%SZ', time.gmtime(time.time()-diff_secs))

    def _timespan_search_params(self):
        return (
            ('search_attr', 'pwdChangedTime'),
            ('search_option', web2ldap.app.searchform.SEARCH_OPT_LE_THAN),
            ('search_string', self._search_timestamp(int(self.av_u.strip()))),
        )

    def display(self, valueindex=0, commandbutton=False) -> str:
        ts_dv = Timespan.display(self, valueindex, commandbutton)
        # Possibly display a link
        ocs = self._entry.object_class_oid_set()
        if not commandbutton or not 'pwdPolicy' in ocs:
            return ts_dv
        try:
            ts_search_params = self._timespan_search_params()
        except (ValueError, KeyError):
            return ts_dv
        search_link = self._app.anchor(
            'searchform', self.link_text,
            (
                ('dn', self._dn),
                ('searchform_mode', u'adv'),
                ('search_attr', u'pwdPolicySubentry'),
                ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                ('search_string', self._dn),
            ) + ts_search_params,
            title=self.title_text,
        )
        return ' '.join((ts_dv, search_link))

syntax_registry.reg_at(
    PwdMaxAge.oid, [
        '1.3.6.1.4.1.42.2.27.8.1.3', # pwdMaxAge
    ]
)


class PwdExpireWarning(PwdMaxAge):
    oid: str = 'PwdExpireWarning-oid'
    desc: str = 'pwdPolicy entry: Password warning period'
    link_text = 'Search soon to expire'
    title_text = u'Search for entries with this password policy and soon to expire password'

    def _timespan_search_params(self):
        pwd_expire_warning = int(self.av_u.strip())
        pwd_max_age = int(self._entry['pwdMaxAge'][0].decode('ascii').strip())
        warn_timestamp = pwd_max_age-pwd_expire_warning
        return (
            ('search_attr', 'pwdChangedTime'),
            ('search_option', web2ldap.app.searchform.SEARCH_OPT_GE_THAN),
            ('search_string', self._search_timestamp(pwd_max_age)),
            ('search_attr', 'pwdChangedTime'),
            ('search_option', web2ldap.app.searchform.SEARCH_OPT_LE_THAN),
            ('search_string', self._search_timestamp(warn_timestamp)),
        )

syntax_registry.reg_at(
    PwdExpireWarning.oid, [
        '1.3.6.1.4.1.42.2.27.8.1.7', # pwdExpireWarning
    ]
)


class PwdAccountLockedTime(GeneralizedTime):
    oid: str = 'PwdAccountLockedTime-oid'
    desc: str = 'user entry: time that the account was locked'
    magic_values = {
        '000001010000Z': 'permanently locked',
    }

    def _validate(self, attrValue: bytes) -> bool:
        return attrValue in self.magic_values or GeneralizedTime._validate(self, attrValue)

    def display(self, valueindex=0, commandbutton=False) -> str:
        gt_disp_html = GeneralizedTime.display(self, valueindex, commandbutton)
        if self._av in self.magic_values:
            return '%s (%s)' % (gt_disp_html, self.magic_values[self._av])
        return gt_disp_html

syntax_registry.reg_at(
    PwdAccountLockedTime.oid, [
        '1.3.6.1.4.1.42.2.27.8.1.17', # pwdAccountLockedTime
    ]
)


class PwdChangedTime(GeneralizedTime):
    oid: str = 'PwdChangedTime-oid'
    desc: str = 'user entry: Last password change time'
    time_divisors = Timespan.time_divisors

    def display(self, valueindex=0, commandbutton=False) -> str:
        gt_disp_html = GeneralizedTime.display(self, valueindex, commandbutton)
        try:
            pwd_changed_dt = strptime(self._av)
        except ValueError:
            return gt_disp_html
        try:
            pwd_policy_subentry_dn = self._entry['pwdPolicySubentry'][0].decode(self._app.ls.charset)
        except KeyError:
            return gt_disp_html
        try:
            pwd_policy = self._app.ls.l.read_s(
                pwd_policy_subentry_dn,
                filterstr='(objectClass=pwdPolicy)',
                attrlist=['pwdMaxAge', 'pwdExpireWarning'],
            )
        except LDAPError:
            return gt_disp_html
        try:
            pwd_max_age_secs = int(pwd_policy.entry_s['pwdMaxAge'][0])
        except KeyError:
            expire_msg = 'will never expire'
        except ValueError:
            return gt_disp_html
        else:
            if pwd_max_age_secs:
                pwd_max_age = datetime.timedelta(seconds=pwd_max_age_secs)
                current_time = datetime.datetime.utcnow()
                expire_dt = pwd_changed_dt+pwd_max_age
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
                            u' ',
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
    PwdChangedTime.oid, [
        '1.3.6.1.4.1.42.2.27.8.1.16', # pwdChangedTime
    ]
)


syntax_registry.reg_at(
    UserPassword.oid, [
        '1.3.6.1.4.1.42.2.27.8.1.20', # pwdHistory
    ]
)


syntax_registry.reg_at(
    Timespan.oid, [
        '1.3.6.1.4.1.42.2.27.8.1.2',  # pwdMinAge
        '1.3.6.1.4.1.42.2.27.8.1.12', # pwdFailureCountInterval
        '1.3.6.1.4.1.42.2.27.8.1.10', # pwdLockoutDuration
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
