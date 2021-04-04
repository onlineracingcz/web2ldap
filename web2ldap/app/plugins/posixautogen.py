"""
Auto-generate some posixAccount attribute values

Status:
Experimental => you have to understand what it internally does when enabling it!
"""

import ldap0
from ldap0.res import SearchReference

from web2ldap.app.plugins.nis import syntax_registry, UidNumber, GidNumber, IA5String


class HomeDirectory(IA5String):
    oid: str = 'HomeDirectory-oid'
    desc: str = 'Path of Unix home directory of the user'
    uid_attr = 'uid'
    homeDirectoryTemplate = '/home/{uid}'

    def transmute(self, attr_values):
        if self.uid_attr not in self._entry:
            return attr_values
        if (
                not attr_values or
                not attr_values[0] or
                attr_values[0].decode(self._app.ls.charset) == self.homeDirectoryTemplate.format(**{self.uid_attr:''})
            ):
            fmt_dict = {self.uid_attr:self._entry[self.uid_attr][0].decode(self._app.ls.charset)}
            attr_values = [
                self.homeDirectoryTemplate.format(**fmt_dict).encode(self._app.ls.charset)
            ]
        return attr_values

syntax_registry.reg_at(
    HomeDirectory.oid, [
        '1.3.6.1.1.1.1.3', # homeDirectory
    ]
)


class AutogenNumberMixIn:
    input_size = 12
    minNewValue = 10000
    maxNewValue = 19999
    object_class = 'posixAccount'

    def formValue(self) -> str:
        if self.object_class.lower() not in {oc.lower().decode('ascii') for oc in self._entry['objectClass']}:
            return ''
        try:
            ldap_results = self._app.ls.l.search_s(
                str(self._app.naming_context),
                ldap0.SCOPE_SUBTREE,
                '(&(objectClass={0})({1}>={2})({1}<={3}))'.format(
                    self.object_class,
                    self._at,
                    self.__class__.minNewValue,
                    self.__class__.maxNewValue
                ),
                attrlist=[self._at],
            )
        except (
                ldap0.NO_SUCH_OBJECT,
                ldap0.SIZELIMIT_EXCEEDED,
                ldap0.TIMELIMIT_EXCEEDED,
            ):
            # search failed => no value suggested
            return ''
        idnumber_set = set()
        for res in ldap_results:
            if isinstance(res, SearchReference):
                continue
            if res.dn_s == self._dn:
                return res.entry_s[self._at][0]
            idnumber_set.add(int(res.entry_s[self._at][0]))
        for idnumber in range(self.__class__.minNewValue, self.maxNewValue+1):
            if idnumber in idnumber_set:
                self.__class__.minNewValue = idnumber
            else:
                break
        if idnumber > self.maxNewValue:
            # end of valid range reached => no value suggested
            return ''
        return str(idnumber)


class AutogenUIDNumber(UidNumber, AutogenNumberMixIn):
    oid: str = 'AutogenUIDNumber-oid'
    desc: str = 'numeric Unix-UID'
    minNewValue = 10000
    maxNewValue = 19999
    object_class = 'posixAccount'

    def formValue(self) -> str:
        form_value = UidNumber.formValue(self)
        if not form_value:
            form_value = AutogenNumberMixIn.formValue(self)
        return form_value # formValue()

syntax_registry.reg_at(
    AutogenUIDNumber.oid, [
        '1.3.6.1.1.1.1.0', # uidNumber
    ]
)


class AutogenGIDNumber(GidNumber, AutogenNumberMixIn):
    oid: str = 'AutogenGIDNumber-oid'
    desc: str = 'numeric Unix-GID'
    object_class = 'posixGroup'

    def formValue(self) -> str:
        form_value = GidNumber.formValue(self)
        if not form_value:
            form_value = AutogenNumberMixIn.formValue(self)
        return form_value # formValue()

syntax_registry.reg_at(
    AutogenGIDNumber.oid, [
        '1.3.6.1.1.1.1.1', # gidNumber
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
