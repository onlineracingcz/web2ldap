# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for dynamic entries (see RFC 2589)
"""

import time

from web2ldap.utctime import strftimeiso8601

from web2ldap.app.schema.syntaxes import Timespan, DistinguishedName, syntax_registry


class EntryTTL(Timespan):
    oid: str = 'EntryTTL-oid'
    desc: str = 'Time-to-live of dynamic entry'

    def display(self, valueindex=0, commandbutton=False) -> str:
        expiration_time = time.time()+int(self._av)
        return '%s, expires %s' % (
            Timespan.display(self, valueindex, commandbutton),
            strftimeiso8601(time.gmtime(expiration_time)),
        )

syntax_registry.reg_at(
    EntryTTL.oid, [
        '1.3.6.1.4.1.1466.101.119.3', # entryTTL
    ]
)


class DynamicSubtrees(DistinguishedName):
    oid: str = 'DynamicSubtrees-oid'
    desc: str = 'Subtrees with dynamic entries'

    def _additional_links(self):
        res = DistinguishedName._additional_links(self)
        res.append(
            self._app.anchor(
                'search', 'Search',
                [
                    ('dn', self.av_u),
                    ('search_root', self.av_u),
                    ('filterstr', '(objectClass=dynamicObject)'),
                    ('searchform_mode', 'exp'),
                ],
                title='Search for dynamic entries',
            ),
        )
        return res

syntax_registry.reg_at(
    DynamicSubtrees.oid, [
        '1.3.6.1.4.1.1466.101.119.4', # dynamicSubtrees
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
