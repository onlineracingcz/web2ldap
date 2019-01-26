"""
asn1helper.py - base classes of ASN.1 types

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from web2ldap.pisces import asn1

from . import util

url_prefix = ''
url_target = '_top'


class BitString(asn1.BitString):
    """
    BIT STRING { }

    This class emulates a sequence class with the index
    treated as number of the bit from 0..bit length.
    """
    bit_str = {}
    def __int__(self):
        return int(util.bytestolong(self.val))

    def __len__(self):
        """Return the possible number of bits"""
        return len(self.bit_str.keys())

    def __getitem__(self, i):
        """Return the value of a single bit"""
        self_len = len(self)
        if i < 0:
            i = i + self_len
        if i < 0 or i >= self_len:
            raise IndexError("list index %d out of range" % (i))
        elif i/8 < len(self.val):
            v = str(self.val)
            return ord(v[i/8])&(1<<((7-i)%8)) > 0
        else:
            return 0

    def __getslice__(self, i, j):
        return [self[x] for x in range(i, j)]

    def __str__(self):
        bitlength = len(self)
        result = map(
            lambda x, d=self.bit_str: d.get(x, 'Bit %d'%(x)),
            filter(
                lambda x, s=self: s[x],
                range(bitlength)
            )
        )
        return ', '.join(result)

    def __repr__(self):
        return '<%s: %s>' % (self.__class__.__name__, self)

    def html(self):
        return str(self)


class SequenceOf(asn1.Sequence):
    """
    SEQUENCE OF ItemClass
    """
    item_class = None

    def __init__(self, val):
        asn1.Sequence.__init__(self, val)
        if self.item_class != None:
            for i in xrange(len(self.val)):
                self.val[i] = self.item_class(self.val[i])

    def __str__(self):
        return ', '.join(map(str, self.val))

    def __repr__(self):
        return '{%s}' % ', '.join(map(repr, self.val))

    def html(self):
        return '<ul>\n%s\n</ul>\n' % (
            '\n'.join([
                '<li>%s</li>' % (x.html())
                for x in self.val
            ])
        )


class AttributeSequence(asn1.Sequence):
    """
    Base class for Sequence containing named attributes
    """
    attr_list = []

    def __init__(self, val):
        asn1.Sequence.__init__(self, val)

    def __str__(self):
        attrs = filter(lambda attr, s=self: hasattr(s, attr), self.attr_list)
        return ', '.join(
            map(
                lambda attr, s=self: str(getattr(s, attr)),
                attrs,
            )
        )

    def __repr__(self):
        attrs = filter(lambda attr, s=self: hasattr(s, attr), self.attr_list)
        return '<%s: %s>' % (
            self.__class__.__name__,
            ', '.join(
                map(
                    lambda attr, s=self: '%s:%s' % (attr, repr(getattr(s, attr))),
                    attrs
                )
            )
        )

    def html(self):
        l = []
        for attr in self.attr_list:
            if hasattr(self, attr):
                o = getattr(self, attr)
                if hasattr(o, 'html'):
                    dd = o.html()
                else:
                    dd = str(o)
                l.append('<dt>%s</dt>\n<dd>%s</dd>\n' % (attr, dd))
        return '<dl>\n%s\n</dl>' % ('\n'.join(l))
