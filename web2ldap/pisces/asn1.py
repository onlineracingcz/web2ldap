"""
A parser for ASN1 object encoded using BER

The doc string just sketches the names of objects in the module.
Consult the documentation for more details.

Burton S. Kaliski Jr. wrote a helpful introduction to ASN.1 and the
BER encoding titled 'A Layman's Guide to a Subset of ASN.1, BER, and
DER.'  It is available from http://www.rsasecurity.com/rsalabs/pkcs/.
The text version is available at
    ftp://ftp.rsasecurity.com/pub/pkcs/ascii/layman.asc.

functions:
    parse(buf: string) -> ASN1Object
    display(obj: ASN1Object)
    parseCfg(path) -> {oid:name}

classes:
    ASN1Object
    plus subclasses for each asn.1 type, e.q. Sequence, Set, etc.

constants:
    INTEGER, BIT_STRING, OCTET_STRING, NULL, OBJECT_IDENTIFIER,
    SEQUENCE, SET, PrintableString, T61String, IA5String, UTCTIME,
    BOOLEAN

The following objects are not part of the user-visible API:
Displayer
ASN1Parser
unparseLengthXXX functions
"""

from __future__ import absolute_import

import struct
import sys
import types
import UserList
import UserString
import time
from cStringIO import StringIO

class EOFError(IOError):
    pass

# tags for universal types
INTEGER = 0x02
BIT_STRING = 0x03
OCTET_STRING = 0x04
NULL = 0x05
OBJECT_IDENTIFIER = 0x06
SEQUENCE = 0x10
SET = 0x11
PRINTABLE_STRING = 0x13
T61STRING = 0x14
IA5STRING = 0x16  # IA5 == ASCII
UTCTIME = 0x17
BOOLEAN = 0x01
UNIVERSALSTRING = 28
BMPSTRING = 30
UTF8STRING = 12
VISIBLESTRING = 26
GENERALIZEDTIME = 24

# tag classes
CLASS_MASK = 0xC0
UNIVERSAL = 0x00
APPLICATION = 0x40
CONTEXTUAL = 0x80
PRIVATE = 0xC0

# encoding info
ENCODING_MASK = 0x20
CONSTRUCTED = 0x20
PRIMITVE = 0x00
TAG_MASK = 0x1F

class Displayer:
    def __init__(self, oids=None):
        if oids:
            self.oids = oids
    def __call__(self, obj, indent=0):
        try:
            if obj.atomic:
                if self.oids and isinstance(obj, OID) \
                   and self.oids.has_key(obj):
                    info = self.oids[obj]
                    if info.has_key('Warning'):
                        print " " * indent, "OID", info['Description'], \
                              "Warning"
                    else:
                        print " " * indent, "OID", info['Description']
                    return
                print " " * indent, str(obj)
            else:
                if isinstance(obj, Contextual):
                    print " " * indent, "[%d]"% obj.tag
                    display(obj.val, indent+1)
                else:
                    print " " * indent, obj.__class__.__name__, "{"
                    for elt in obj.val:
                        display(elt, indent+1)
                    print " " * indent, "}"
        except AttributeError:
            print " " * indent, repr(obj)

def display(obj, indent=0):
    # XXX doesn't work on constructed yet
    try:
        if obj.atomic:
            print " " * indent + str(obj)
        else:
            if isinstance(obj, Contextual):
                print " " * indent, "[%d]"% obj.tag
                display(obj.val, indent+1)
            else:
                print " " * indent, obj.__class__.__name__, "{"
                for elt in obj.val:
                    display(elt, indent+1)
                print " " * indent, "}"
    except AttributeError:
        print " " * indent, repr(obj)

class ASN1Object:
    atomic = 1

    def __init__(self, val):
        self.val = val

    # XXX need to make sure this really works everywhere; it's a late
    # addition.  it requires that all objects have a val that is a
    # list.
    def __cmp__(self, other):
        if isinstance(other, ASN1Object):
            return cmp(self.val, other.val)
        return -1

    def __repr__(self):
        return "%s:%s" % (self.__class__.__name__, repr(self.val))

    def encode(self, io=None):
        if io is None:
            io = StringIO()
            ioFlag = 1
        else:
            ioFlag = 0
        try:
            encode = self._encode
        except AttributeError:
            raise AttributeError, \
                  ("%s instance does not implement _encode" %
                   self.__class__.__name__)
        else:
            encode(io)
        if ioFlag:
            return io.getvalue()

class Sequence(ASN1Object, UserList.UserList):
    atomic = 0
    def __init__(self, val=None):
        if not val:
            val = []
        self.val = self.data = val

    def __repr__(self):
        return "SEQUENCE {" + repr(self.val)[1:-1] + "}"

    def _encode(self, io):
        encObjs = []
        for elt in self.data:
            encObjs.append(encode(elt))
        io.write(unparseSequence(encObjs))

class Set(ASN1Object, UserList.UserList):
    atomic = 0
    def __init__(self, val):
        # XXX I don't remember why I only get a single value here
        self.val = self.data = [val]
    def __repr__(self):
        return "SET {" + repr(self.val) + "}"
    def _encode(self, io):
        encObjs = []
        for elt in self.data:
            encObjs.append(encode(elt))
        io.write(unparseSet(encObjs))

class String(ASN1Object, UserString.UserString):
    # abstract base class
    tag = None
    def __init__(self, val):
        self.data = self.val = val

    def _encode(self, io):
        io.write(chr(self.tag) + unparseLength(len(self.val)) + self.val)

class BitString(String):
    tag = BIT_STRING
    def __init__(self, val, unused=0):
        self.data = self.val = val
        self.unused = unused
    def _encode(self, io):
        io.write(chr(self.tag) + unparseLength(len(self.val) + 1) \
                 + chr(self.unused) + self.val)

class PrintableString(String):
    tag = PRINTABLE_STRING

class OctetString(String):
    tag = OCTET_STRING

class T61String(String):
    tag = T61STRING

class IA5String(String):
    tag = IA5STRING

class GeneralizedTime(ASN1Object):
    """The generalized time type, GeneralizedTime, is a standard ASN.1 type
    for variable precision representation of time.  Optionally, the
    GeneralizedTime field can include a representation of the time
    differential between local and Greenwich Mean Time.
    """

    def __init__(self, val=None):
        if type(val) == types.StringType:
            self.val = val
            self._val = None
        else:
            self.unparse(val)

    def __cmp__(self, other):
        return cmp(self.val, other.val)

    def _encode(self, io):
        io.write(chr(GENERALIZEDTIME) + unparseLength(len(self.val)) + self.val)

    def unparse(self, val):
        """Convert a Python time representation to UTC time.

        Argument must be in UTC.
        """
        # Python dates might be represented as seconds or time tuples.
        # I'll simply require that both times have the same repr.

        # UTC is easier to cope with because the user can make sure a
        # time tuple is in  UTC, but it would be a pain for me to do that.
        self._val = time.mktime(val)
        if type(val) != types.TupleType:
            try:
                val = time.gmtime(val)
            except TypeError:
                raise TypeError, "time must be seconds or time-tuple"
        yy = val[0]
        if yy >= 2000:
            yy = yy - 2000
            if yy >= 50:
                # man this is braind-dead
                raise ValueError, "can't handle data that far in future"
        elif yy < 2000:
            yy = yy - 1900
            if yy < 50:
                raise ValueError, "can't handle data that far in past"
        self.val = "%02d%02d%02d%02d%02d%02dZ" % (yy, val[1], val[2],
                                                  val[3], val[4], val[5])

    def _parse(self):
        if self._val:
            return self._val
        yy = int(self.val[:2])
        mm1 = int(self.val[2:4])
        dd = int(self.val[4:6])
        hh = int(self.val[6:8])
        mm2 = int(self.val[8:10])
        ss = int(self.val[10:12])
        assert self.val[-1] == 'Z'

        if yy >= 50:
            yy = 1900 + yy
        else:
            yy = 2000 + yy
        self._val = time.mktime((yy, mm1, dd, hh, mm2, ss, -1, -1, -1)) \
                    - time.timezone
        return self._val


class UTCTime(ASN1Object):
    """Standard ASN.1 type for time expressed in GMT

    draft-ietf-pkix-ipki-part1-08.txt notes:
    For the purposes of this profile, UTCTime values shall be expressed
    Greenwich Mean Time (Zulu) and shall include seconds (i.e., times are
    YYMMDDHHMMSSZ), even where the number of seconds is zero.  Conforming
    systems shall interpret the year field (YY) as follows:

    Where YY is greater than or equal to 50, the year shall be inter-
    preted as 19YY; and

    Where YY is less than 50, the year shall be interpreted as 20YY.
    """

    def __init__(self, val=None):
        if type(val) == types.StringType:
            self.val = val
            self._val = None
        else:
            self.unparse(val)

    def __cmp__(self, other):
        return cmp(self.val, other.val)

    def _encode(self, io):
        io.write(chr(UTCTIME) + unparseLength(len(self.val)) + self.val)

    def unparse(self, val):
        """Convert a Python time representation to UTC time.

        Argument must be in UTC.
        """
        # Python dates might be represented as seconds or time tuples.
        # I'll simply require that both times have the same repr.

        # UTC is easier to cope with because the user can make sure a
        # time tuple is in  UTC, but it would be a pain for me to do that.
        self._val = time.mktime(val)
        if type(val) != types.TupleType:
            try:
                val = time.gmtime(val)
            except TypeError:
                raise TypeError, "time must be seconds or time-tuple"
        yy = val[0]
        if yy >= 2000:
            yy = yy - 2000
            if yy >= 50:
                # man this is braind-dead
                raise ValueError, "can't handle data that far in future"
        elif yy < 2000:
            yy = yy - 1900
            if yy < 50:
                raise ValueError, "can't handle data that far in past"
        self.val = "%02d%02d%02d%02d%02d%02dZ" % (yy, val[1], val[2],
                                                  val[3], val[4], val[5])

    def _parse(self):
        if self._val:
            return self._val
        yy = int(self.val[:2])
        mm1 = int(self.val[2:4])
        dd = int(self.val[4:6])
        hh = int(self.val[6:8])
        mm2 = int(self.val[8:10])
        ss = int(self.val[10:12])
        assert self.val[-1] == 'Z'

        if yy >= 50:
            yy = 1900 + yy
        else:
            yy = 2000 + yy
        self._val = time.mktime((yy, mm1, dd, hh, mm2, ss, -1, -1, -1)) \
                    - time.timezone
        return self._val

class Contextual(ASN1Object):
    """Wrapper for optional and choice encoded items (primarily)

    For contextual encoding, we can't necessarily tell what the type
    of the value is without looking at the ASN.1 type decl.  Of
    course, the whole purpose of this module is to avoid looking at
    the type decl -- so we can't win (directly).

    The solution is this thunk object.  When the decoded structure is
    actually used, it should be clear whether this is, say, an
    OPTIONAL integer type, some other tagged, known type, or an
    encoded CHOICE.  Call the decode method when the encoding includes
    the full DER encoding.  Call choose when the value doesn't have
    the appropriate tag/len info.
    """
    def __init__(self, tag, length, val):
        self.tag = tag
        self.length = length
        self.val = val
        self.unknown = 1
        if self.val:
            self.atomic = 0
        else:
            self.atomic = 1
    def __repr__(self):
        if self.unknown:
            return '<contextual %d %d>' % (self.tag, self.length)
        elif self.val:
            return "[%d] {" % self.tag + repr(self.val) + "}"
        else:
            return "[%d]" % self.tag

    def decode(self):
        if self.unknown:
            self.val = parse(self.val)
            self.unknown = 0
        return self.val

    def choose(self, tag):
        if self.unknown:
            p = parse(self.val)
            p.id = 0
            p.length = self.length
            self.val = p._parse(tag, self.length)
            self.unknown = 0
        return self.val

class Constructed(ASN1Object):
    def __init__(self, enc, tag, length, val):
        self.enc = enc
        self.tag = tag
        self.length = length
        self._parse(val)

    def _parse(self, val):
        assert type(val) == types.StringType, '***bah!'
        p = ASN1Parser(StringIO(val))
        self.val = p.parse()
        self.val_tag = p.tag
        self.val_length = p.length

    def __cmp__(self, other):
        if isinstance(other, Constructed):
            return cmp((self.tag, self.val), (other.tag, other.val))
        return -1

    def __repr__(self):
        return "[%d] {%s}" % (self.tag, repr(self.val))

    def _encode(self, io):
        io.write(chr(CONTEXTUAL | CONSTRUCTED | self.tag) + chr(self.length) \
                 + encode(self.val))


class Boolean(ASN1Object):
    def __nonzero__(self):
        if self.val:
            return 1
        else:
            return 0
    def __repr__(self):
        if self.val:
            return 'TRUE'
        else:
            return 'FALSE'
    def _encode(self, io):
        io.write(chr(BOOLEAN) + chr(1) + chr(self.val))

class OID(ASN1Object):
    def __init__(self, val):
        self.val = tuple(val)
    def __hash__(self):
        if not hasattr(self, '_hash'):
            self._hash = self.val.__hash__()
        return self._hash
    def __cmp__(self, other):
        return cmp(self.val, other.val)
    def __repr__(self):
        return '.'.join(map(str, self.val))
    def _encode(self, io):
        elts = self.val
        bytes = []
        bytes.append(40 * elts[0] + elts[1])
        for elt in elts[2:]:
            if elt < 0x7F:
                bytes.append(elt)
            else:
                temp = []
                div = rem = elt
                while div:
                    div, rem = divmod(div, 128)
                    temp.append(rem)
                temp.reverse()
                head = map(lambda x:x | 0x80, temp[:-1])
                bytes = bytes + head + temp[-1:]
        io.write(chr(OBJECT_IDENTIFIER) + unparseLength(len(bytes))
                 + ''.join(map(chr, bytes)))

class ASN1Parser:
    # Keeps some state around between method invocations, which
    # simplifies programming
    #
    # This code can safely raise EOFError inside methods, which will
    # be caught by parse and raise ValueError, "unexpected end of input"

    VERBOSE = 0

    def __init__(self, io):
        self.io = io
        # all these instance variables store information about the
        # more recently read tag
        self.tag = None
        self.id = None
        self.length = 0
        self.indefinite = None
        self.constructed = None

    def getTag(self):
        c = self.io.read(1)
        if c == '':
            raise EOFError
        tag = ord(c)
        if self.VERBOSE:
            sys.stderr.write("tag %s\n" % hex(tag))
        self.id = tag & ~TAG_MASK
        self.tag = tag & TAG_MASK

        if tag & ENCODING_MASK == CONSTRUCTED:
            self.constructed = 1

        if self.tag == TAG_MASK:
            # high-tag-number
            tag = 0
            while 1:
                c = ord(self.io.read(1))
                tag = (tag << 7) | (tag & 0x7F)
                if c & 0x80:
                    break
            self.tag = tag
        return self.tag

    def getLength(self):
        oct1 = ord(self.io.read(1))
        if oct1 == 0x80:
            self.length = 0
            self.indefinite = 1
        if oct1 & 0x80:
            # lower bits indicate number of octets to represent length
            l = convertOctetsToInt(self.io.read(oct1 & 0x7F))
            self.length = l
        else:
            self.length = oct1 & 0x7F
        if self.VERBOSE:
            sys.stderr.write("length %d\n" % self.length)
        return self.length

    def getBody(self):
        buf = self.io.read(self.length)
#        if len(buf) != self.length:
#            raise EOFError
        return buf

    def ord(self, char):
        if len(char) == 0:
            raise EOFError
        return ord(char)

    def parse(self):
        try:
            self.tag = tag = self.getTag()
            self.length = length = self.getLength()
        except EOFError:
            raise ValueError, "unexpected end of encoded data"
        return self._parse(tag, length)

    def _parse(self, tag, length):
        _class = self.id & CLASS_MASK
        if _class == UNIVERSAL:
            try:
                method = self.__dispatch[tag]
            except KeyError:
                self.val = self.parseUnknown()
            else:
                self.val = method(self)
        elif _class == CONTEXTUAL:
            # class is context-specific
            self.val = self.parseContextSpecific()
        else:
            raise ValueError, \
                  "invalid or unsupported tag: %s (id %s)" % (self.tag,
                                                              _class)
        return self.val

    def parseBoolean(self):
        b = self.ord(self.getBody())
        return Boolean(b)

    def parseContextSpecific(self):
        if self.length == 0 and not self.indefinite:
            # a zero-length object?
            return None
        buf = self.getBody()
        enc = self.id & ENCODING_MASK
        if enc == CONSTRUCTED:
            return Constructed(enc, self.tag, self.length, buf)
        # If the encoded object is a CHOICE, then the encoding carries
        # *no* information about the type of the encoded value.  The
        # best we can do as create a Choice object that can be told
        # what the right value is.  Fuck.
        return Contextual(self.tag, self.length, buf)

    def parseUnknown(self):
        return self.getBody()

    def parseInteger(self):
        buf = self.getBody()
        if len(buf) == 0:
           raise EOFError
        return getInteger(buf)

    def parseZero(self):
        # XXX why is this zero? what does it all mean?
        if self.id & 0x80:
            # this hack retrieves the version number from x509
            return self.length

    def parseSequence(self):
        seq = Sequence()
        base = self.io.tell()
        body = self.getBody()
        assert type(body)==types.StringType,'***bah!'
        newIo = StringIO(body)
        try:
            while 1:
                obj = ASN1Parser(newIo).parse()
                seq.append(obj)
        except (EOFError, ValueError):
            pass
        return seq

    def parseGeneralizedTime(self):
        return GeneralizedTime(self.getBody())

    def parseUTCTime(self):
        return UTCTime(self.getBody())

    def parseBitString(self):
        unused = self.ord(self.io.read(1))
        return BitString(self.io.read(self.length - 1), unused)

    def parsePrintableString(self):
        return PrintableString(self.getBody())

    def parseOctetString(self):
        return OctetString(self.getBody())

    def parseT61String(self):
        return T61String(self.getBody())

    def parseVisibleString(self):
        return VisibleString(self.getBody())

    def parseUniversalString(self):
        return UniversalString(self.getBody())

    def parseUTF8String(self):
        return UTF8String(self.getBody())

    def parseBMPString(self):
        return BMPString(self.getBody())

    def parseIA5String(self):
        return IA5String(self.getBody())

    def parseSet(self):
        return Set(parse(self.getBody()))

    def parseObjectIdentifier(self):
        buf = self.getBody()
        try:
            o1 = self.ord(buf[0])
        except IndexError:
            raise EOFError
        x = o1 / 40
        y = o1 % 40
        if x > 2:
            y = y + (x - 2) * 40
            x = 2
        oid = [x, y]

        num = None
        for octet in map(self.ord, buf[1:]):
            if octet & 0x80:
                if num:
                    num = (num << 7L) | (octet & 0x7F)
                else:
                    num = long(octet & 0x7f)
            else:
                if num:
                    final = (num << 7L) | octet
                    # Is there a better way to do this?
                    # Should I just make it long all the time?
                    try:
                        oid.append(int(final))
                    except OverflowError:
                        oid.append(final)
                    num = None
                else:
                    oid.append(octet)
        return OID(oid)

    def parseNull(self):
        self.getBody()
        return None

    __dispatch = {SEQUENCE: parseSequence,
                  INTEGER: parseInteger,
                  SET: parseSet,
                  GENERALIZEDTIME: parseGeneralizedTime,
                  UTCTIME: parseUTCTime,
                  BIT_STRING: parseBitString,
                  OCTET_STRING: parseOctetString,
                  PRINTABLE_STRING: parsePrintableString,
                  VISIBLESTRING: parseVisibleString,
                  UNIVERSALSTRING: parseUniversalString,
                  BMPSTRING: parseBMPString,
                  UTF8STRING: parseUTF8String,
                  T61STRING: parseT61String,
                  IA5STRING: parseIA5String,
                  SET: parseSet,
                  OBJECT_IDENTIFIER: parseObjectIdentifier,
                  NULL: parseNull,
                  BOOLEAN: parseBoolean,
                  0: parseZero,
                  }

def getInteger(buf):
    bytes = map(ord, buf)
    if bytes[0] & 0x80:
        sign = -1
    else:
        sign = 1
    value = long(bytes[0] & 0x7F)
    for byte in bytes[1:]:
        value = (value << 8) | byte
    if sign == 1:
        return value
    else:
        return -value

def encode(obj):
    t = type(obj)
    if t == types.StringType:
        raise ValueError, "can't encode string: %s" % repr(obj)
    if hasattr(obj, 'encode'):
        f = StringIO()
        try:
            obj.encode(f)
        except TypeError:
            print repr(obj), repr(f)
            raise
        f.seek(0, 0)
        return f.read()
    if t in (types.IntType, types.LongType):
        return unparseInteger(obj)
    elif obj is None:
        return unparseNull()
    raise ValueError, "don't know how to encode: %s" % repr(obj)

def unparseContextual(tag, enc, constructed=1):
    return chr((constructed and 0x40) | 0x80 | tag) \
           + unparseLength(len(enc)) + enc

def unparseSequence(encObjs, constructed=1):
    buf = ''.join(encObjs)
    return chr(constructed and 0x20 | SEQUENCE or SEQUENCE) \
           + unparseLength(len(buf)) + buf

def unparseNull():
    return '\005\000'

def unparseSet(encObjs, constructed=1):
    # XXX actually, you need to sort the elements in the set before encoding
    buf = ''.join(encObjs)
    return chr(constructed and 0x20 |SET or SET) \
           + unparseLength(len(buf)) + buf

def unparseInteger(num):
    if num < 0:
        sign = -1
        num = -num
    else:
        sign = 1
    if num == 0:
        bytes = [0]
    else:
        bytes = []
        div = num
        rem = 0
        while div:
            try:
                div, rem = divmod(div, 256)
            except TypeError:
                raise
            bytes.append(int(rem))
        last = bytes[-1]
        if last & 0x80:
            bytes.append(0)
    if sign == -1:
        bytes[-1] = bytes[-1] | 0x80
    bytes.reverse()
    return chr(INTEGER) + unparseLength(len(bytes)) \
           + ''.join(map(chr, bytes))

def unparseLength(length):
    if length <= 127:
        return chr(length)
    bytes = []
    div = length
    while div:
        div, rem = divmod(div, 256)
        bytes.append(rem)
    bytes.reverse()
    return chr(0x80|len(bytes)) + ''.join(map(chr, bytes))

def convertOctetsToInt(buf):
    # XXX this really is a kludge
    l = len(buf)
    if l <= 4:
        return struct.unpack(">l", chr(0) * (4 - l) + buf)[0]
    else:
        val = 0L
        for byte in map(ord, buf):
            val = (val << 8) | byte
        return val

def parseCfg(io):
    """Parse dumpasn1 Object Identifier configuration file

    Returns a dictionary mapping OID objects to human-readable
    descriptions.

    The configuration file is available at the following URL:
    https://www.cs.auckland.ac.nz/~pgut001/dumpasn1.cfg
    (Last verified Apr 10, 2000.)
    """
    oids = {}
    oid = None
    line_counter = 0
    # Read first line
    line = io.readline()
    while line:
        line_counter += 1
        line = line.strip()
        if line and line[0]!='#':
            # Parse the line
            try:
                name,val = line.split('=',1)
                name,val = name.strip(),val.strip()
            except ValueError:
                name = line
                val = None

            if name == 'OID':
                if oid:
                    oids[oid] = d
                oid = OID(tuple(map(int,val.split(' '))))
                d = {}
            else:
                d[name] = val
        # Read next line
        line = io.readline()
    if oid:
        oids[oid] = dict
    return oids

def parse(buf):
    assert type(buf)==types.StringType,'***bah!'
    return ASN1Parser(StringIO(buf)).parse()


# Constants added by Michael Stroeder <michael@stroeder.com>
# without knowing exactly about it...
class UniversalString(String):
    """
    UniversalString ::= [UNIVERSAL 28] IMPLICIT OCTET STRING
            -- UniversalString is defined in ASN.1:1993
    """
    tag = UNIVERSALSTRING

class BMPString(String):
    """
    BMPString ::= [UNIVERSAL 30] IMPLICIT OCTET STRING
          -- BMPString is the subtype of UniversalString and models
           -- the Basic Multilingual Plane of ISO/IEC/ITU 10646-1
    """
    tag = BMPSTRING

class UTF8String(String):
    """
    UTF8String ::= [UNIVERSAL 12] IMPLICIT OCTET STRING
    """
    tag = UTF8STRING

class VisibleString(String):
    """
    VisibleString
    """
    tag = VISIBLESTRING
