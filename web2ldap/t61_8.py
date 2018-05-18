# -*- coding: utf-8 -*-
"""
Python Character Mapping Codec for T.61 8-Bit

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import codecs
import copy

from . import t61_7

### Codec APIs

class Codec(codecs.Codec):

    def encode(self,input,errors='strict'):
        return codecs.charmap_encode(input,errors,encoding_map)

    def decode(self,input,errors='strict'):
        return codecs.charmap_decode(input,errors,decoding_map)

class StreamWriter(Codec,codecs.StreamWriter):
    pass

class StreamReader(Codec,codecs.StreamReader):
    pass

### encodings module API

def getregentry(*args, **kwargs):
  try:
    return codecs.CodecInfo(
        name='t61-8',
        encode=Codec().encode,
        decode=Codec().decode,
        streamreader=StreamReader,
        streamwriter=StreamWriter,
    )
  except AttributeError:
    # Fallback for older Python versions
    return (Codec().encode,Codec().decode,StreamReader,StreamWriter)

def getaliases():
    return ('t61-8','t61_8','t.61_8','t61_8bit','t.61_8bit','t61-8bit')


def codec_search_function(encoding):
    if encoding in getaliases():
        return getregentry()
    return None


codecs.register(codec_search_function)


### Decoding Map

decoding_map = copy.copy(t61_7.decoding_map)

decoding_map.update({
        0x0080: 0x0080, # PADDING CHARACTER (PAD)
        0x0081: 0x0081, # HIGH OCTET PRESET (HOP)
        0x0082: 0x0082, # BREAK PERMITTED HERE (BPH)
        0x0083: 0x0083, # NO BREAK HERE (NBH)
        0x0084: 0x0084, # INDEX (IND)
        0x0085: 0x0085, # NEXT LINE (NEL)
        0x0086: 0x0086, # START OF SELECTED AREA (SSA)
        0x0087: 0x0087, # END OF SELECTED AREA (ESA)
        0x0088: 0x0088, # CHARACTER TABULATION SET (HTS)
        0x0089: 0x0089, # CHARACTER TABULATION WITH JUSTIFICATION (HTJ)
        0x008a: 0x008a, # LINE TABULATION SET (VTS)
        0x008b: 0x008b, # PARTIAL LINE FORWARD (PLD)
        0x008c: 0x008c, # PARTIAL LINE BACKWARD (PLU)
        0x008d: 0x008d, # REVERSE LINE FEED (RI)
        0x008e: 0x008e, # SINGLE-SHIFT TWO (SS2)
        0x008f: 0x008f, # SINGLE-SHIFT THREE (SS3)
        0x0090: 0x0090, # DEVICE CONTROL STRING (DCS)
        0x0091: 0x0091, # PRIVATE USE ONE (PU1)
        0x0092: 0x0092, # PRIVATE USE TWO (PU2)
        0x0093: 0x0093, # SET TRANSMIT STATE (STS)
        0x0094: 0x0094, # CANCEL CHARACTER (CCH)
        0x0095: 0x0095, # MESSAGE WAITING (MW)
        0x0096: 0x0096, # START OF GUARDED AREA (SPA)
        0x0097: 0x0097, # END OF GUARDED AREA (EPA)
        0x0098: 0x0098, # START OF STRING (SOS)
        0x0099: 0x0099, # SINGLE GRAPHIC CHARACTER INTRODUCER (SGCI)
        0x009a: 0x009a, # SINGLE CHARACTER INTRODUCER (SCI)
        0x009b: 0x009b, # CONTROL SEQUENCE INTRODUCER (CSI)
        0x009c: 0x009c, # STRING TERMINATOR (ST)
        0x009d: 0x009d, # OPERATING SYSTEM COMMAND (OSC)
        0x009e: 0x009e, # PRIVACY MESSAGE (PM)
        0x009f: 0x009f, # APPLICATION PROGRAM COMMAND (APC)
        0x00a0: 0x00a0, # NO-BREAK SPACE
        0x00a1: 0x00a1, # INVERTED EXCLAMATION MARK
        0x00a2: 0x00a2, # CENT SIGN
        0x00a3: 0x00a3, # POUND SIGN
        0x00a4: 0x0024, # DOLLAR SIGN
        0x00a5: 0x00a5, # YEN SIGN
        0x00a6: 0x0023, # NUMBER SIGN
        0x00a7: 0x00a7, # SECTION SIGN
        0x00a8: 0x00a4, # CURRENCY SIGN
        0x00ab: 0x00ab, # LEFT-POINTING DOUBLE ANGLE QUOTATION MARK
        0x00b0: 0x00b0, # DEGREE SIGN
        0x00b1: 0x00b1, # PLUS-MINUS SIGN
        0x00b2: 0x00b2, # SUPERSCRIPT TWO
        0x00b3: 0x00b3, # SUPERSCRIPT THREE
        0x00b4: 0x00d7, # MULTIPLICATION SIGN
        0x00b5: 0x00b5, # MICRO SIGN
        0x00b6: 0x00b6, # PILCROW SIGN
        0x00b7: 0x00b7, # MIDDLE DOT
        0x00b8: 0x00f7, # DIVISION SIGN
        0x00bc: 0x00bc, # VULGAR FRACTION ONE QUARTER
        0x00bd: 0x00bd, # VULGAR FRACTION ONE HALF
        0x00be: 0x00be, # VULGAR FRACTION THREE QUARTERS
        0x00bf: 0x00bf, # INVERTED QUESTION MARK
        0x00c1: 0xe006, # NON-SPACING GRAVE ACCENT (ISO-IR-103 193) (character part)
        0x00c2: 0xe007, # NON-SPACING ACUTE ACCENT (ISO-IR-103 194) (character part)
        0x00c4: 0xe009, # NON-SPACING TILDE (ISO-IR-103 196) (character part)
        0x00c5: 0xe00a, # NON-SPACING MACRON (ISO-IR-103 197) (character part)
        0x00c6: 0xe00b, # NON-SPACING BREVE (ISO-IR-103 198) (character part)
        0x00c7: 0xe00c, # NON-SPACING DOT ABOVE (ISO-IR-103 199) (character part)
        0x00c8: 0xe00d, # NON-SPACING DIAERESIS (ISO-IR-103 200) (character part)
        0x00ca: 0xe00e, # NON-SPACING RING ABOVE (ISO-IR-103 202) (character part)
        0x00cb: 0xe011, # NON-SPACING CEDILLA (ISO-IR-103 203) (character part)
        0x00cc: 0xe013, # NON-SPACING LOW LINE (ISO-IR-103 204) (character part)
        0x00cd: 0xe00f, # NON-SPACING DOUBLE ACCUTE (ISO-IR-103 204) (character part)
        0x00ce: 0xe012, # NON-SPACING OGONEK (ISO-IR-103 206) (character part)
        0x00cf: 0xe010, # NON-SPACING CARON (ISO-IR-103 206) (character part)
        0x00e0: 0x2126, # OHM SIGN
        0x00e1: 0x00c6, # LATIN CAPITAL LETTER AE
        0x00e2: 0x00d0, # LATIN CAPITAL LETTER ETH (Icelandic)
        0x00e3: 0x00aa, # FEMININE ORDINAL INDICATOR
        0x00e6: 0x0132, # LATIN CAPITAL LIGATURE IJ
        0x00e7: 0x013f, # LATIN CAPITAL LETTER L WITH MIDDLE DOT
        0x00ea: 0x0152, # LATIN CAPITAL LIGATURE OE
        0x00eb: 0x00ba, # MASCULINE ORDINAL INDICATOR
        0x00ec: 0x00de, # LATIN CAPITAL LETTER THORN (Icelandic)
        0x00ee: 0x014a, # LATIN CAPITAL LETTER ENG (Lappish)
        0x00ef: 0x0149, # LATIN SMALL LETTER N PRECEDED BY APOSTROPHE
        0x00f0: 0x0138, # LATIN SMALL LETTER KRA (Greenlandic)
        0x00f1: 0x00e6, # LATIN SMALL LETTER AE
        0x00f3: 0x00f0, # LATIN SMALL LETTER ETH (Icelandic)
        0x00f5: 0x0131, # LATIN SMALL LETTER I DOTLESS
        0x00f6: 0x0133, # LATIN SMALL LIGATURE IJ
        0x00f7: 0x0140, # LATIN SMALL LETTER L WITH MIDDLE DOT
        0x00fa: 0x0153, # LATIN SMALL LIGATURE OE
        0x00fb: 0x00df, # LATIN SMALL LETTER SHARP S (German)
        0x00fc: 0x00fe, # LATIN SMALL LETTER THORN (Icelandic)
        0x00fe: 0x014b, # LATIN SMALL LETTER ENG (Lappish)
})

### Encoding Map

encoding_map = {}
for k,v in decoding_map.items():
    encoding_map[v] = k

codecs.register(getregentry)

