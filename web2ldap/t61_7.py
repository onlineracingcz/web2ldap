# -*- coding: utf-8 -*-
"""
Python Character Mapping Codec for T.61 7-Bit

Written by Michael Stroeder <michael@stroeder.com>.
"""

from __future__ import absolute_import

import codecs

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

def getregentry():
  try:
    return codecs.CodecInfo(
        name='t61-7',
        encode=Codec().encode,
        decode=Codec().decode,
        streamreader=StreamReader,
        streamwriter=StreamWriter,
    )
  except AttributeError:
    # Fallback for older Python versions
    return (Codec().encode,Codec().decode,StreamReader,StreamWriter)

def getaliases():
    return ('t61-7','t61_7','t.61_7','t61_7bit','t.61_7bit','t61-7bit')


def codec_search_function(encoding):
    if encoding in getaliases():
        return getregentry()
    return None


codecs.register(codec_search_function)


### Decoding Map

decoding_map = {
        0x0000: 0x0000, # NULL (NUL)
        0x0001: 0x0001, # START OF HEADING (SOH)
        0x0002: 0x0002, # START OF TEXT (STX)
        0x0003: 0x0003, # END OF TEXT (ETX)
        0x0004: 0x0004, # END OF TRANSMISSION (EOT)
        0x0005: 0x0005, # ENQUIRY (ENQ)
        0x0006: 0x0006, # ACKNOWLEDGE (ACK)
        0x0007: 0x0007, # BELL (BEL)
        0x0008: 0x0008, # BACKSPACE (BS)
        0x0009: 0x0009, # CHARACTER TABULATION (HT)
        0x000a: 0x000a, # LINE FEED (LF)
        0x000b: 0x000b, # LINE TABULATION (VT)
        0x000c: 0x000c, # FORM FEED (FF)
        0x000d: 0x000d, # CARRIAGE RETURN (CR)
        0x000e: 0x000e, # SHIFT OUT (SO)
        0x000f: 0x000f, # SHIFT IN (SI)
        0x0010: 0x0010, # DATALINK ESCAPE (DLE)
        0x0011: 0x0011, # DEVICE CONTROL ONE (DC1)
        0x0012: 0x0012, # DEVICE CONTROL TWO (DC2)
        0x0013: 0x0013, # DEVICE CONTROL THREE (DC3)
        0x0014: 0x0014, # DEVICE CONTROL FOUR (DC4)
        0x0015: 0x0015, # NEGATIVE ACKNOWLEDGE (NAK)
        0x0016: 0x0016, # SYNCRONOUS IDLE (SYN)
        0x0017: 0x0017, # END OF TRANSMISSION BLOCK (ETB)
        0x0018: 0x0018, # CANCEL (CAN)
        0x0019: 0x0019, # END OF MEDIUM (EM)
        0x001a: 0x001a, # SUBSTITUTE (SUB)
        0x001b: 0x001b, # ESCAPE (ESC)
        0x001c: 0x001c, # FILE SEPARATOR (IS4)
        0x001d: 0x001d, # GROUP SEPARATOR (IS3)
        0x001e: 0x001e, # RECORD SEPARATOR (IS2)
        0x001f: 0x001f, # UNIT SEPARATOR (IS1)
        0x0020: 0x0020, # SPACE
        0x0021: 0x0021, # EXCLAMATION MARK
        0x0022: 0x0022, # QUOTATION MARK
        0x0023: 0x0023, # NUMBER SIGN
        0x0024: 0x00a4, # CURRENCY SIGN
        0x0025: 0x0025, # PERCENT SIGN
        0x0026: 0x0026, # AMPERSAND
        0x0027: 0x0027, # APOSTROPHE
        0x0028: 0x0028, # LEFT PARENTHESIS
        0x0029: 0x0029, # RIGHT PARENTHESIS
        0x002a: 0x002a, # ASTERISK
        0x002b: 0x002b, # PLUS SIGN
        0x002c: 0x002c, # COMMA
        0x002d: 0x002d, # HYPHEN-MINUS
        0x002e: 0x002e, # FULL STOP
        0x002f: 0x005c, # REVERSE SOLIDUS
        0x0030: 0x0030, # DIGIT ZERO
        0x0031: 0x0031, # DIGIT ONE
        0x0032: 0x0032, # DIGIT TWO
        0x0033: 0x0033, # DIGIT THREE
        0x0034: 0x0034, # DIGIT FOUR
        0x0035: 0x0035, # DIGIT FIVE
        0x0036: 0x0036, # DIGIT SIX
        0x0037: 0x0037, # DIGIT SEVEN
        0x0038: 0x0038, # DIGIT EIGHT
        0x0039: 0x0039, # DIGIT NINE
        0x003a: 0x003a, # COLON
        0x003b: 0x003b, # SEMICOLON
        0x003c: 0x003c, # LESS-THAN SIGN
        0x003d: 0x003d, # EQUALS SIGN
        0x003e: 0x232a, # RIGHT-POINTING ANGLE BRACKET
        0x003f: 0x003f, # QUESTION MARK
        0x0040: 0x0040, # COMMERCIAL AT
        0x0041: 0x0041, # LATIN CAPITAL LETTER A
        0x0042: 0x0042, # LATIN CAPITAL LETTER B
        0x0043: 0x0043, # LATIN CAPITAL LETTER C
        0x0044: 0x0044, # LATIN CAPITAL LETTER D
        0x0045: 0x0045, # LATIN CAPITAL LETTER E
        0x0046: 0x0046, # LATIN CAPITAL LETTER F
        0x0047: 0x0047, # LATIN CAPITAL LETTER G
        0x0048: 0x0048, # LATIN CAPITAL LETTER H
        0x0049: 0x0049, # LATIN CAPITAL LETTER I
        0x004a: 0x004a, # LATIN CAPITAL LETTER J
        0x004b: 0x004b, # LATIN CAPITAL LETTER K
        0x004c: 0x004c, # LATIN CAPITAL LETTER L
        0x004d: 0x004d, # LATIN CAPITAL LETTER M
        0x004e: 0x004e, # LATIN CAPITAL LETTER N
        0x004f: 0x004f, # LATIN CAPITAL LETTER O
        0x0050: 0x0050, # LATIN CAPITAL LETTER P
        0x0051: 0x0051, # LATIN CAPITAL LETTER Q
        0x0052: 0x0052, # LATIN CAPITAL LETTER R
        0x0053: 0x0053, # LATIN CAPITAL LETTER S
        0x0054: 0x0054, # LATIN CAPITAL LETTER T
        0x0055: 0x0055, # LATIN CAPITAL LETTER U
        0x0056: 0x0056, # LATIN CAPITAL LETTER V
        0x0057: 0x0057, # LATIN CAPITAL LETTER W
        0x0058: 0x0058, # LATIN CAPITAL LETTER X
        0x0059: 0x0059, # LATIN CAPITAL LETTER Y
        0x005a: 0x005a, # LATIN CAPITAL LETTER Z
        0x005b: 0x005b, # LEFT SQUARE BRACKET
        0x005f: 0x005f, # LOW LINE
        0x0061: 0x0061, # LATIN SMALL LETTER A
        0x0062: 0x0062, # LATIN SMALL LETTER B
        0x0063: 0x0063, # LATIN SMALL LETTER C
        0x0064: 0x0064, # LATIN SMALL LETTER D
        0x0065: 0x0065, # LATIN SMALL LETTER E
        0x0066: 0x0066, # LATIN SMALL LETTER F
        0x0067: 0x0067, # LATIN SMALL LETTER G
        0x0068: 0x0068, # LATIN SMALL LETTER H
        0x0069: 0x0069, # LATIN SMALL LETTER I
        0x006a: 0x006a, # LATIN SMALL LETTER J
        0x006b: 0x006b, # LATIN SMALL LETTER K
        0x006c: 0x006c, # LATIN SMALL LETTER L
        0x006d: 0x006d, # LATIN SMALL LETTER M
        0x006e: 0x006e, # LATIN SMALL LETTER N
        0x006f: 0x006f, # LATIN SMALL LETTER O
        0x0070: 0x0070, # LATIN SMALL LETTER P
        0x0071: 0x0071, # LATIN SMALL LETTER Q
        0x0072: 0x0072, # LATIN SMALL LETTER R
        0x0073: 0x0073, # LATIN SMALL LETTER S
        0x0074: 0x0074, # LATIN SMALL LETTER T
        0x0075: 0x0075, # LATIN SMALL LETTER U
        0x0076: 0x0076, # LATIN SMALL LETTER V
        0x0077: 0x0077, # LATIN SMALL LETTER W
        0x0078: 0x0078, # LATIN SMALL LETTER X
        0x0079: 0x0079, # LATIN SMALL LETTER Y
        0x007a: 0x007a, # LATIN SMALL LETTER Z
        0x007c: 0x007c, # VERTICAL LINE
        0x007f: 0x007f, # DELETE (DEL)
}

### Encoding Map

encoding_map = {}
for k,v in decoding_map.items():
    encoding_map[v] = k

codecs.register(getregentry)

