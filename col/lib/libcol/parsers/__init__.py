
from LineParser import LineParser
from SyslogParser import SyslogParser
from WmiParser import WmiParser
from StackTraceParser import StackTraceParser
from RegexParser import RegexParser
from SnareParser import SnareParser

import os
import glob

from pylib import homing

PARSERS_PATH = homing.home_join("installed/col/lib/libcol/parsers/")


def get_plug_parsers_list():
    """Returns the list of ConfigGen files
    """
    parsers = glob.glob(os.path.join(PARSERS_PATH, "*.py"))

    plug_parsers = []
    for parser in parsers:
        pg = os.path.basename(parser)
        if pg not in["__init__.py", "LineParser.py", "SyslogParser.py", "WmiParser.py", "StackTraceParser.py",
                     "RegexParser.py", "SnareParser.py", "LIv4Parser.py", "LIv4SNMPParser.py", "NewSyslogParser.py"]:
            plug_parsers.append(pg.strip(".py"))
    return plug_parsers


class InvalidParserException(Exception):
    def __init__(self, parser_name, sid):
        message = "Invalid parser '%s' configured for sid %s" % (parser_name, sid)
        super(InvalidParserException, self).__init__(message)


def GetParser(parser_name, sid=None, charset=None, regex_pattern=None, regexparser_name=None):
    if parser_name == "RegexParser" and regex_pattern is not None:
        return RegexParser(regex_pattern, regexparser_name, sid, charset)

    parsers = dict(LineParser=LineParser,
                   SyslogParser=SyslogParser,
                   WmiParser=WmiParser,
                   StackTraceParser=StackTraceParser,
                   SnareParser=SnareParser
                   )

    for pn in get_plug_parsers_list():
        '''
        The name of the File and the class for the parser should be same
        i.e. from NewParser import NewParser
        '''
        try:
            imported_parser = __import__(pn, globals(), locals(), [pn], -1)
            parser_dict = {pn: getattr(imported_parser, pn)}
            parsers.update(parser_dict)
        except Exception, e:
            import logging as log
            log.warn("Exception reading plugged parsers: %s" % str(e))

    try:
        return parsers[parser_name](sid, charset)
    except KeyError:
        raise InvalidParserException(parser_name, sid)
