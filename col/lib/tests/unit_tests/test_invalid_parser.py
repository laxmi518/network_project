
from nose.tools import raises
from libcol.parsers import GetParser, InvalidParserException


@raises(InvalidParserException)
def test_invalid_parser():
    GetParser('InvalidParser')
