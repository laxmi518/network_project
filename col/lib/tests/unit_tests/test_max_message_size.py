
from nose.tools import eq_
from libcol.parsers import LineParser


def test_correct_size():
    lp = LineParser()
    lp.write('a'*9999)
    eq_(lp.buffer, 'a'*9999)

def test_exceeded_size():
    lp = LineParser()
    lp.write('a'*10000)
    eq_(lp.buffer, "")
