# -*- coding: utf-8

from nose.tools import eq_
from libcol.parsers import GetParser

regex_pattern = "(?P<axxx>a[^a]{4})((?P<same>[a-z]{1})(?P=same){2})"

def test_RegexParser():

    rp = GetParser('RegexParser', regex_pattern=regex_pattern)
    rp.write('boxabbbbbbbbbaccccccccccadddddddddddarrrrr')
    rp.write('nut\ngrapes')


    count = 0
    event = []
    for events in rp:
        #if events != None:
        event.append(events)
        count = count + 1
    len_event = len(event)
    assert count == len_event

    for i, e in enumerate(event):
        if i == 0:
            expected = dict(
                _normalized_fields=dict(msg_type = 'unmatched_data'),
                msg='box',
                _type_str='msg msg_type'
                )
            eq_(e, expected)

        if i == 1:
            expected = dict(
                _normalized_fields=dict(same = 'b', axxx = 'abbbb'),
                msg='abbbbbbb',
                _type_str='msg same axxx',
            )


