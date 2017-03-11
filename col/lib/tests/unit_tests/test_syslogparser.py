
import time
import calendar
from nose.tools import eq_
from libcol.parsers import GetParser

import os
os.environ['TZ'] = 'UTC'
gmtime = time.gmtime()
this_year = gmtime.tm_year

def test_SyslogParser():
    sp = GetParser('SyslogParser')

    sp.write('<23> Jan 12 23:59:59 hello world\n<24> Jan 13 23:59:59 hello foobar\n')

    for i, event in enumerate(sp):
        if i == 0:
            expected = dict(
                msg='<23> Jan 12 23:59:59 hello world',
                _type_str='msg',
                _type_num='log_ts severity facility',
                _normalized_fields=dict(facility=2, severity=7)
            )
            expected['_normalized_fields']['log_ts'] = calendar.timegm(time.strptime("%d Jan 12 23:59:59" % this_year, "%Y %b %d %H:%M:%S"))
            eq_(event, expected)
        if i == 1:
            expected = dict(
                msg='<24> Jan 13 23:59:59 hello foobar',
                _type_str='msg',
                _type_num='log_ts severity facility',
                _normalized_fields=dict(facility=3, severity=0, log_ts=1294963199)
            )
            expected['_normalized_fields']['log_ts'] = calendar.timegm(time.strptime("%d Jan 13 23:59:59" % this_year, "%Y %b %d %H:%M:%S"))
            eq_(event, expected)
    eq_(i, 1)

def test_no_pri():
    sp = GetParser('SyslogParser')

    sp.write('Jan 12 23:59:59 hello world\n')

    for event in sp:
        expected = dict(
            msg='Jan 12 23:59:59 hello world',
            _type_str='msg',
            _type_num='log_ts',
            _normalized_fields=dict(log_ts=1294876799)
        )
        expected['_normalized_fields']['log_ts'] = calendar.timegm(time.strptime("%d Jan 12 23:59:59" % this_year, "%Y %b %d %H:%M:%S"))
        eq_(event, expected)

def test_no_pri_no_date():
    sp = GetParser('SyslogParser')

    sp.write('hello world\n')

    for event in sp:
        eq_(event, dict(
            msg='hello world',
            _type_str='msg',
            ))

def test_log_time_with_year():
    sp = GetParser('SyslogParser')

    sp.write('Aug 11 2011 12:58:28\n')

    for event in sp:
        eq_(event, dict(
            msg='Aug 11 2011 12:58:28',
            _type_str='msg',
            _type_num='log_ts',
            _normalized_fields=dict(log_ts=1313067508)
            ))
