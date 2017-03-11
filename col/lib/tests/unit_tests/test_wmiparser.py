
import os
from nose.tools import eq_
from libcol.parsers import GetParser

wp = GetParser('WmiParser')

def test_parse_wmi_log_query():
    log_text = ['CLASS: Win32_NTLogEvent',
        'Category|CategoryString|ComputerName|Data|EventCode|EventIdentifier|\
        EventType|InsertionStrings|Logfile|Message|RecordNumber|SourceName|TimeGenerated|\
        TimeWritten|Type|User',
        '0|(null)|COMPUTER_1|(0,0,0,0,3,0,78,0,0,0,0,0,67,31,0,192,0,0,0,0,0,0,0,0,6,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)|\
        8003|3221233475|1|(\\Device\\LanmanDatagramReceiver,DELL-PC,NetBT_Tcpip_{D4F4CE72-D5E3-4855-B)|\
        System|The master browser has received a server announcement from the computer DELL-PC\r',\
         'that believes that it is the master browser for the domain on transport NetBT_Tcpip_{D4F4CE72-D5E3-4855-B.\r',\
          'The master browser is stopping or an election is being forced.\r', '|2|MRxSmb|20110523145906.000000+345|\
          20110523145906.000000+345|error|(null)', '0|(null)|COMPUTER_1|NULL|7001|3221232473|1|\
          (ClipBook,Network DDE,The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.\r', ')|\
          System|The ClipBook service depends on the Network DDE service which failed to start because of the following error: \r',\
           'The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.\r', '\r',\
            '|1|Service Control Manager|20110523141225.000000+345|20110523141225.000000+345|error|(null)']

    wp.write(log_text)
    expected = {'_type_str': 'msg',
                '_type_num': 'record_number log_ts severity facility',
                'msg': '<13>May 23 14:12:25 2011 COMPUTER_1 MSWinEventLog\tService Control Manager\t1\tMon May 23 14:12:25 2011\t7001\tService Control Manager\t(null)\tN/A\terror\tCOMPUTER_1\tNone\t\tThe ClipBook service depends on the Network DDE service which failed to start because of the following error: \rThe service cannot be started, either because it is disabled or because it has no enabled devices associated with it.',
                '_normalized_fields': {'severity': 5, 'facility': 1, 'record_number': 1, 'log_ts': 1306159945}
                }
    result = wp.__iter__().next()

    eq_(result, expected)


def test_parse_wmi_date_query():
    date_text = ['CLASS: Win32_LocalTime',
                 'Day|DayOfWeek|Hour|Milliseconds|Minute|Month|Quarter|Second|WeekInMonth|Year',
                 '23|1|16|0|12|5|2|50|4|2011',
                 '']
    date_time = wp.parse_wmi_date_query(date_text)
    eq_(date_time, date_time)


def test_parse_wmi_timezone_query():
    timezone_text = ['CLASS: Win32_TimeZone', 'Bias|StandardName', '345|Nepal Standard Time', '']
    time_zone = wp.parse_wmi_timezone_query(timezone_text)
    eq_(time_zone, '345')
