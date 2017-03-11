
import datetime
import re
import time
import calendar
from pylib import msgfilling
import LineParser

wmi_time_re = re.compile(r'^(\d+)[^+-]*([+-])?(\d+)?$')

class WmiParser(object):

    def __init__(self, sid=None, charset=None):
        self.sid = sid
        self.charset = charset
        self.buffer_list = []
        self.last_time = 0
        self.facility = 1
        self.severity = 5

    def set_facility_severity(self, facility, severity):
        self.facility = facility
        self.severity = severity

    def write(self, buffer):
        buffer = [LineParser.encode(each, self.charset, self.sid) for each in buffer]
        self.buffer_list.append(buffer)

    def __iter__(self):
        try:
            buffer = self.buffer_list.pop(0)
        except IndexError:
            raise StopIteration
        events = self.parse_wmi_log_query(buffer)
        events = sorted(events, key=lambda k:(k['_normalized_fields']['log_ts'], k['_normalized_fields']['record_number']))
        for event in events:
            yield event
        raise StopIteration

    def parse_wmi_log_query(self, wmi_data):
        msgs = wmi_data[2:]
        keys = wmi_data[1].split('|')
        events = []
        appended_msgs = []
        prev_msg = ''

        for each_msg in msgs:
            start_msg = each_msg.split('|', 1)
            if start_msg[0].isdigit():
                if prev_msg != '':
                    appended_msgs.append(prev_msg)
                prev_msg = each_msg
            else:
                prev_msg = prev_msg + each_msg

        appended_msgs.append(prev_msg)

        priority = self.facility * self.severity + 8
        for index, each_msg in enumerate(appended_msgs):
            event = {"_normalized_fields": {}}

            splitted_msg = []
            split1 = each_msg.split('|', 9)
            splitted_msg.extend(split1[0:9])
            split2 = split1[9].rsplit('|', 6)
            splitted_msg.extend(split2)

            for index, each_key in enumerate(keys):
                each_key = each_key.strip()
                if each_key in ('Message', 'TimeGenerated','RecordNumber'):
                    if each_key == 'TimeGenerated':
                        wmi_time = splitted_msg[index].strip()
                        if not self.last_time or (wmi_time[-3:]!=self.last_time[-3:] or self.last_time < wmi_time):
                            self.last_time = wmi_time
                        event["_normalized_fields"]["log_ts"] = parse_wmi_time(wmi_time)
                        #event['log_ts'] = parse_wmi_time(wmi_time)
                        msgfilling.add_types(event, '_type_num', 'log_ts')
                    elif each_key == 'Message':
                        event['msg'] = parse_wmi_message(splitted_msg, index, priority)
                        msgfilling.add_types(event, '_type_str', 'msg')
                    elif each_key == 'RecordNumber':
                        event["_normalized_fields"]["record_number"] = int(splitted_msg[index].strip())
                        #event['record_number'] = int(splitted_msg[index].strip())
                        msgfilling.add_types(event, '_type_num', 'record_number')
            #event['severity'] = self.severity
            #event['facility'] = self.facility
            event["_normalized_fields"]["severity"] = self.severity
            event["_normalized_fields"]["facility"] = self.facility
            msgfilling.add_types(event, '_type_num', 'severity facility')
            events.append(event)

        return events

    def get_last_time(self):
        return self.last_time

    def parse_wmi_date_query(self, wmi_data):
        split_time = map(int, wmi_data[2].split('|'))
        return datetime.datetime(split_time[9], split_time[5], split_time[0],
                                split_time[2], split_time[4], split_time[7], split_time[3])

    def parse_wmi_timezone_query(self, wmi_data):
        return wmi_data[2].split('|')[0]

def parse_wmi_message(message, index, priority):
    hostname = message[2]
    eventlog = 'MSWinEventLog'
    sourcename = message[11]
    event_counter = message[10]

    date_time = parse_wmi_time(message[12].strip())
    date_time = datetime.datetime.utcfromtimestamp(date_time)
    date_time_full = date_time.strftime('%a %b %d %H:%M:%S %Y')
    date_time_no_day = date_time.strftime('%b %d %H:%M:%S %Y')

    event_id = message[4].strip()
    username = message[15]
    sid_type = 'N/A'
    event_log_type = message[14]
    computer_name = message[2]

    category_string = message[1].strip()
    if category_string == '(null)':
        category_string = 'None'

    expanded_string = message[index].strip()

    return "<%s>%s %s %s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\t%s" % (priority, date_time_no_day.strip(),
                hostname, eventlog, sourcename, event_counter, date_time_full, event_id, sourcename,
                username, sid_type, event_log_type, computer_name, category_string, expanded_string)

def parse_wmi_time(wmi_time):
    log_time, plus_minus, offset = wmi_time_re.search(wmi_time).groups()
    struct = time.strptime(log_time, '%Y%m%d%H%M%S')

    # if log_time were gmt:
    log_ts = int(calendar.timegm(struct))

    return log_ts

    # # since log_time was not in gmt, we now configure log_ts with the offset
    # if plus_minus:
    #     offset = int(offset) * 60
    #     if plus_minus == '+':
    #         log_ts = log_ts - offset
    #     elif plus_minus == '-':
    #         log_ts = log_ts + offset

    # return log_ts


if __name__ == '__main__':
    wp = WmiParser()

    log_text = ['CLASS: Win32_NTLogEvent', \
        'Category|CategoryString|ComputerName|Data|EventCode|EventIdentifier|\
        EventType|InsertionStrings|Logfile|Message|RecordNumber|SourceName|TimeGenerated|\
        TimeWritten|Type|User', '0|(null)|COMPUTER_1|\
        (0,0,0,0,3,0,78,0,0,0,0,0,67,31,0,192,0,0,0,0,0,0,0,0,6,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)|\
        8003|3221233475|1|(\\Device\\LanmanDatagramReceiver,DELL-PC,NetBT_Tcpip_{D4F4CE72-D5E3-4855-B)|\
        System|The master browser has received a server announcement from the computer DELL-PC\r',\
         'that believes that it is the master browser for the domain on transport NetBT_Tcpip_{D4F4CE72-D5E3-4855-B.\r',\
          'The master browser is stopping or an election is being forced.\r', '|2|MRxSmb|20110523145906.000000+345|\
          20110523145906.000000+345|error|(null)', '0|(null)|COMPUTER_1|NULL|7001|3221232473|1|\
          (ClipBook,Network DDE,The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.\r', ')|\
          System|The ClipBook service depends on the Network DDE service which failed to start because of the following error: \r',\
           'The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.\r', '\r',\
            '|1|Service Control Manager|20110523141225.000000+345|20110523141225.000000+345|error|(null)']

    date_text = ['CLASS: Win32_LocalTime', 'Day|DayOfWeek|Hour|Milliseconds|Minute|Month|Quarter|\
        Second|WeekInMonth|Year', '23|1|16|0|12|5|2|50|4|2011', '']

    timezone_text = ['CLASS: Win32_TimeZone', 'Bias|StandardName', '345|Nepal Standard Time', '']

    wp.write(log_text)
    for msg in wp:
        print msg
