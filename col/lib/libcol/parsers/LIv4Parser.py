
import re
import time
import logging

from pylib import msgfilling, timestamp
from pylib.collections.ordereddict import OrderedDict
from libcol.parsers.LineParser import LineParser


col_ts_cache = OrderedDict()
def _get_col_ts(year, month, day, hour, minute, second):
    key = (year, month, day, hour, minute, second)
    ts = col_ts_cache.get(key)
    if ts:
        return ts

    struct = time.struct_time(map(int, (year, month, day, hour, minute, second,
                                        0, 0, 0)))
    ts = int(time.mktime(struct))

    if len(col_ts_cache) == 5:
        col_ts_cache.popitem(last=False)
    col_ts_cache[key] = ts

    return ts


class LIv4Parser(LineParser):
    def __init__(self, col_type, collected_at, charset=None):
        self.col_type = col_type
        self.collected_at = collected_at
        super(LIv4Parser, self).__init__(col_type, charset)

        self.v4_logstorage_re = re.compile(r"""
            (\d)\                                                       # <SEVERITY>
            (\d{0,2})\                                                  # <FACILITY>
            ((\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})[+]00:00)\  # <SYSLOGTIME>
            ([a-zA-Z]{3}\ {1,2}\d{1,2}\ \d\d:\d\d:\d\d)\                # <CLIENTTIME>
            ((?:\d{1,3}\.){3}\d{1,3})\                                  # <SRCIP>
            (.*)                                                        # <MESSAGE>
            """, re.VERBOSE)

    def next(self):
        event = super(LIv4Parser, self).next()
        found = self.v4_logstorage_re.match(event['msg'])

        if not found:
            logging.warning('LIv4Parser; received message with incorrect format;'
                            ' sid=%s; msg=%r', self.sid, event['msg'])
            return event

        severity = found.group(1)
        facility = found.group(2)

        #syslog_time = found.group(3)
        col_year = found.group(4)
        col_month = found.group(5)
        col_day = found.group(6)
        col_hour = found.group(7)
        col_minute = found.group(8)
        col_second = found.group(9)

        client_time = found.group(10)
        src_ip = found.group(11)
        msg = found.group(12)

        priority = int(facility) * 8 + int(severity)
        col_ts = _get_col_ts(col_year, col_month, col_day,
                                  col_hour, col_minute, col_second)
        log_ts = timestamp.fromsyslogtime(client_time, int(col_year))

        # for sorting only, col_ts will be reparsed from mid by indexsearcher
        event["col_ts"] = col_ts
        event["mid"] = "%s|%s|%s|%d|%%d" % (self.collected_at, self.col_type, src_ip, col_ts)
        event["msg"] = "<%s> %s %s" % (priority, client_time, msg)

        event["_normalized_fields"] = dict(severity=severity, facility=facility, log_ts=log_ts, log_type="syslog")

        # event["severity"] = severity
        # event["facility"] = facility
        # event["log_ts"] = log_ts
        # event["log_type"] = "syslog"
        
        event["col_type"] = self.col_type
        event["device_ip"] = src_ip
        
        msgfilling.add_types(event, "_type_num", "severity facility log_ts col_ts")
        msgfilling.add_types(event, "_type_str", "log_type col_type device_ip")
        msgfilling.add_types(event, "_type_ip", "device_ip")

        return event


if __name__ == '__main__':
    pass
