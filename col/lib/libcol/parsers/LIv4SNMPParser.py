
import re
import time
import logging

from pylib import msgfilling
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


class LIv4SNMPParser(LineParser):
    def __init__(self, col_type, collected_at, charset=None):
        self.col_type = col_type
        self.collected_at = collected_at
        super(LIv4SNMPParser, self).__init__(col_type, charset)

        self.v4_logstorage_re = re.compile(r"""
            \S+\                                                        # <VERSION>
            ((\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?[+]00:00)\  # <SERVERTIME>
            ((?:\d{1,3}\.){3}\d{1,3})\                                  # <SRCIP>
            .*                                                          # <MESSAGE>
            """, re.VERBOSE)

    def next(self):
        event = super(LIv4SNMPParser, self).next()
        found = self.v4_logstorage_re.match(event['msg'])

        if not found:
            logging.warning('LIv4SNMPParser; received message with incorrect format;'
                            ' sid=%s; msg=%r', self.sid, event['msg'])
            return event

        #server_time = found.group(1)
        col_year = found.group(2)
        col_month = found.group(3)
        col_day = found.group(4)
        col_hour = found.group(5)
        col_minute = found.group(6)
        col_second = found.group(7)

        src_ip = found.group(8)

        col_ts = _get_col_ts(col_year, col_month, col_day,
                                  col_hour, col_minute, col_second)

        # for sorting only, col_ts will be reparsed from mid by indexsearcher
        event["col_ts"] = col_ts
        event["mid"] = "%s|%s|%s|%d|%%d" % (self.collected_at, self.col_type, src_ip, col_ts)

        event["_normalized_fields"] = dict(log_type="snmp")
        #event["log_type"] = "snmp"
        
        event["col_type"] = self.col_type
        event["device_ip"] = src_ip
        
        msgfilling.add_types(event, "_type_num", "col_ts")
        msgfilling.add_types(event, "_type_str", "log_type col_type device_ip")
        msgfilling.add_types(event, "_type_ip", "device_ip")

        return event


if __name__ == '__main__':
    pass
