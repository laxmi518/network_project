# -*- coding: utf-8
import re
import copy
import logging

from pylib import msgfilling
import LineParser

UNMATCHED_DATA = "unmatched_data"

class RegexParser(object):
    def __init__(self, regex_pattern, name=None, sid=None, charset=None):
        self.regex = re.compile(regex_pattern, re.M|re.DOTALL)
        self.name = name
        self.sid = sid
        self.charset = charset
        self.buffer = ''
        self.buffer_limit = 10000

    def write(self, buffer, old_parser=False):
        buffer = LineParser.encode(buffer, self.charset, self.sid)
        self.buffer += buffer

        if len(self.buffer) >= self.buffer_limit:
            logging.warn("Log message too long; sent by sid=%s; msg=%r",
                         self.sid, self.buffer[:100])
            self.buffer = ""

    def __iter__(self):
        while self.buffer:
            match = self.regex.search(self.buffer)
            if not match:
                return
            log = match.group()
            event = match.groupdict()
            event['msg'] = log
            start_index = self.buffer.find(log)

            if start_index > 0:
                redundant_data = self.buffer[:start_index]
                if redundant_data.strip():
                    yield dict(msg=redundant_data, _normalized_fields=dict(msg_type=UNMATCHED_DATA), _type_str='msg msg_type')

            self.buffer = self.buffer[start_index + len(log):]
            msgfilling.add_values(event)

            event["_normalized_fields"] = {}

            event_copy = copy.deepcopy(event)
            for k, v in event_copy.iteritems():
                if k not in ["msg", "_type_num", "_type_ip", "_type_str", "device_ip", "device_name", "_normalized_fields"]:
                    event.pop(k)
                    event["_normalized_fields"][k] = v

            yield event


if __name__ == '__main__':
    #rp = RegexParser(r"(?P<date_date>(?:\d{4}-\d{2}-\d{2}))\s\d{2}:\d{2}:\d{2}[,.]\S+\s+.*(?:\n)")
    rp = RegexParser(r"client (?P<client>(?:\d{1,3}\.){3}\d{1,3}) (?:dis)?connected.*")
    log = "client 192.168.1.2 connected asdfas asdfa345 42356462546& client 192.168.1.3 disconnected"
    log1 = """2012-10-15 12:19:29.747 DEBUG - Request received from 192.168.19.160 [192.168.19.160:13672] to fc.spectracard.se
                <?xml version="1.0" encoding="utf-8"?>
                <spectracard xmlns="http://alphyra.se/spectracard">
                  <source>
                    <installationId>108979</installationId>
                    <posId>1</posId>
                  </source>
                </spectracard>
                2012-10-15 13:45:03.444 DEBUG - SUPER(19819) [http-2048-29]
                dsfasd"""
    log2 = """2012-10-15 12:19:03.222 DEBUG - getScaCmd(19819) [http-2048-29]ritesh2012-10-15 12:19:03.222 DEBUG - getScaCmd(19819) [http-2048-29]"""
    rp.write(log)
    rp.write(log)
    #rp.write(log1)
    for event in rp:
        print event
