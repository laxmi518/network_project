
"""
LogParser for parsing LI logs.
Multiline traceback errors are regarded as a single message.
This works by assuming traceback errors are indented.
"""

import calendar
import time
import logging
import re2

from pylib.collections.ordereddict import OrderedDict
from LineParser import LineParser

log = logging.getLogger(__name__)
log_time_re = re2.compile(r'\d{4}-\d{2}-\d{2}[_ ]\d{2}:\d{2}:\d{2}')


def _count_leading_char(line, char):
    counter = 0
    for c in line:
        if c == char:
            counter += 1
        else:
            break
    return counter


def _count_leading_ident(line):
    if line:
        beginner = line[0]
        if beginner == '\t':
            return _count_leading_char(line, beginner) * 2
        elif beginner == ' ':
            return _count_leading_char(line, beginner)
    return 0


class StackTraceParser(LineParser):

    def __init__(self, sid=None, charset=None):
        super(StackTraceParser, self).__init__(sid, charset)
        self.trace = ""
        self.log_ts = 0

    def write(self, buffer, old_parser=False):
        self.stop_this_iter = False
        self.old_parser = old_parser
        self.last_time = time.time()
        super(StackTraceParser, self).write(buffer, old_parser)

    def next(self):
        last_space = 0

        while True:
            if not self.old_parser:
                if self.stop_this_iter:
                    self.trace = ""
                    raise StopIteration

            try:
                event = super(StackTraceParser, self).next()
            except StopIteration:
                self.stop_this_iter = True
                if not self.old_parser:
                    return _make_event(self.trace, self.log_ts)
                else:
                    raise StopIteration

            try:
                msg = event['msg']
                if log_time_re.test_match(msg):
                    #log_time = msg.split(' ', 1)[0]
                    #log_line = msg
                    log_time, log_line = msg.split(' ', 1)
                else:
                    log_time, log_line = None, msg
            except ValueError:
                self.trace += "\n"
                continue

            lead_space = _count_leading_ident(log_line)

            try:
                if lead_space == 0:
                    if last_space == 0 or last_space == 2:
                        try:
                            if self.trace:
                                return _make_event(self.trace, self.log_ts)
                            else:
                                continue
                        finally:
                            self.trace = msg
                            self.log_ts = _parse_log_ts(log_time)
                    else:
                        self.trace += "\n%s" % msg
                        try:
                            return _make_event(self.trace, self.log_ts)
                        finally:
                            self.trace = ""
                            self.log_ts = 0
                elif lead_space >= 2:
                    if self.trace:
                        self.trace += '\n'
                    if self.log_ts == 0:
                        self.log_ts = _parse_log_ts(log_time)
                    self.trace += msg
            finally:
                last_space = lead_space


def _make_event(msg, log_ts):
    event = dict(msg=msg, _type_str='msg')
    if log_ts != 0:
        #event['log_ts'] = log_ts
        event["_normalized_fields"] = dict(log_ts=log_ts)
        event['_type_num'] = 'log_ts'
    return event

log_ts_cache = OrderedDict()


def _parse_log_ts(log_time):
    if log_time is None:
        return 0
    try:
        log_time = log_time[:19]
        ts = log_ts_cache.get(log_time)
        if ts:
            return ts
        time_seq = map(int, [log_time[0:4], log_time[5:7], log_time[
                            8:10], log_time[11:13], log_time[14:16],
                                log_time[17:19]]) + [0, 0, 0]

        struct = time.struct_time(time_seq)
        ts = calendar.timegm(struct)

        if len(log_ts_cache) == 5:
            log_ts_cache.popitem(last=False)
        log_ts_cache[log_time] = ts

        return ts
    except:
        return 0

if __name__ == '__main__':
    parser = StackTraceParser()

    parser.write("""\
2011-07-28_05:34:44.79620 Starting syslog_collector
2011-07-28_05:34:44.85331 /usr/local/lib/python2.6/dist-packages/gevent_zeromq/core.py:51: DeprecationWarning: object.__init__() takes no parameters
2011-07-28_05:34:44.85334   super(_Socket, self).__init__(context, socket_type)
2011-07-28_05:34:44.85560 Traceback (most recent call last):
2011-07-28_05:34:44.85563   File "/home/sujan/makalu/ptf/disk/installed/col/apps/syslog_collector/syslog_collector.py", line 146, in <module>
2011-07-28_05:34:44.85568     main()
2011-07-28_05:34:44.85573   File "/home/sujan/makalu/ptf/disk/installed/col/apps/syslog_collector/syslog_collector.py", line 141, in main
2011-07-28_05:34:44.85577     start_tcp_server(address, config, syslog_out, tcp_bench)
2011-07-28_05:34:44.85582   File "/home/sujan/makalu/ptf/disk/installed/col/apps/syslog_collector/syslog_collector.py", line 89, in start_tcp_server
2011-07-28_05:34:44.85586     tcp_server.start()
2011-07-28_05:34:44.85590   File "/usr/lib/pymodules/python2.6/gevent/baseserver.py", line 146, in start
2011-07-28_05:34:44.85595     self.pre_start()
2011-07-28_05:34:44.85599   File "/usr/lib/pymodules/python2.6/gevent/server.py", line 89, in pre_start
2011-07-28_05:34:44.85603     BaseServer.pre_start(self)
2011-07-28_05:34:44.85606   File "/usr/lib/pymodules/python2.6/gevent/baseserver.py", line 136, in pre_start
2011-07-28_05:34:44.85611     self.socket = _tcp_listener(self.address, backlog=self.backlog, reuse_addr=self.reuse_addr)
2011-07-28_05:34:44.85614   File "/usr/lib/pymodules/python2.6/gevent/baseserver.py", line 206, in _tcp_listener
2011-07-28_05:34:44.85620     sock.bind(address)
2011-07-28_05:34:44.85623 socket.error: [Errno 13] Permission denied: ('0.0.0.0', 514)
2011-07-28_05:34:45.86414 Starting syslog_collector
2011-07-28_05:34:45.92451 /usr/local/lib/python2.6/dist-packages/gevent_zeromq/core.py:51: DeprecationWarning: object.__init__() takes no parameters
2011-07-28_05:34:45.92453   super(_Socket, self).__init__(context, socket_type
""")

    for line in parser:
        print line
