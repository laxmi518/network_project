
from nose.tools import eq_
from libcol.parsers import StackTraceParser
from libcol.parsers.StackTraceParser import _parse_log_ts

def test_python_traceback():
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

    result = list(parser)
    expected = [
        {'msg': '2011-07-28_05:34:44.79620 Starting syslog_collector', '_type_str': 'msg', '_type_num': 'log_ts',
         '_normalized_fields': {'log_ts': _parse_log_ts('2011-07-28_05:34:44.79620')}},
        {'msg': '2011-07-28_05:34:44.85331 /usr/local/lib/python2.6/dist-packages/gevent_zeromq/core.py:51: DeprecationWarning: object.__init__() takes no parameters\n2011-07-28_05:34:44.85334   super(_Socket, self).__init__(context, socket_type)', '_type_str': 'msg', '_type_num': 'log_ts',
         '_normalized_fields': {'log_ts': _parse_log_ts('2011-07-28_05:34:44.85331')}},
        {'msg': '2011-07-28_05:34:44.85560 Traceback (most recent call last):\n2011-07-28_05:34:44.85563   File "/home/sujan/makalu/ptf/disk/installed/col/apps/syslog_collector/syslog_collector.py", line 146, in <module>\n2011-07-28_05:34:44.85568     main()\n2011-07-28_05:34:44.85573   File "/home/sujan/makalu/ptf/disk/installed/col/apps/syslog_collector/syslog_collector.py", line 141, in main\n2011-07-28_05:34:44.85577     start_tcp_server(address, config, syslog_out, tcp_bench)\n2011-07-28_05:34:44.85582   File "/home/sujan/makalu/ptf/disk/installed/col/apps/syslog_collector/syslog_collector.py", line 89, in start_tcp_server\n2011-07-28_05:34:44.85586     tcp_server.start()\n2011-07-28_05:34:44.85590   File "/usr/lib/pymodules/python2.6/gevent/baseserver.py", line 146, in start\n2011-07-28_05:34:44.85595     self.pre_start()\n2011-07-28_05:34:44.85599   File "/usr/lib/pymodules/python2.6/gevent/server.py", line 89, in pre_start\n2011-07-28_05:34:44.85603     BaseServer.pre_start(self)\n2011-07-28_05:34:44.85606   File "/usr/lib/pymodules/python2.6/gevent/baseserver.py", line 136, in pre_start\n2011-07-28_05:34:44.85611     self.socket = _tcp_listener(self.address, backlog=self.backlog, reuse_addr=self.reuse_addr)\n2011-07-28_05:34:44.85614   File "/usr/lib/pymodules/python2.6/gevent/baseserver.py", line 206, in _tcp_listener\n2011-07-28_05:34:44.85620     sock.bind(address)\n2011-07-28_05:34:44.85623 socket.error: [Errno 13] Permission denied: (\'0.0.0.0\', 514)', '_type_str': 'msg', '_type_num': 'log_ts',
         '_normalized_fields': {'log_ts': _parse_log_ts('2011-07-28_05:34:44.85560')}},
        {'msg': '2011-07-28_05:34:45.86414 Starting syslog_collector', '_type_str': 'msg', '_type_num': 'log_ts',
         '_normalized_fields': {'log_ts': _parse_log_ts('2011-07-28_05:34:45.86414')}},
        {'msg': '2011-07-28_05:34:45.92451 /usr/local/lib/python2.6/dist-packages/gevent_zeromq/core.py:51: DeprecationWarning: object.__init__() takes no parameters\n2011-07-28_05:34:45.92453   super(_Socket, self).__init__(context, socket_type', '_type_str': 'msg', '_type_num': 'log_ts',
         '_normalized_fields': {'log_ts': _parse_log_ts('2011-07-28_05:34:45.86414')}},
    ]
    eq_(result, expected)


def test_java_exception():
    parser = StackTraceParser()

    parser.write("""\
2040-12-28_12:30:06.42732 ERROR: Error while indexing
2040-12-28_12:30:06.42733 java.lang.NumberFormatException: For input string: "2240310605"
2040-12-28_12:30:06.42734 	at java.lang.NumberFormatException.forInputString(NumberFormatException.java:65)
2040-12-28_12:30:06.42734 	at java.lang.Integer.parseInt(Integer.java:484)
2040-12-28_12:30:06.42734 	at java.lang.Integer.parseInt(Integer.java:514)
2040-12-28_12:30:06.42735 	at com.immunesecurity.indexer.LogDocument.getTsDoc(LogDocument.java:44)
2040-12-28_12:30:06.42735 	at com.immunesecurity.indexer.Indexer.index(Indexer.java:143)
2040-12-28_12:30:06.42735 	at com.immunesecurity.indexer.RunnableIndexThread.run(RunnableIndexThread.java:56)
2040-12-28_12:30:06.42736 	at java.lang.Thread.run(Thread.java:636)
2040-12-28_12:30:06.42736 ERROR: Error while indexing
2040-12-28_12:30:06.42737 java.lang.NumberFormatException: For input string: "2240310605"
2040-12-28_12:30:06.42737 	at java.lang.NumberFormatException.forInputString(NumberFormatException.java:65)
2040-12-28_12:30:06.42737 	at java.lang.Integer.parseInt(Integer.java:484)
2040-12-28_12:30:06.42738 	at java.lang.Integer.parseInt(Integer.java:514)
2040-12-28_12:30:06.42738 	at com.immunesecurity.indexer.LogDocument.getTsDoc(LogDocument.java:44)
2040-12-28_12:30:06.42738 	at com.immunesecurity.indexer.Indexer.index(Indexer.java:143)
2040-12-28_12:30:06.42739 	at com.immunesecurity.indexer.RunnableIndexThread.run(RunnableIndexThread.java:56)
2040-12-28_12:30:06.42739 	at java.lang.Thread.run(Thread.java:636)
2040-12-28_12:30:06.42740 ERROR: Error while indexing
""")

    result = list(parser)
    expected = [
        {'msg': '2040-12-28_12:30:06.42732 ERROR: Error while indexing', '_type_str': 'msg', '_type_num': 'log_ts',
         '_normalized_fields': {'log_ts': _parse_log_ts('2040-12-28_12:30:06.42732')}},
        {'msg': '2040-12-28_12:30:06.42733 java.lang.NumberFormatException: For input string: "2240310605"\n2040-12-28_12:30:06.42734 \tat java.lang.NumberFormatException.forInputString(NumberFormatException.java:65)\n2040-12-28_12:30:06.42734 \tat java.lang.Integer.parseInt(Integer.java:484)\n2040-12-28_12:30:06.42734 \tat java.lang.Integer.parseInt(Integer.java:514)\n2040-12-28_12:30:06.42735 \tat com.immunesecurity.indexer.LogDocument.getTsDoc(LogDocument.java:44)\n2040-12-28_12:30:06.42735 \tat com.immunesecurity.indexer.Indexer.index(Indexer.java:143)\n2040-12-28_12:30:06.42735 \tat com.immunesecurity.indexer.RunnableIndexThread.run(RunnableIndexThread.java:56)\n2040-12-28_12:30:06.42736 \tat java.lang.Thread.run(Thread.java:636)', '_type_str': 'msg', '_type_num': 'log_ts',
         '_normalized_fields': {'log_ts': _parse_log_ts('2040-12-28_12:30:06.42733')}},
        {'msg': '2040-12-28_12:30:06.42736 ERROR: Error while indexing', '_type_str': 'msg', '_type_num': 'log_ts',
         '_normalized_fields': {'log_ts': _parse_log_ts('2040-12-28_12:30:06.42736')}},
        {'msg': '2040-12-28_12:30:06.42737 java.lang.NumberFormatException: For input string: "2240310605"\n2040-12-28_12:30:06.42737 \tat java.lang.NumberFormatException.forInputString(NumberFormatException.java:65)\n2040-12-28_12:30:06.42737 \tat java.lang.Integer.parseInt(Integer.java:484)\n2040-12-28_12:30:06.42738 \tat java.lang.Integer.parseInt(Integer.java:514)\n2040-12-28_12:30:06.42738 \tat com.immunesecurity.indexer.LogDocument.getTsDoc(LogDocument.java:44)\n2040-12-28_12:30:06.42738 \tat com.immunesecurity.indexer.Indexer.index(Indexer.java:143)\n2040-12-28_12:30:06.42739 \tat com.immunesecurity.indexer.RunnableIndexThread.run(RunnableIndexThread.java:56)\n2040-12-28_12:30:06.42739 \tat java.lang.Thread.run(Thread.java:636)', '_type_str': 'msg', '_type_num': 'log_ts',
         '_normalized_fields': {'log_ts': _parse_log_ts('2040-12-28_12:30:06.42737')}},
        {'msg': '2040-12-28_12:30:06.42740 ERROR: Error while indexing', '_type_str': 'msg', '_type_num': 'log_ts',
         '_normalized_fields': {'log_ts': _parse_log_ts('2040-12-28_12:30:06.42737')}},
    ]
    eq_(result, expected)
