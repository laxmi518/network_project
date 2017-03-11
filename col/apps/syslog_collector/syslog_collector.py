#!/usr/bin/env python

"""
Syslog Collecter based on the gevent. It handles
each of the syslog client using the Green thread. It collects the syslog data,
parses out the log time from each of the log message and sends them to the upper
storage layer.
"""

from libcol.interface.collector import CollectorInterface

class SyslogCollector(CollectorInterface):
    def __init__(self, name):
        super(SyslogCollector, self).__init__(name)

    def handle_data(self, data, config):
        """
        Handle UDP, TCP and TCP/SSL data
        """
        parser = config["parser"]
        if parser:
            parser.write(data)
            for event in parser:
                self.add_event(event, config)

    def handle_udp_data(self, data, **config):
        """
        """
        self.handle_data(data, config)

    def handle_tcp_data(self, data, **config):
        """
        """
        self.handle_data(data, config)

    def handle_tcp_ssl_data(self, data, **config):
        """
        """
        self.handle_data(data, config)

if __name__ == "__main__":
    
    syslog_col = SyslogCollector("Syslog")
    
    syslog_col.turn_tcp_server_on()
    syslog_col.turn_tcp_ssl_server_on()
    syslog_col.turn_udp_server_on()
    
    syslog_col.start()
