
from libcol.interface.collector import CollectorInterface

class SyslogCollector(CollectorInterface):
    def __init__(self, name):
        super(SyslogCollector, self).__init__(name)

    def handle_udp_data(self, data, **config):
        parser = config["parser"]
        if parser:
            parser.write(data)
            for event in parser:
                self.add_event(event, config)
    
    def handle_tcp_data(self, data, **config):
        pass
    
    def handle_tcp_ssl_data(self, data, **config):
        pass

if __name__ == "__main__":
    
    syslog_col = SyslogCollector("Syslog")
    
    #syslog_col.turn_tcp_server_on()
    #syslog_col.turn_tcp_ssl_server_on()
    syslog_col.turn_udp_server_on()
    
    syslog_col.start()
