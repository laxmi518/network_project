#!/usr/bin/env python

from libcol.collectors import file_handler
from libcol.interface.collector import CollectorInterface

class FTPCollector(CollectorInterface):
    def __init__(self, name):
        super(FTPCollector, self).__init__(name)

    def handle_file_received(self, data, config):
        """
        data = local file name
        """
        home = config["home"]
        source_name = data.split(home)
        if len(source_name) > 1:
          source_name = source_name[1].lstrip("/")
        else:
          source_name = source_name[0].lstrip("/")

        file_handler.main(config["sid"], config["col_type"], config["time_received"], config["parser"], data,
                          config["charset"], config["device_name"], config["normalizer"],
                          config["repo"], config["cursor"],
                          config.get("regex_pattern"), config.get("regexparser_name"), 
                          config["device_ip"], conf_path=config["wiring_conf_path"],
                          source_name=source_name)

if __name__ == "__main__":
    
    ftp_col = FTPCollector("FTP")
    
    ftp_col.turn_ftp_server_on(parser_name_only=True)
    
    ftp_col.start()
