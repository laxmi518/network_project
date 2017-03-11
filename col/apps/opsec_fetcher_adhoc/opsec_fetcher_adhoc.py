#!/usr/bin/env python

import os
import re
import subprocess

from pylib import homing, logger, mongo
from pylib.opseclib.logparser import parse_log
from libcol.interface.fetcher_runner import FetcherRunner
from libcol.interface.fetcher_interface import Fetcher

log = logger.getLogger(__name__)

db = mongo.get_makalu()

class OpsecFetcherAdhoc(Fetcher):

    def __init__(self, **args):
        super(OpsecFetcherAdhoc, self).__init__(**args)

        ip_path = homing.home_join("storage/col/opsec_fetcher", self.device_ip)
        #Change directory to the ip of sever because the certificate files are present there
        os.chdir(ip_path)
        #The path of loggrabber utils
        utils_path = homing.home_join("installed/system/apps/opsec_tools")
        #The executor script to export logs
        self.loggrabber_executor = os.path.join(utils_path, "fw1-loggrabber")
        #The configuration to be used with -c
        self.loggrabber_conf = os.path.join(utils_path, "fw1-loggrabber-offline.conf")
        #The configuration file to be used with -l
        self.lea_conf_file = os.path.join(os.path.join(ip_path, "lea.conf"))
        #convert stattime and endtime to YYMMDDHHMMSS format from "2013-11-21 18:45:00" format
        self.convert_time()

    def convert_time(self):
        #convert from YY-MM-DD HH:MM:SS to YYMMDDHHMMSS
        self.new_starttime = re.sub(r"[-: ]", "", self.starttime)
        self.new_endtime = re.sub(r"[-: ]", "", self.endtime)

    def run_script(self):
        """
        Fetch only the most recent logs
        """
        proc = subprocess.Popen(
                [self.loggrabber_executor,
                '-l', self.lea_conf_file,
                '-c', self.loggrabber_conf,
                '--filter',
                "starttime=%s;endtime=%s" % (self.new_starttime, self.new_endtime)],
                stdout=subprocess.PIPE
                )
        return proc

    def add_types(self, event, key, value):
        #Add the msgfilling types here by parsing the key
        self.prepare_event(event, key, value)

    def fetch_job(self):
        proc = self.run_script()
        #Done with running the fw1-loggrabber client from subprocess

        #This buffer maintains the remaining part of the log message that is incomplete
        #in this chunk of data
        last_buffer = ""
        while True:
            #Read 4kb of data chunk at a time
            chunk = proc.stdout.read(4096)
            if not chunk:
                db.device.update({
                   "ip": self.device_ip,
                   "col_apps": {
                       "$elemMatch": {
                           "app":"AdhocOPSECFetcher",
                           "start_datetime": self.starttime,
                           "end_datetime": self.endtime
                       }
                   }
                }, {"$set":{"col_apps.$.active": False}})

                break

            #If we have last_buffer, then we add it to the existing chunk
            if last_buffer:
                chunk = last_buffer + chunk
            lines = chunk.splitlines(True)
            #Put the last line to last_buffer because it maynot be a complete log message
            last_buffer = lines[len(lines)-1]
            #So iterate only to number of lines - 1
            for line in lines[:-1]:
                event = parse_log(line)
                if event:
                    for key, value in event.items():
                        self.add_types(event, key, value)
                    self.add_event(event)
            #But if the last line ends with \n, it means it is a complete log
            #So process it to send to upper layer
            if last_buffer.endswith("\n"):
                event = parse_log(last_buffer)
                if event:
                    for key, value in event.items():
                        self.prepare_event(event, key, value)
                    self.add_event(event)
                #And clear the last buffer
                last_buffer = ""

runner = FetcherRunner()
runner.register_fetcher(OpsecFetcherAdhoc)
runner.start()
