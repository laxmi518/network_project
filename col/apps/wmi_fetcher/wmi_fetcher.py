#!/usr/bin/env python

import subprocess

from pylib import logger
from libcol.interface.fetcher_runner import FetcherRunner
from libcol.interface.fetcher_interface import Fetcher

WMIC_PATH = "/bin/wmic"

log = logger.getLogger(__name__)


class WMIFetcher(Fetcher):

    def __init__(self, **args):
        """
        """
        self.time_zone = 0
        self.time_gen = None

        super(WMIFetcher, self).__init__(**args)

    def from_time(self, year=None, month=None, day=None, hours=None, minutes=None,
                  seconds=None, microseconds=None):
        """
        returns: A WMI datetime string of the form: `yyyymmddHHMMSS.mmmmmm+UUU`
        """
        def str_or_stars(i, length):
            if i is None:
                return "*" * length
            else:
                return str(i).rjust(length, "0")

        wmi_time = ""
        wmi_time += str_or_stars(year, 4)
        wmi_time += str_or_stars(month, 2)
        wmi_time += str_or_stars(day, 2)
        wmi_time += str_or_stars(hours, 2)
        wmi_time += str_or_stars(minutes, 2)
        wmi_time += str_or_stars(seconds, 2)
        wmi_time += "."
        wmi_time += str_or_stars(microseconds, 6)
        wmi_time += "+"
        wmi_time += str_or_stars(self.time_zone, 3)
        return wmi_time

    def get_wmi_data(self, wml_query):
        """
        """
        password = self.get_decrypted_password(self.password)
        wmic_args = ["%s" % WMIC_PATH, "-U", "%s%%%s" % (self.username, password),
                     "//%s" % self.sid, "%s" % wml_query]
        wmicproc = subprocess.Popen(wmic_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        wmic_data, wmi_err_data = wmicproc.communicate()

        if wmi_err_data:
            log.warn("error when executing wmi command; host=%r; username=%r; query=%r, err_data=%r",
                     self.sid, self.username, wml_query, wmi_err_data)

        if wmic_data:
            wmic_data = wmic_data.split("\n")
            if "[wmi/wmic.c:196:main()] ERROR: Login to remote object." in wmic_data:
                log.warn("Invalid IP address or Invalid credentials for host %s" % self.sid)
                return None
            elif "[wmi/wmic.c:200:main()] ERROR: WMI query execute." in wmic_data:
                log.warn("Invaid WMI query for host %s" % self.sid)
                return None

        return wmic_data

    def get_time_of_current_log(self):
        """
        """
        # query = "SELECT Bias FROM Win32_TimeZone"
        # wmic_data = self.get_wmi_data(query)
        # if not wmic_data:
        #     return None

        # self.time_zone = self.parser_instance.parse_wmi_timezone_query(wmic_data)

        query = "SELECT * FROM Win32_UTCTime"
        wmic_data = self.get_wmi_data(query)
        if not wmic_data:
            return None

        datetime_client = self.parser_instance.parse_wmi_date_query(wmic_data)

        current_time = self.from_time(*datetime_client.timetuple()[:-2])

        return current_time

    def fetch_job(self):
        """
        """
        log.debug("fetching wmi log")

        if not self.time_gen:
            self.time_gen = self.get_time_of_current_log()
            if not self.time_gen:
                return

        query = "SELECT * FROM Win32_NTLogEvent WHERE TimeGenerated>\'%s\'" % self.time_gen
        wmic_data = self.get_wmi_data(query)

        if wmic_data:
            self.parser_instance.write(wmic_data)

            for event in self.parser_instance:
                self.add_event(event)

            time_gen_in_logs = self.parser_instance.get_last_time()
            if time_gen_in_logs:
                self.time_gen = time_gen_in_logs


runner = FetcherRunner()
runner.register_fetcher(WMIFetcher)
runner.start()
