#!/usr/bin/env python

import os
import time
import base64
import logging as log

from lib import ftpclient
from pylib import homing, disk, pdict
from libcol.collectors import file_handler, shelves
from libcol.interface.fetcher_runner import FetcherRunner
from libcol.interface.fetcher_interface import Fetcher

class FTPFetcher(Fetcher):

    def __init__(self, **args):
        super(FTPFetcher, self).__init__(**args)

    def fetch_job(self):
        log.debug("fetching files for sid:%s", self.sid)

        basedir = self.fetcher_runner.get_field_value_from_config("basedir")
        basedir = basedir.replace("$LOGINSPECT_HOME", homing.LOGINSPECT_HOME)

        ftp_shelves_file = os.path.join(basedir, "ftp.shelves")
        disk.prepare_path(ftp_shelves_file)

        pd = pdict.PersistentDict(ftp_shelves_file)
        if pd.get(self.sid):
            first_fetch = False
        else:
            first_fetch = True
            pd[self.sid] = True
            pd.sync()

        db_file = os.path.join(basedir, "checksums.pdict")

        localdir = os.path.join(basedir, self.device_ip, base64.urlsafe_b64encode(self.sid))

        password = self.get_decrypted_password(self.password)
        ftp = ftpclient.login(self.device_ip, self.port, self.user, password)

        for remotefile, mtime in ftpclient.fetch_file_mtime(ftp, self.path, self.name_pattern):
            disk.prepare_path(localdir + '/')

            if first_fetch:
                vc = shelves.VersionChecker(db_file, self.sid, remotefile, mtime, old_logs=self.old_logs)
            else:
                vc = shelves.VersionChecker(db_file, self.sid, remotefile, mtime)

            if vc.is_older_version():
                continue

            localfile = os.path.join(localdir, base64.urlsafe_b64encode(remotefile))
            log.info('Downloading remote file %r to %r', remotefile, localfile)

            try:
                ftpclient.download(ftp, remotefile, localfile)
            except Exception, err:
                log.warn("fetching failed; remotefile=%s; sid=%s; error=%r", remotefile, self.sid, err)
                continue

            col_ts = time.time()
            cursor = vc.get_old_cursor(localfile)
            if cursor < 0:
                continue

            conf_path = self.fetcher_runner.get_field_value_from_config("wiring_conf_path") or None
            col_type = self.fetcher_runner.get_field_value_from_config("col_type")

            client_map = self.get_client_map()
            file_handler.main(self.sid, col_type, col_ts, self.parser, localfile, self.charset,
                              self.device_name, client_map['normalizer'], client_map['repo'],
                              cursor, client_map.get("regex_pattern"),
                              client_map.get("regexparser_name"), self.device_ip, conf_path=conf_path,
                              source_name=remotefile)
        ftp.quit()


runner = FetcherRunner()
runner.register_fetcher(FTPFetcher)
runner.start()
