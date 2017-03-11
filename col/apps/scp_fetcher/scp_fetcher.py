#!/usr/bin/env python

import os
import ssh
import time
import base64
import gevent
import shutil
import logging as log

from lib import scp
from pylib import homing, ssh_keygen, disk, pdict
from libcol.collectors import file_handler, shelves
from libcol.interface.fetcher_runner import FetcherRunner
from libcol.interface.fetcher_interface import Fetcher

class SCPFetcher(Fetcher):

    def __init__(self, **args):
        super(SCPFetcher, self).__init__(**args)

    def fetch_job(self):
        log.debug("fetching files for sid:%s", self.sid)

        config = self.fetcher_runner.get_config()
        try:
            source = config["client_map"][self.sid]
        except KeyError:
            log.debug("source for sid=%s has been deleted" % (self.sid))
            return

        basedir = config["basedir"].replace('$LOGINSPECT_HOME', homing.LOGINSPECT_HOME)

        scp_shelves_file = os.path.join(basedir, "scp.shelves")
        disk.prepare_path(scp_shelves_file)

        pd = pdict.PersistentDict(scp_shelves_file)
        if pd.get(self.sid):
            first_fetch = False
        else:
            first_fetch = True
            pd[self.sid] = True
            pd.sync()

        db_file = os.path.join(basedir, "checksums.pdict")

        remotepath = self.remotepath
        if remotepath.startswith('~'):
            remotepath = '.' + remotepath[1:]

        if '%' in self.device_ip:
            old_empty_dir = os.path.join(basedir, self.device_ip)
            if os.path.exists(old_empty_dir):
                try:
                    shutil.rmtree(old_empty_dir)
                except:
                    pass
            ip_dir = self.device_ip.replace("%", "_")
        else:
            ip_dir = self.device_ip

        localdir = os.path.join(basedir, ip_dir, base64.urlsafe_b64encode(self.sid))

        try:
            password = self.get_decrypted_password(self.password)
            scp.setup(self.device_ip, self.port, self.user, password)
        except (ssh.SSHException, EOFError, SystemExit), err:
            log.warn("error while setting up connection; sid=%s", self.sid)
            return

        try:
            for remotefile, mtime in scp.fetch_file_mtime(remotepath, self.name_pattern):
                disk.prepare_path(localdir + '/')

                if first_fetch:
                    vc = shelves.VersionChecker(db_file, self.sid, remotefile, mtime=mtime, old_logs=self.old_logs)
                else:
                    vc = shelves.VersionChecker(db_file, self.sid, remotefile, mtime=mtime)

                if vc.is_older_version():
                    continue

                localfile = os.path.join(localdir, base64.urlsafe_b64encode(remotefile))
                log.info('Downloading remote file %r to %r', remotefile, localfile)

                try:
                    scp.scp_get(remotefile, localfile)
                except (ssh.SSHException, EOFError, SystemExit), err:
                    log.warn("fetching failed; sid=%s; remotefile=%s; error=%r", self.sid, remotefile, err)
                    continue

                col_ts = time.time()
                cursor = vc.get_old_cursor(localfile)
                if cursor < 0:
                    continue

                conf_path = self.fetcher_runner.get_field_value_from_config("wiring_conf_path") or None
                col_type = self.fetcher_runner.get_field_value_from_config("col_type")
                client_map = self.get_client_map()

                file_handler.main(self.sid, col_type, col_ts, self.parser, localfile, self.charset,
                                  self.device_name, client_map["normalizer"], client_map["repo"],
                                  cursor, client_map.get("regex_pattern"),
                                  client_map.get("regexparser_name"), self.device_ip, conf_path=conf_path,
                                  source_name=remotefile)
        except gevent.GreenletExit:
            raise
        except (Exception, ssh.SSHException, EOFError, SystemExit), err:
            log.warn('exception while running job; sid=%s; err=%r', self.sid, err)


def _ensure_certificates():
    if not os.path.exists(scp.private_keyfile):
        ssh_keygen.generate(private=scp.private_keyfile, public=scp.private_keyfile + ".pub")

_ensure_certificates()

runner = FetcherRunner()
runner.register_fetcher(SCPFetcher)
runner.start()
