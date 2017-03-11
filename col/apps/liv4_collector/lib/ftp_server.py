
import asyncore
import logging
import os
import time
import tarfile

from pyftpdlib import ftpserver
from pylib import disk, homing, filetype

ftpserver.log = lambda msg: logging.info(msg)
ftpserver.logline = lambda msg: logging.debug(msg)

DOWNLOADED_FILE = None

def get_downloaded_file(db, repo):
    return db.datatransport.find_one({"repo": repo}).get("downloaded_file")

class FTPHandler(ftpserver.FTPHandler):
    def __init__(self, conn, server, db, repo):
        ftpserver.FTPHandler.__init__(self, conn, server)
        self.db = db
        self.repo = repo

    def on_file_received(self, filepath):
        logging.info("received file %s", filepath)
        type_, subtype = filetype.filetype(filepath)
        if subtype in ["x-gzip", "x-bzip2", "x-tar"] and tarfile.is_tarfile(filepath):
            global DOWNLOADED_FILE
            DOWNLOADED_FILE = filepath
            self.db.datatransport.update({"repo": self.repo}, {"$set":
                    {"downloaded_file": filepath, "subtype": subtype,
                    "time": time.time(), "status": "file uploaded"}
            })
            raise asyncore.ExitNow
        else:
            logging.warn('Only tarfile with "x-tar", "x-gzip" or "x-bzip2" as mime subtype supported (%s given)', filepath)
            os.remove(filepath)

    def on_incomplete_file_received(self, filepath):
        # remove partially uploaded files
        os.remove(filepath)

def listen(db, config, updater):
    repo = config["repo"]
    localfile = get_downloaded_file(db, repo)
    if localfile:
        logging.warn("file already downloaded at %r", localfile)
        return localfile

    channel = config["upload_channel"]
    username = channel["username"]
    password = channel["password"]
    home = channel["home"].replace("$LOGINSPECT_HOME", homing.LOGINSPECT_HOME).replace("$repo", repo)
    disk.prepare_path(home + '/')
    address = ('0.0.0.0', channel["port"])

    authorizer = ftpserver.DummyAuthorizer()
    authorizer.add_user(username, password, home, "elradfmwM")
    FTPHandler.authorizer = authorizer

    ftpd = ftpserver.FTPServer(address, lambda conn, server: FTPHandler(conn, server, db, repo))
    logging.warn("ftp server starting at %r", address)
    ftpd.serve_forever()
    return DOWNLOADED_FILE
