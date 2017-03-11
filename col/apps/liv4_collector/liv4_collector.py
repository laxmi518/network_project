#!/usr/bin/env python

from pylib import conf, textual, mongo
from lib import ftp_server, extracter, transformer, status_updater

def _parse_args():
    options, config = conf.parse_config()
    return config

def main():
    config = _parse_args()
    config = textual.utf8(config)
    db = mongo.get_makalu()
    updater = status_updater.Updater(db, config["repo"])

    if config.get("upload_channel") is not None:
        downloaded_file = ftp_server.listen(db, config, updater)
        basedir = extracter.extract(downloaded_file, db, config, updater)
        is_compressed_file_present = True
    else:
        basedir = config["path"]
        is_compressed_file_present = False

    transformer.start(config, basedir, db, is_compressed_file_present, updater)


main()
