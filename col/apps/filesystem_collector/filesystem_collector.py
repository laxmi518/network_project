#!/usr/bin/env python

"""
Log Collector that monitors the filesystem logs
"""

import logging
import shelve

from pylib.wiring import gevent_zmq as zmq

from lib import watcher
from pylib import conf, disk, homing

log = logging.getLogger(__name__)

def _parse_args():
    options, config = conf.parse_config()
    return config

def main():
    config = _parse_args()
    zmq_context = zmq.Context()

    db_file = homing.home_join('storage/col/filesystem_collector', 'checksums.shelve')
    disk.prepare_path(db_file)

    cursor_shelve = shelve.open(db_file, protocol=2)
    watcher.monitor(config, cursor_shelve, zmq_context)


if __name__ == '__main__':
    main()
