#!/usr/bin/env python

"""
Log Collector that monitors the filesystem for new logs
"""

import json
import optparse
import time

from pylib import disk, logger
from lib import watcher_watchdog as watcher

log = logger.getLogger(__name__)


def _parse_args():
    cli_parser = optparse.OptionParser()
    cli_parser.add_option("-c", "--conf", help="Configuration file.")

    cli_parser.set_defaults(conf=disk.get_sibling(__file__, 'sources.conf'))

    logger.configure(cli_parser, syslog=False)

    options, args = cli_parser.parse_args()
    if len(args) > 0:
        cli_parser.error("No extra arg is expected.")

    try:
        mapper = json.load(open(options.conf))

    except IOError, err:
        log.debug(err)
        cli_parser.error("Configuration file '%s' does not exist." % options.conf)

    except ValueError, err:
        log.debug(err)
        cli_parser.error("JSON syntax error while loading '%s'.\n%s" % (options.conf, err))

    return mapper


def main():
    mapper = _parse_args()

    observer = watcher.monitor(mapper)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    #observer.join()


if __name__ == '__main__':
    main()
