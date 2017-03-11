#!/usr/bin/env python

from gevent import monkey; monkey.patch_all()

from pylib import conf
from lib import fetcherloop

def _parse_args():
    options, config = conf.parse_config()
    return config

def main():
    config = _parse_args()
    fetcherloop.start(config)

main()
