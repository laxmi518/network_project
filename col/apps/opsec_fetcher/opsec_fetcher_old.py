#!/usr/bin/env python

from gevent import monkey; monkey.patch_all()

from pylib.wiring import gevent_zmq as zmq
import logging

from lib import fetcherloop
from pylib import conf, wiring

log = logging.getLogger(__name__)

def _parse_args():
    options, app_config = conf.parse_config()
    return app_config

def main():
    zmq_context = zmq.Context()
    
    config = _parse_args()
    
    opsecfetcher_out = wiring.Wire("collector_out", zmq_context=zmq_context,
                                        conf_path=config.get('wiring_conf_path') or None)

    log.info('opsec fetcher starting..')
    fetcherloop.start(config, opsecfetcher_out)

main()
