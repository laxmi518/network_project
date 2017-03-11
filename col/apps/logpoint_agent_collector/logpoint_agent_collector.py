#!/usr/bin/env python

import logging
from pylib.wiring import gevent_zmq as zmq

from lib import fi_collector
from fi_applications import make_zip
from pylib import conf, wiring, textual


log = logging.getLogger(__name__)


def _parse_args():
    options, config = conf.parse_config()
    return config

def _prepare_application_directory(config):
    make_zip.create_zipped_application_packages(config['basedir'])

def main():
    zmq_context = zmq.Context()
    
    config = _parse_args()
    #config = textual.utf8(config)
    
    #_prepare_application_directory(config)
    
    fi_out = wiring.Wire('collector_out', zmq_context=zmq_context,
                                conf_path=config.get('wiring_conf_path') or None)
    
    log.info('LogPoint_agent_collector starting...')
    
    fi_collector.main(config, fi_out)

main()
