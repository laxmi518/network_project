#!/usr/bin/env python

from gevent import monkey; monkey.patch_all()

import logging
import re

from lib import fetcherloop
from libcol import parsers
from pylib import conf


log = logging.getLogger(__name__)


def _parse_args():
    options, config = conf.parse_config()
    return config


def _validate(value, type=basestring, rex=None, callable=None):
    assert isinstance(value, type)
    if rex:
        assert re.search(rex, value)
    if callable:
        callable(value)


def validate_config(config):
    try:
        assert config['basedir']
        assert config['col_type']

        for sid, source in config['client_map'].iteritems():
            _validate(source['ip'])
            _validate(source['port'], int)
            _validate(source['user'], rex='^[^|:]+$')
            _validate(source['password'])
            _validate(source['path'], rex='^[^|]*$')
            _validate(source['fetch_interval_seconds'], int)
            _validate(source['charset'])

            col_type = config['col_type']
            source = "%(ip)s-%(user)s:%(port)s:%(path)s" % source
            assert sid == "%s|%s" % (col_type, source)

    except Exception, err:
        log.error('config.json validation failed')
        raise


def main():
    config = _parse_args()
    validate_config(config)

    fetcherloop.start(config)


main()
