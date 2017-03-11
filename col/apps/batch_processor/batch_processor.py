#!/usr/bin/env python

'''
Supports reading and parsing following file types
'''

import logging
import time
import os

from pylib.wiring import gevent_zmq as zmq

from libcol.parsers import GetParser, InvalidParserException
from pylib import conf, wiring, msgfilling, timing
from lib import unpackers

log = logging.getLogger(__name__)
MAX_SPEED = 1000

def _parse_args():
    options, config  = conf.parse_config()
    return config


def file_processor(path, parser_name, sid, charset, cursor, regex_pattern, regexparser_name):
    try:
        parser = GetParser(parser_name, sid, charset, regex_pattern, regexparser_name)
    except InvalidParserException, err:
        log.warn(err)
        return

    try:
        for data in unpackers.unpack(path, cursor):
            parser.write(data, old_parser=True)

            for msg in parser:
                yield msg
    except Exception, err:
        log.warn("Error while unpacking:\n%r", err)


def main():
    log.info('Batch Processor for Collector apps starting...')

    config = _parse_args()
    zmq_context = zmq.Context()

    processor_in = wiring.Wire('batch_processor_in', zmq_context=zmq_context,
                                    conf_path=config.get('wiring_conf_path') or None)
    collector_out = wiring.Wire('collector_out', zmq_context=zmq_context,
                                    conf_path=config.get('wiring_conf_path') or None)

    last_timestamp = 0

    throttler = timing.speed_throttler(MAX_SPEED)
    while True:
        file_info = processor_in.recv()

        sid     = file_info['sid']
        col_type = file_info['col_type']
        col_ts  = file_info['col_ts']
        parser  = file_info['parser']
        file    = file_info['file']
        cursor = file_info['cursor']
        charset = file_info['charset']
        device_name = file_info['device_name']
        device_ip = file_info['device_ip']
        regex_pattern = file_info['regex_pattern']
        regexparser_name = file_info['regexparser_name']
        normalizer = file_info['normalizer']
        repo = file_info['repo']
        source_name = file_info['source_name']
        
        current_timestamp = int(time.time())
        if current_timestamp > last_timestamp:
            last_timestamp = current_timestamp
            counter = 0

        for event in file_processor(file, parser, sid, charset, cursor,
                regex_pattern, regexparser_name):
            throttler.next()
            counter += 1

            loginspect_name = config["loginspect_name"]
            event['mid'] = '%s|%s|%s|%d' % (loginspect_name, sid, col_ts, counter)
            event['collected_at'] = loginspect_name

            event['device_name'] = device_name
            msgfilling.add_types(event, '_type_str', 'device_name collected_at col_type')
            
            event['col_ts'] = col_ts
            event['_counter'] = counter
            event['col_type'] = col_type
            msgfilling.add_types(event, '_type_num', 'col_ts')
            
            if device_ip is not None:
                event['device_ip'] = device_ip
                msgfilling.add_types(event, '_type_str', 'device_ip')
                msgfilling.add_types(event, '_type_ip', 'device_ip')
            
            event['normalizer'] = normalizer
            event['repo'] = repo

            if source_name:
                if event.get('_normalized_fields'):
                    event['_normalized_fields']['source_name'] = source_name
                else:
                    event['_normalized_fields'] = {'source_name': source_name}
                msgfilling.add_types(event, '_type_str', 'source_name')

            collector_out.send_with_norm_policy_and_repo(event)

        try:
           os.unlink(file)
        except:
           pass


if __name__ == '__main__':
    main()
