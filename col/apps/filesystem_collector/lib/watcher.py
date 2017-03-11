
import fnmatch
import glob
import logging
import os
import time

import pymongo
import gevent

from libcol import parsers
from pylib import homing, configgenerator, wiring, msgfilling, mongo

log = logging.getLogger(__name__)


class FileHandler(object):
    def __init__(self, path, config, collector_out, cursor_shelve):
        """
        path: log file to be monitored
        """
        self.path = path.encode('utf-8')

        self.config = config
        self.collector_out = collector_out
        self.cursor_shelve = cursor_shelve

        profile = config["client_map"][path]
        self.parser_name = profile['parser']
        self.col_type = config['col_type']
        self.sid = '%s|127.0.0.1-%s' % (config['col_type'], self.path)
        self.device_name = profile['device_name']
        self.normalizer = profile['normalizer']
        self.repo = profile['repo']
        charset = profile['charset']
        self.parser = parsers.GetParser(self.parser_name, self.sid, charset,
                profile.get('regex_pattern'), profile.get('regexparser_name'))

        self.last_timestamp = 0
        # job for checking last line timeout
        self.gevent_job = None

        if not self.path in cursor_shelve:
            self.cursor = 0

        self.process()

    @property
    def cursor(self):
        return self.cursor_shelve[self.path]

    @cursor.setter
    def cursor(self, cursor_value):
        self.cursor_shelve[self.path] = cursor_value
        self.cursor_shelve.sync()

    def process(self):
        with open(self.path) as f:
            f.seek(0, 2)
            if self.cursor > f.tell():
                self.cursor = 0

            f.seek(self.cursor)
            while True:
                data = f.read(1024)
                self.cursor = f.tell()
                if not data:
                    if isinstance(self.parser, parsers.StackTraceParser) and self.parser.trace:
                        dummy_data = "2011-07-28_05:34:45.92453 dummy\n"
                        self.forward(dummy_data)
                        self.parser.trace = ""
                    return

                logging.info('file=%s; cursor=%s; data_len=%d', self.path, self.cursor, len(data))
                self.collector_out.start_benchmarker_processing()

                self.forward(data)

    def forward(self, data):
        self.parser.write(data, old_parser=True)

        col_ts = int(time.time())
        if col_ts > self.last_timestamp:
            self.last_timestamp = col_ts
            self.counter = 0

        if self.counter >= 100:
            time.sleep(1)

        for event in self.parser:
            self.counter += 1

            loginspect_name = self.config["loginspect_name"]
            event['mid'] = '%s|%s|%s|%d' % (loginspect_name, self.sid, col_ts, self.counter)
            
            event['col_ts'] = col_ts
            event['_counter'] = self.counter
            event['col_type'] = self.col_type
            msgfilling.add_types(event, '_type_num', 'col_ts')
            msgfilling.add_types(event, '_type_str', 'col_type')
            
            event["collected_at"] = loginspect_name

            event["device_name"] = self.device_name
            msgfilling.add_types(event, '_type_str', 'device_name collected_at')
            
            event['device_ip'] = '127.0.0.1'
            msgfilling.add_types(event, '_type_str', 'device_ip')
            msgfilling.add_types(event, '_type_ip', 'device_ip')

            event['normalizer'] = self.normalizer
            event['repo'] = self.repo

            if event.get('_normalized_fields'):
                event['_normalized_fields']['source_name'] = self.path
            else:
                event['_normalized_fields'] = {'source_name': self.path}
            msgfilling.add_types(event, '_type_str', 'source_name')

            self.collector_out.send_with_norm_policy_and_repo(event)


def _del_unused_paths(config, cursor_shelve):
    for path in cursor_shelve:
        if path not in config['client_map']:
            del cursor_shelve[path]
    cursor_shelve.sync()


def _read_file_content_changes(config, cursor_shelve, collector_out):
    for path in set(config["client_map"]):
        try:
            handler = FileHandler(path, config, collector_out, cursor_shelve)
        except parsers.InvalidParserException, err:
            log.warn(err)
            continue

def monitor(config, cursor_shelve, zmq_context):
    collector_out = wiring.Wire('collector_out', zmq_context=zmq_context,
                                        conf_path=config.get('wiring_conf_path') or None)

    new_modified_config = {"client_map": {}}

    while True:
        if config['_onreload']():
            old_modified_config = new_modified_config
            new_modified_config = _get_modified_config(config)
            if new_modified_config != old_modified_config:
                update_norm_repo_db(new_modified_config)
                _del_unused_paths(new_modified_config, cursor_shelve)
        _read_file_content_changes(new_modified_config, cursor_shelve, collector_out)
        gevent.sleep(10)

def _diff_config(old_modified_config, new_modified_config):
    old_files = set(old_modified_config["client_map"])
    new_files = set(new_modified_config["client_map"])

    paths_to_remove = old_files - new_files
    paths_to_add = new_files - old_files

    for k, v in old_modified_config["client_map"].iteritems():
        if k in paths_to_remove:
            continue
        if v != new_modified_config["client_map"][k]:
            paths_to_remove.add(k)
            paths_to_add.add(k)

    return paths_to_remove, paths_to_add


def _wait_and_get_db(max_seconds=60):
    start = time.time()
    while True:
        try:
            db = mongo.get_makalu()
            return db
        except pymongo.errors.AutoReconnect:
            now = time.time()
            if now > start + max_seconds:
                raise

            logging.warning("filesystem_colletor; waiting for mongodb")
            time.sleep(1)


def update_norm_repo_db(modified_config):
    db = _wait_and_get_db()

    # col_apps with {'app': 'FileSystemCollector', 'generated': True} are all managed by filesystem_collector
    source = {
        'app': 'FileSystemCollector',
        'generated': True
    }
    db.device.update({'ip': '127.0.0.1'}, {'$pull': {'col_apps': source}}, safe=True)

    sources = []
    for path, prop in modified_config['client_map'].iteritems():
        source = {
            'app': modified_config['app'],
            'sid': '%s|127.0.0.1-%s' % (modified_config['col_type'], path),
            'parser': prop['parser'],
            'normalizer': prop['normalizer'],
            'repo' : prop['repo'],
            'generated': True,
        }
        sources.append(source)
    db.device.update({'ip': '127.0.0.1'}, {'$pushAll': {'col_apps': sources}}, safe=True)
    configgenerator.regenerate_config_files()


def _get_modified_config(config):
    modified_config = {}
    for key, value in config.iteritems():
        if key == 'client_map':
            modified_config[key] = {}
            for glob_path, prop in value.iteritems():
                glob_path = _env_path(glob_path)
                for path in glob.iglob(glob_path):
                    for glob_exclude in prop.get('exclude'):
                        glob_exclude = _env_path(glob_exclude)
                        if fnmatch.fnmatch(path, glob_exclude):
                            break
                    else:
                        if not os.access(path, os.R_OK):
                            log.warn("log file %s not monitored because of permission restrictions", path)
                            continue
                        if os.path.isdir(path):
                            #log.warn("log file %s not monitored because it is a dir", path)
                            continue
                        modified_config[key][path] = {
                            'parser': prop['parser'],
                            'normalizer': prop['normalizer'],
                            'repo': prop['repo'],
                            'charset': prop['charset'],
                            'device_name': prop['device_name'],
                        }
        else:
            modified_config[key] = value

    return modified_config


def _env_path(path):
    return path.replace('$LOGINSPECT_HOME', homing.LOGINSPECT_HOME)
