
import os
import time
import logging
import re
from collections import defaultdict
import shutil
import gevent
from pylib.wiring import gevent_zmq as zmq

from pylib import wiring, msgfilling, timing
from lib import reader, progress, device_router

MAX_SPEED = 1000
ip_re = re.compile(r"(?:\d{0,3}\.){3}\d{0,3}")

def start(config, basedir, db, is_compressed_file_present, updater):
    logging.warn("transforming logs")
    repo = config["repo"]
    zmq_context = zmq.Context()

    col_out = wiring.Wire('collector_out', zmq_context=zmq_context)
    grouped_files, ips, estimator = get_grouped_files(basedir)
    device_router.add(db, ips, config)

    updater.update_stat('running')

    gevent.spawn_link_exception(progress.responder, estimator, zmq_context, repo)

    gevent.sleep(2)  # allow config-regeneration to complete successfully called by device_router.add
    transform(grouped_files, col_out, estimator, config, updater)

    # delete uploaded compressed file and extracted dir
    if is_compressed_file_present:
        dir_path = os.path.dirname(basedir)
        if os.path.exists(dir_path):
            shutil.rmtree(dir_path)

    # stopping immediately will remove sid in norm_front and store_handler
    # so sleep 1 hour, because events may be in queue of norm_front and store_handler
    time.sleep(3600)
    updater.update_stat('finished')


def transform(grouped_files, col_out, estimator, config, updater):
    last_ts = 0
    last_path = ""

    recorded_col_ts = updater.get_col_ts()
    recorded_col_ts_human = time.strftime("%Y%m%d %H:%M:%S", time.localtime(recorded_col_ts))
    start = time.time()

    throttler = timing.speed_throttler(MAX_SPEED)
    for day, filepaths in grouped_files:
        if time.mktime(time.strptime(str(day), "%Y%m%d")) + 86400 <= recorded_col_ts:
            logging.warning("skipping logs for day %d, last tracked col_ts is %d (%s)",
                    day, recorded_col_ts, recorded_col_ts_human)
            continue
        for col_ts, event, path in reader.event_generator_by_time(filepaths, config):
            throttler.next()
            if col_ts < recorded_col_ts:
                continue
            if col_ts < last_ts:
                assert path == last_path, "path=%s; last_path=%s" % (path, last_path)
                logging.warning("outdated msg with col_ts=%s, last_ts=%s; path=%s", col_ts, last_ts, path)
            elif col_ts > last_ts:
                last_ts = col_ts
                counter = 0
                # save col_ts every col_ts minute
                if col_ts % 60 == 0:
                    updater.save_col_ts(col_ts)
                gevent.sleep()

            counter += 1
            last_path = path

            event["mid"] = event["mid"] % counter
            event["_counter"] = counter
            event["collected_at"] = config["loginspect_name"]
            
            msgfilling.add_types(event, '_type_str', 'collected_at')
            
            event['normalizer'] = config['normalizer']
            event['repo'] = config['repo']
            col_out.send_with_norm_policy_and_repo(event)

        estimator.modify(filepaths, add=False)

    duration = time.time() - start
    total = reader.COUNTER
    logging.warning("%d messages processed in %d sec, @ %d msg/sec, @ %d bytes/sec", total, duration, total/duration, reader.BYTES_READ/duration)

def get_grouped_files(logdir):
    """Returns list of files grouped by day in increasing order
    eg. [(200901, ["/storage/chroot/logs/IP/192.168.2.1/200901/20090101.gz",
                   "/storage/chroot/logs/IP/192.168.2.2/200901/20090101.gz"])]
    """
    estimator = RemainingBytesEstimator()
    log_paths = defaultdict(list)
    ip_set = set()

    valid_files_re = re.compile(r'^(\d{8})(.snmp)?(.gz)?$')
    for root, dirs, files in os.walk(logdir):
        _add_ips(dirs, ip_set)
        for filename in files:
            filepath = os.path.join(root, filename)

            is_valid = valid_files_re.match(filename)
            if not is_valid:
                logging.warn("skipping %r", filepath)
                continue

            log_paths[int(is_valid.group(1))].append(filepath)
            estimator.modify(filepath, add=True)

    log_paths = sorted(log_paths.iteritems())
    return log_paths, ip_set, estimator


class RemainingBytesEstimator(object):
    def __init__(self):
        self.compressed_bytes = 0
        self.uncompressed_bytes = 0
        self.compression_ratio = 0.1
        self.processed_bytes = 0

        # for calculating compression ratio
        self.compressed_filesize = 0
        self.uncompressed_filesize = 0

    def modify(self, filepaths, add=True):
        if add == True:
            operator = '__add__'
        else:
            operator = '__sub__'
            self.processed_bytes = reader.BYTES_READ

        if isinstance(filepaths, basestring):
            filepaths = [filepaths]

        for filepath in filepaths:
            bytes = os.path.getsize(filepath)
            if filepath.endswith('.gz'):
                self.compressed_bytes = getattr(self.compressed_bytes, operator)(bytes)
                if add == False:
                    self.compressed_filesize += bytes
            else:
                self.uncompressed_bytes = getattr(self.uncompressed_bytes, operator)(bytes)
                if add == False:
                    self.uncompressed_filesize += bytes

        if add == False:
            decompressed_filesize = reader.BYTES_READ - self.uncompressed_filesize
            if decompressed_filesize > 0:
                self.compression_ratio = self.compressed_filesize / float(decompressed_filesize)

    def get_est_total_bytes(self):
        return self.compressed_bytes / self.compression_ratio + self.uncompressed_bytes + self.processed_bytes


def _add_ips(dirs, ip_set):
    for ip in ip_re.findall(" ".join(dirs)):
        ip_set.add(ip)
