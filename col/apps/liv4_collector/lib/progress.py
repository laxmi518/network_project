
import time
import gevent
import reader
from pylib import wiring
import logging

def _calculate_time_left(total_bytes, completed_bytes, rate):
    remaining_bytes = total_bytes - completed_bytes
    time_left = remaining_bytes / rate
    return time_left


def _get_human_time(sec):
    units = [("sec", 60), ("min", 60), ("hr", 24), ("day", 1)]
    for unit, whole in units:
        ht = float(sec) / whole
        if ht < 1:
            break
        sec = ht
    return sec, unit


def _get_human_size(bytes):
    units = ["B", "KB", "MB", "GB", "TB"]
    for unit in units:
        hs = bytes / 1024.
        if hs < 1:
            break
        bytes = hs
    return bytes, unit


def responder(estimator, zmq_context, repo_name):
    responder = wiring.Wire('liv4_collector_progress_reply',
            zmq_context=zmq_context, repo_name=repo_name)
    start_time = time.time()
    while True:
        request = responder.recv()
        while True:
            est_byte_size = float(estimator.get_est_total_bytes())
            completed_bytes = reader.BYTES_READ
            completed_msgs = reader.COUNTER

            completed_percent = completed_bytes / est_byte_size * 100
            if completed_percent < 0.1:
                logging.warn("completed_bytes=%s, completed_msgs=%s, est_byte_size=%s, completed_percent=%s",
                                completed_bytes, completed_msgs, est_byte_size, completed_percent)
                gevent.sleep(2)
            elif completed_percent > 100:
                completed_percent = 100
            else:
                break

        duration = time.time() - start_time
        rate_bytes = completed_bytes / duration
        rate_msgs = completed_msgs / duration
        rate_unit = _get_human_size(rate_bytes)

        time_left = _calculate_time_left(est_byte_size, completed_bytes, rate_bytes)
        if int(time_left) == 0 and completed_percent != 100:
            time_left = 1
        elif time_left < 0:
            time_left = 0

        human_time = _get_human_time(time_left)
        response = dict(percent_completed="%.1f%%" % (completed_percent),
                        rate="%.1f %s/sec (%d msg/sec)" % (rate_unit[0], rate_unit[1], rate_msgs),
                        time_left="%.1f %s" % tuple(human_time),
                        )
        responder.send(response)
