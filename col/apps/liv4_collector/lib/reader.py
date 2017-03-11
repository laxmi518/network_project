
import gzip
import heapq
import logging

from libcol.parsers.LIv4Parser import LIv4Parser
from libcol.parsers.LIv4SNMPParser import LIv4SNMPParser

BYTES_READ = 0
COUNTER = 0

def file_events_generator(path, parser):
    global BYTES_READ, COUNTER

    if path.endswith('.gz'):
        fp = gzip.open(path, "rb")
    else:
        fp = open(path, "rb", 1024)

    while True:
        data = fp.read(1024)
        if not data:
            fp.close()
            return
        parser.write(data)
        for event in parser:
            COUNTER += 1
            yield event
        BYTES_READ += len(data)


class EventReader:
    def __init__(self, path, config):
        self.path = path
        if path.endswith(".snmp") or path.endswith(".snmp.gz"):
            parser = LIv4SNMPParser(config["col_type"], config["loginspect_name"], config["charset"])
        else:
            parser = LIv4Parser(config["col_type"], config["loginspect_name"], config["charset"])
        self.generator = file_events_generator(path, parser)

    def next(self):
        return self.generator.next()


def event_generator_by_time(filepaths, config):
    heap = []
    for filepath in filepaths:
        er = EventReader(filepath, config)
        _push_event_to_heap(er, heap)

    while True:
        try:
            col_ts, event, er = heapq.heappop(heap)
        except IndexError:
            return

        _push_event_to_heap(er, heap)
        yield col_ts, event, er.path


def _push_event_to_heap(er, heap):
    try:
        event = er.next()
        heapq.heappush(heap, (event["col_ts"], event, er))
    except StopIteration:
        pass
    except KeyError:
        logging.warn("col_ts not present in the event:%r", event["msg"])
        _push_event_to_heap(er, heap)
