
"""

"""

import logging
import os

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


log = logging.getLogger(__name__)


class Watcher(FileSystemEventHandler):
    def __init__(self, observer, path, attr):

        self.observer = observer
        self.path = path

        self.cursor = 0
        self.parser = attr['parser']
        self.sid = attr['sid']

        self.is_dir = os.path.isdir(self.path)

        super(Watcher, self).__init__()

        self.schedule()

    def on_any_event(self, event):
        log.debug('event %r', event)

    def on_modified(self, event):
        log.info('modified %s', event.src_path)

        #self.observer.unschedule(self.observed_watch)
        #self.schedule()

        #if event.src_path == self.path:
        #    log.info('modified %s', event.src_path)
        #    self.read()

    def on_deleted(self, event):
        log.info('deleted %s', event.src_path)

        #if event.src_path == self.path:
        #    #log.info('deleted %s', event.src_path)
        #    self.cursor = 0

        #self.observer.stop()
        #self.observer.unschedule(self.observed_watch)
        #self.schedule()
        #self.observer.start()

        #time.sleep(1)
        #self.schedule()

    def schedule(self):
        #parent_dir = self.path
        parent_dir = os.path.dirname(self.path)
        self.observed_watch = self.observer.schedule(self, parent_dir, recursive=True)
        log.debug('scheduled on %s', parent_dir)

    def read(self):
        with open(self.path) as f:
            f.seek(self.cursor)
            logs = f.read()
            self.cursor = f.tell()

        print logs


def monitor(mapper):
    observer = Observer()

    for path, attr in mapper.iteritems():
        watcher = Watcher(observer, path, attr)

    return observer
