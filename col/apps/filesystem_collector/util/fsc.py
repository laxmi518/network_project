import pyinotify

from pylib import logger

log = logger.getLogger(__name__)


class EventHandler(pyinotify.ProcessEvent):
    def process_IN_CREATE(self, event):
        log.debug('created: %s', event.pathname)

    def process_IN_DELETE(self, event):
        log.debug('deleted: %s', event.pathname)

    def process_IN_MODIFY(self, event):
        log.debug('modified: %s', event.pathname)


wm = pyinotify.WatchManager()
handler = EventHandler()

mask = pyinotify.IN_MODIFY

notifier = pyinotify.Notifier(wm, handler)

wdd = wm.add_watch('/tmp', mask, rec=True)

        
