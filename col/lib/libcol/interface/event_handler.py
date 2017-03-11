import logging
import gevent
import gevent.queue

class EventHandler(object):

    def __init__(self, fetcher_runner):
        """
        Initialize the Event Handler.
       """
        self.fetcher_runner = fetcher_runner
        self.__event_queue = gevent.queue.JoinableQueue()

    def register_callback(self, cbf):
        """
        cbf is the call back function that will be called
        when the __event_queue receives an event
        """
        self.__cbf = cbf

    def event_queue_handler(self):
        """
        Wait in an non-blocking loop for an event
        When one is received, the callback function __cbf is called with the event
        """
        while True:
            event = self.__event_queue.get()
            try:
                if self.fetcher_runner.get_debug_mode() == True:
                    logging.warn(event)
                self.__cbf(event)
            finally:
                self.__event_queue.task_done()

    def add_event(self, event):
        """
        Interface for adding an event to the queue
        """
        self.__event_queue.put(event)

