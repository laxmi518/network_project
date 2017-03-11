import logging
import gevent

from pylib.wiring import gevent_zmq as zmq

from pylib import wiring, conf

from job_generator import JobGenerator
from event_handler import EventHandler

def _create_context(config):
    """
        Creates wiring context for sending events to normalizer
    """
    zmq_context = zmq.Context()
    return wiring.Wire("collector_out", zmq_context=zmq_context,
                                    conf_path=config.get("wiring_conf_path"))

def _parse_args():
    """
        Parses config and return
    """
    options, app_config = conf.parse_config()
    return app_config

class FetcherRunner(object):

    def __init__(self):
        """
        """

        self.config = _parse_args()
        self.context = _create_context(self.config)

        self.set_debug_mode(False)

    def register_fetcher(self, fetcher_handle):
        self.fetcher_handle = fetcher_handle

    def set_debug_mode(self, mode=True):
        self.debug = mode

    def start(self):
        self.event_handler = EventHandler(self)
        self.event_handler.register_callback(self.context.send_with_norm_policy_and_repo)

        job_generator = JobGenerator(self)

        try:
            joblet = gevent.spawn_link_exception(job_generator.job_updater)
            eventlet = gevent.spawn_link_exception(self.event_handler.event_queue_handler)
            gevent.joinall([joblet, eventlet])
        except gevent.GreenletExit, err:
            logging.warn(err)
        except Exception, err:
            logging.warn(err)


        """
        Getter Functions
        """
    def get_debug_mode(self):
        return self.debug

    def get_event_handler(self):
        return self.event_handler

    def get_fetcher_handle(self):
        return self.fetcher_handle

    def get_wiring_context(self):
        return self.context

    def get_config(self):
        return self.config

    def get_loginspect_name(self):
        return self.config["loginspect_name"]

    def get_col_type(self):
        return self.config["col_type"]

    def get_field_value_from_config(self, field_name):
        return self.config.get(field_name)
