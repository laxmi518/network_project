

import os
import time
import logging
import shelve

from pylib import msgfilling, homing, disk, cipher
from libcol.parsers import GetParser, InvalidParserException

#Note to self: try using object composition instead of inheritanche

COL_STORAGE_PATH = homing.home_join("storage/col/")
MEMORY_FILE = "memory.mem"

class Fetcher(object):
    """
    This is an interface from which all the fetchers will be written.
    For each sid in the config, a new instance of this class gets instanciated.
    So the device_ip, device_name etc.
        fields for the given client_map are directly the class members
        of the instance of this class
    """
    def __init__(self, **args):
        """
        Nothing to init
        """
        self.__log_counter = 0
        self.__last_col_ts = int(time.time())

        """
        Args contains sid, client_map and fetcher_runner instance
        """
        #Extract name of the class to make a directory in storage dir
        self._set_fetcher_runner(args["runner"])
        self.set_fields(args)

    def initialize_memory(self, path_name):
        """
        Call this function if memory feature for a fetcher
        is required.

        storage_path = storage/col/<path_name>
        sid_path = storage/col/path_name/<device_ip>
        mem_path = storage/col/path_name/<device_ip>/memory.mem

        These path will be created when memory initialization is done
        """
        #Make path to the storage dir
        self.storage_path = os.path.join(COL_STORAGE_PATH, path_name) + "/"
        #Ensure path creation
        disk.prepare_path(self.storage_path)
        #Make path for this sid
        self.sid_path = os.path.join(self.storage_path, self.device_ip)
        #Make a class variable to use with the pd
        self.mem_path = os.path.join(self.sid_path, MEMORY_FILE)
        #Create memory.mem file at self.mem_path
        disk.prepare_path(self.mem_path)

    def get_decrypted_password(self, enc_pass):
        """
        """
        cipher_obj = cipher.Cipher()
        return cipher_obj.decrypt(enc_pass)

    def _set_fetcher_runner(self, runner):
        self.fetcher_runner = runner

    def _set_parser(self):
        parser = None
        if self.client_map.get("parser"):
            try:
                parser = GetParser(self.client_map["parser"], self.sid, self.charset,
                                   self.client_map.get("regex_pattern"), self.client_map.get("regexparser_name"))
            except InvalidParserException, err:
                logging.warn(err)
        setattr(self, "parser_instance", parser)

    def set_fields(self, args, parser_changed=True):
        self.sid = args["sid"]
        self.client_map = args["client_map"]

        for field, value in self.client_map.iteritems():
            value = str(value) if isinstance(value, unicode) else value
            setattr(self, field, value)

        if not parser_changed:
            return
        self._set_parser()

    def get_client_map(self):
        return self.client_map

    def fetch_job(self):
        """
        To be implemented by Derived Classes
        """
        raise NotImplementedError('Method not implemented %s' % self.fetch_job.__name__)

    def __update_log_counter(self):
        """
        Update the log_counter and col_ts when multiple logs are received within single second
        """
        col_ts = int(time.time())
        if col_ts > self.__last_col_ts:
            self.__last_col_ts = col_ts
            self.__log_counter = 0
        else:
            self.__log_counter += 1

    def add_global_fields(self, event):
        event["normalizer"] = self.normalizer
        event["repo"] = self.repo
        self.prepare_event(event, "collected_at", self.fetcher_runner.get_loginspect_name(), _normalized=False)
        self.prepare_event(event, "col_type", self.fetcher_runner.get_col_type(), _normalized=False)

    def add_mandatory_fields(self, event):
        self.prepare_event(event, "device_ip", self.device_ip, "_type_ip", _normalized=False)
        self.prepare_event(event, "device_ip", self.device_ip, _normalized=False)
        self.prepare_event(event, "device_name", self.device_name, _normalized=False)

    def add_mid(self, event):
        self.__update_log_counter()
        mid_prefix = '%s|%s|%s|%d|' % (self.fetcher_runner.get_loginspect_name(), \
                                         self.fetcher_runner.get_col_type(), \
                                            self.device_ip, self.__last_col_ts)

        event['mid'] = mid_prefix + "%d" % self.__log_counter

        event['_counter'] = self.__log_counter
        self.prepare_event(event, "col_ts", self.__last_col_ts, "_type_num", _normalized=False)

    def add_extra_field_values(self, event):
        """
        """
        self.add_global_fields(event)
        self.add_mandatory_fields(event)
        self.add_mid(event)

    def add_event(self, event):
        self.add_extra_field_values(event)
        self.fetcher_runner.get_event_handler().add_event(event)

    def prepare_event(self, event, field, value, _type="_type_str", _normalized=True):
        """
        Update event with field/value and msgfilling done
        """
        if _normalized:
            if event.get("_normalized_fields"):
                event["_normalized_fields"][field] = value
            else:
                event["_normalized_fields"] = dict(field=value)
        else:
            event[field] = value
        msgfilling.add_types(event, _type, field)

    def prepare_msgfilling(self, event, field, _type="_type_str"):
        """
        Update the event with msgfilling the given field with the given type
        """
        msgfilling.add_types(event, _type, field)

    def memorize(self, value, key):
        """
        Provides function for storing key/value.
        If any job wants to store its info to disk, then use this function
        Use cases:
            rss_fetcher -> storing last-modified, etag
            opsec_fetcher -> storing starttime, loc
        Storing should be done because when service restarts, the values stored
        in memory will get lost. So to resume the service state, values should be constantly
        wirttn to disk.
        """
        self.pdict = shelve.open(self.mem_path)
        self.pdict[key] = value
        self.pdict.close()

    def recall(self, key):
        """
        To recall the stored value from key stored
        """
        self.pdict = shelve.open(self.mem_path)
        value = self.pdict[key]
        self.pdict.close()
        return value

    def get_storage_path(self):
        return self.storage_path

    def get_mem_path(self):
        return self.mem_path
