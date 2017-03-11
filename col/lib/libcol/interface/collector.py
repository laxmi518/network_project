
from gevent import monkey
monkey.patch_all()

import os
import sys
import time
import gevent
import logging
import gevent.queue
from gevent import socket
from pylib.wiring import gevent_zmq as zmq
from pyftpdlib import ftpserver
from gevent.server import StreamServer

from libcol import config_reader
from collections import defaultdict
from pylib import conf, msgfilling, wiring, inet, homing, textual, disk, cipher
from libcol import config_reader
from libcol.collectors import shelves
from libcol.parsers import GetParser, InvalidParserException

ftpserver.log = lambda msg: logging.info(msg)
ftpserver.logline = lambda msg: logging.debug(msg)


class CollectorInterface(object):

    def __init__(self, collector_name):
        """
        Initialize the collector parameters
        """
        self.__collector_name = collector_name
        self.__config = self.__parse_args()

        wire_name = self.__config.get("output_wire") or "collector_out"
        self.__collector_out = self.__create_context(wire_name)

        self.__event_queue = gevent.queue.JoinableQueue()

        """
        This mem variable is used to store parameters if the result of one fetch is,
        required by the result of next fetch
        """
        self.__mem = defaultdict(dict)

        """
        This is used for logging the events being sent
        """
        self.debug_mode = False

        self.__log_counter = 0
        self.__last_col_ts = int(time.time())

        """
        Initialize server ON variables to OFF
        """
        self.__tcp_server_on = False
        self.__tcp_ssl_server_on = False
        self.__udp_server_on = False
        self.__ftp_server_on = False

        """
        Load Ports for various protocols
        """
        self.__tcp_port = self.__config["port"]
        self.__udp_port = self.__config["port"]
        self.__tcp_ssl_port = self.__config.get("ssl_port") or None
        self.__ftp_port = self.__config["port"]

        """
        Load SSL certificates
        """
        if self.__tcp_ssl_port:
            ssl_args = homing.homize(self.__config["ssl_args"])
            self.__key_file = ssl_args["keyfile"]
            self.__cert_file = ssl_args["certfile"]
        
        """
        """
        self.__ftp_parser_name_only = False

    def get_decrypted_password(self, enc_pass):
        """
        """
        cipher_obj = cipher.Cipher()
        return cipher_obj.decrypt(enc_pass)

    def __create_context(self, wire_name):
        """
        Creates wiring context for sending events to normalizer
        """
        zmq_context = zmq.Context()
        collector_out = wiring.Wire(wire_name, zmq_context=zmq_context,
                                        conf_path=self.__config.get('wiring_conf_path', None))
        return collector_out

    def __parse_args(self):
        """
        Parses config and return
        """
        options, app_config = conf.parse_config()
        return app_config

    @property
    def collector_name(self):
        return self.__collector_name

    @property
    def config(self):
        return self.__config

    @property
    def mem(self):
        return self.__mem

    def __get_sid_parser(self, config_ip, profile):
        sid = "%s|%s" % (self.__config["col_type"], config_ip)

        parser_name = profile.get("parser")
        charset = profile.get("charset")

        parser = None
        if parser_name:
            try:
                parser = GetParser(parser_name, sid, charset,
                                   profile.get("regex_pattern"), profile.get("regexparser_name"))
            except InvalidParserException, err:
                logging.warn(err)

        return sid, parser

    def __get_profile_info(self, addr):
        ip = inet.get_ip(addr)
        config_ip = config_reader.get_config_ip(ip, self.__config)
        if not config_ip:
            return

        profile = self.__config["client_map"][config_ip]
        sid, parser = self.__get_sid_parser(config_ip, profile)
        device_name = self.__config["client_map"][config_ip]["device_name"]
        
        normalizer = self.__config["client_map"][config_ip]["normalizer"]
        repo = self.__config["client_map"][config_ip]["repo"]

        return ip, sid, parser, device_name, normalizer, repo

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

    def add_extra_field_values(self, event, dev_config):
        """
        Add device_ip, device_name, logpoint_name, col_type, mid, col_ts, collected_at
        """
        device_name = dev_config["device_name"]
        loginspect_name = self.__config["loginspect_name"]
        col_type = self.__config["col_type"]

        self.__update_log_counter()
        mid_prefix = "%s|%s|%d|" % (loginspect_name, dev_config["sid"], self.__last_col_ts)

        event["mid"] = mid_prefix + "%d" % self.__log_counter
        
        event["normalizer"] = dev_config["normalizer"]
        event["repo"] = dev_config["repo"]
        
        self.prepare_event(event, "col_type", col_type, _normalized=False)
        self.prepare_event(event, "device_ip", dev_config["ip"], _normalized=False)
        self.prepare_event(event, "device_ip", dev_config["ip"], "_type_ip", _normalized=False)
        self.prepare_event(event, "device_name", device_name, _normalized=False)
        self.prepare_event(event, "collected_at", loginspect_name, _normalized=False)
        
        self.prepare_event(event, "col_ts", self.__last_col_ts, "_type_num", _normalized=False)
        event["_counter"] = self.__log_counter

    def add_event(self, event, dev_config):
        """
        Add event to queue
        """
        self.add_extra_field_values(event, dev_config)
        self.__event_queue.put(event)

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
    
    def prepare_msgfilling(self, event, _type, msg_str):
        """
        msgfilling multiple fields at once
        """
        msgfilling.add_types(event, _type, msg_str)
        
    def _create_listener(self, port, backlog=256):
        """
        Creates an IPv6-capable listener.
        """
        # The creating of the socket is similar
        # to gevent.baseserver._tcp_listener().
        sock, sockaddr = inet.create_external_address(port)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(sockaddr)
        sock.listen(backlog)
        sock.setblocking(0)
        return sock

    def handle_tcp_data(self, sock, addr):
        """
        This is the handle for tcp server. Must be implemeted by the deriving class.
        """
        raise NotImplementedError("Method not implemented %s" % self.handle_tcp_data.__name__)

    def handle_udp_data(self, data, **config):
        """
        This is the handle for udp server. Must be implemeted by the deriving class.
        """
        raise NotImplementedError("Method not implemented %s" % self.handle_udp_data.__name__)

    def handle_tcp_ssl_data(self, data, **config):
        """
        This is the handle for tcp ssl server. Must be implemeted by the deriving class.
        """
        raise NotImplementedError("Method not implemented %s" % self.handle_tcp_ssl_data.__name__)

    def handle_file_received(self, data, config):
        """
        This the handle for file received in ftp server. Must be implemeted by the deriving class.
        """
        raise NotImplementedError("Method not implemented %s" % self.handle_file_received.__name__)

    def __handle_tcp_client(self, sock, addr, protocol="TCP"):
        """
        """
        logging.debug("tcp collector; %s connected;" % str(addr))
        ip = inet.get_ip(addr)

        try:
            # config_ip can be changed if any device whose cidr belong to this ip is added
            old_config_ips = None
            old_parser_name = None
            old_charset = None
            parser = None

            while True:
                config_ips = self.__config["client_map"].keys()
                if config_ips != old_config_ips:
                    old_config_ips = config_ips
                    config_ip = config_reader.get_config_ip(ip, self.__config)
                    if not config_ip:
                        return
                    sid = "%s|%s" % (self.__config["col_type"], config_ip)

                profile = self.__config["client_map"][config_ip]
                parser_name = profile.get("parser") or None
                charset = profile["charset"]
                if parser_name and (parser_name != old_parser_name or charset != old_charset):
                    if old_parser_name and old_charset:
                        logging.warn("settings changed for ip %s, old_parser=%s, new_parser=%s, "
                                 "old_charset=%s, new_charset=%s", ip, old_parser_name, parser_name,
                                 old_charset, charset)
                    old_parser_name = parser_name
                    old_charset = charset
                    new_parser = GetParser(parser_name, sid, charset,
                                           profile.get('regex_pattern'), profile.get('regexparser_name'))
                    if parser and parser.buffer:
                        new_parser.write(parser.buffer)
                    parser = new_parser

                data = sock.recv(4096)
                if not data:
                    break

                if protocol == "SSL":
                    self.handle_tcp_ssl_data(data, ip=ip, sid=sid, parser=parser, device_name=profile["device_name"],
                                             normalizer=profile["normalizer"], repo=profile["repo"])
                else:
                    self.handle_tcp_data(data, ip=ip, sid=sid, parser=parser, device_name=profile["device_name"],
                                         normalizer=profile["normalizer"], repo=profile["repo"])
        except Exception, e:
            logging.warn('Exception receiving message: %s' % str(e))
        finally:
            sock.close()

    def __start_tcp_server(self):
        """
        Start TCP Server
        """
        logging.info("%s Collector; listening tcp server at %s", self.__collector_name, self.__tcp_port)

        def handler(sock, addr):
            return self.__handle_tcp_client(sock, addr)

        listener = self._create_listener(self.__tcp_port)
        tcp_server = StreamServer(listener, handler)
        tcp_server.serve_forever()

    def __start_udp_server(self):
        """
        Start UDP Server
        """
        logging.info("%s Collector; listening udp server at %s", self.__collector_name, self.__udp_port)

        sock, sockaddr = inet.create_external_address(self.__udp_port, socket.SOCK_DGRAM,
                                                      use_gevent=True)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Asking for 8MB for receive buffer.
        if not sys.platform == "darwin":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8388608)

        sock.bind(sockaddr)

        while True:
            data, addr = sock.recvfrom(9216)
            if not data:
                continue
            logging.debug("udp collector; from ip=%s, got msg=%s;", addr, data)

            profile_info = self.__get_profile_info(addr)
            if profile_info is not None:
                ip, sid, parser, device_name, normalizer, repo = profile_info
            else:
                continue

            self.handle_udp_data(data, ip=ip, sid=sid, parser=parser, device_name=device_name,
                                 normalizer=normalizer, repo=repo)

    def __start_tcp_ssl_server(self):
        """
        Start TCP/SSL Server
        """
        logging.info("%s Collector; listening tcp ssl server at %s", self.__collector_name, self.__tcp_ssl_port)

        def handler(sock, addr):
            return self.__handle_tcp_client(sock, addr, "SSL")

        listener = self._create_listener(self.__tcp_ssl_port)
        tcp_server = StreamServer(listener, handler, keyfile=self.__key_file, certfile=self.__cert_file)
        tcp_server.serve_forever()

    def make_inet6_compatible(self, ftpserver, port):
        """
        Make ftpserver ipv6 compatible
        """
        if ftpserver.socket:
            ftpserver.socket.close()

        # create_socket in FTPServer
        sock, sockaddr = inet.create_external_address(port)
        sock.setblocking(0)
        ftpserver.set_socket(sock)

        ftpserver.set_reuse_addr()
        ftpserver.bind(sockaddr)
        ftpserver.listen(5)

    def __start_ftp_server(outself):
        """
        Start FTP Server
        """
        logging.info("%s Collector; listening ftp server at %s", outself.__collector_name, outself.__ftp_port)

        address = ("0.0.0.0", outself.__ftp_port)

        basedir = outself.__config["basedir"].replace("$LOGINSPECT_HOME", homing.LOGINSPECT_HOME)
        db_file = os.path.join(basedir, "checksums.pdict")
        
        class FTPHandler(ftpserver.FTPHandler):

            def __init__(self, conn, server, config, db_file, parser_name_only):
                ftpserver.FTPHandler.__init__(self, conn, server)

                self.config = config = textual.utf8(config)
                self.ip = inet.get_ip(conn.getpeername())
                self.db_file = db_file
                self.parser_name_only = parser_name_only
                self.config_ip = config_reader.get_config_ip(self.ip, config)
                if not self.config_ip:
                    conn.send("Please add your device %s to ftp_collector in LogInspect to send logs.\n" % self.ip)
                    self.close()
                    return

                self.profiles = config["client_map"][self.config_ip]

                self.authorizer = ftpserver.DummyAuthorizer()

                for user, profile in self.profiles.iteritems():
                    password = outself.get_decrypted_password(profile["password"])

                    permission = profile["permission"]

                    basedir = config["basedir"].replace("$LOGINSPECT_HOME", homing.LOGINSPECT_HOME)
                    home = profile["home"].lstrip("/")  # let home not be absolute path

                    user_home = os.path.join(basedir, home)
                    disk.prepare_path(user_home + "/")

                    self.authorizer.add_user(user, password, user_home, permission)

            def on_file_received(self, localfile):
                logging.debug("file transfer; completed")

                profile = self.config["client_map"][self.config_ip][self.username]
                sid = profile["sid"]
                profile["device_ip"] = self.ip

                vc = shelves.VersionChecker(self.db_file, sid, localfile)
                cursor = vc.get_old_cursor(localfile)
                if cursor < 0:
                    return

                profile["time_received"] = time.time()
                profile["cursor"] = cursor

                profile["wiring_conf_path"] = self.config.get("wiring_conf_path") or None
                profile["col_type"] = self.config["col_type"]
                
                if not self.parser_name_only:
                    parser_name = profile.get("parser")
                    charset = profile.get("charset")

                    parser = None
                    if parser_name:
                        try:
                            parser = GetParser(parser_name, sid, charset,
                                               profile.get("regex_pattern"), profile.get("regexparser_name"))
                        except InvalidParserException, err:
                            logging.warn(err)
                    profile["parser"] = parser

                outself.handle_file_received(localfile, profile)

        ftpd = ftpserver.FTPServer(address, 
                                   lambda conn, server:
                                   FTPHandler(conn, server,
                                              outself.__config, db_file, outself.__ftp_parser_name_only))

        outself.make_inet6_compatible(ftpd, outself.__ftp_port)
        ftpd.max_cons = 256
        ftpd.max_cons_per_ip = 5
        ftpd.serve_forever()

    """
    Turn flags on to start desired servers
    """
    def turn_tcp_server_on(self):
        self.__tcp_server_on = True

    def turn_tcp_ssl_server_on(self):
        self.__tcp_ssl_server_on = True

    def turn_udp_server_on(self):
        self.__udp_server_on = True

    def turn_ftp_server_on(self, parser_name_only=False):
        self.__ftp_server_on = True
        self.__ftp_parser_name_only = parser_name_only

    def __event_queue_handler(self):
        """
            Gets an event from the event_queue, Sends it to the upper layer,
            Proceed to the other event. If no event are currently in the event_queue,
            it waits in a non-blocking loop.
        """
        while True:
            event = self.__event_queue.get()
            try:
                if self.debug_mode:
                    logging.warn(event)
                self.__collector_out.send_with_norm_policy_and_repo(event)
            finally:
                self.__event_queue.task_done()

    def __spawn_servers(self):
        """
        Spawn the servers on indivisual greenlets whose turn_on FLAGS are ON
        Return the greenlet objects
        """
        servers_started = []
        server_greenlets = []

        if self.__tcp_server_on:
            servers_started.append("TCP SERVER")
            servlet_tcp = gevent.spawn_link_exception(self.__start_tcp_server)
            server_greenlets.append(servlet_tcp)

        if self.__tcp_ssl_server_on:
            if self.__tcp_ssl_port:
                servers_started.append("TCP/SSL SERVER")
                servlet_tcp_ssl = gevent.spawn_link_exception(self.__start_tcp_ssl_server)
                server_greenlets.append(servlet_tcp_ssl)
            else:
                logging.error("SSL port not defined in config file")

        if self.__udp_server_on:
            servers_started.append("UDP SERVER")
            servlet_udp = gevent.spawn_link_exception(self.__start_udp_server)
            server_greenlets.append(servlet_udp)

        if self.__ftp_server_on:
            servers_started.append("FTP SERVER")
            servlet_ftp = gevent.spawn_link_exception(self.__start_ftp_server)
            server_greenlets.append(servlet_ftp)

        if not servers_started:
            logging.warn("No Servers Started! Was that what you wanted to do?")
            logging.warn("Use e.g. turn_tcp_server_on() to start tcp server")
        else:
            logging.warn("Started Servers: %s", ", ".join(servers_started))

        return server_greenlets

    def start(self):
        """
        Start event queue handler and different protocol socket listeners
        """
        try:
            servlets = self.__spawn_servers()
            eventlet = gevent.spawn_link_exception(self.__event_queue_handler)
            servlets.extend([eventlet])
            gevent.joinall(servlets)
        except gevent.GreenletExit, err:
            logging.warn(err)
        except Exception, err:
            logging.warn(err)
