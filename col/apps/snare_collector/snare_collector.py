#!/usr/bin/env python

"""
Snare Collecter based on the gevent. It collects the snare data,
parses out the log time from each of the log message and sends them to the upper
storage layer.
"""

import sys
import time

from gevent.server import StreamServer
from gevent import socket
from pylib.wiring import gevent_zmq as zmq

from libcol.parsers import GetParser, InvalidParserException
from libcol import config_reader
from pylib import conf, homing, logger, wiring, msgfilling, inet, cidr


log = logger.getLogger(__name__)

def _parse_args():
    options, config = conf.parse_config()
    return config


def _get_sid_parser(config, config_ip, profile):
    sid = '%s|%s' % (config['col_type'], config_ip)

    parser_name = profile.get('parser')
    if parser_name is None:
        log.warn("parser not found for sid=%s", sid)
        return sid, None

    charset = profile.get('charset')

    try:
        parser = GetParser(parser_name, sid, charset,
                profile.get('regex_pattern'), profile.get('regexparser_name'))
    except InvalidParserException, err:
        log.warn(err)
        return sid, None

    return sid, parser


def _handle_data(data, sid, parser, snare_out, device_name, ip, collected_at):
    snare_out.start_benchmarker_processing()

    global LAST_COL_TS
    global LOG_COUNTER

    col_ts = int(time.time())
    if col_ts > LAST_COL_TS:
        LAST_COL_TS = col_ts
        LOG_COUNTER = 0

    mid_prefix = '%s|%s|%d|' % (collected_at, sid, col_ts)
    parser.write(data)
    
    #log.info("checking data: %s", data)
    
    for event in parser:
        LOG_COUNTER += 1
        event['mid'] = mid_prefix + "%d" % LOG_COUNTER
        event['device_name'] = device_name
        event['device_ip'] = ip
        event['collected_at'] = collected_at
        msgfilling.add_types(event, '_type_str', 'device_name collected_at')
        msgfilling.add_types(event, '_type_ip', 'device_ip')
        snare_out.send_with_mid(event)

def _get_profile_info(addr, config):
    ip = inet.get_ip(addr)
    config_ip = config_reader.get_config_ip(ip, config)
    if not config_ip:
        return
    profile = config["client_map"].get(config_ip)
    sid, parser = _get_sid_parser(config, config_ip, profile)
    if not parser:
        return

    device_name = config['client_map'][config_ip]["device_name"]
    collected_at = config["loginspect_name"]
    
    return ip, sid, parser, device_name, collected_at


def _handle_tcp_client(sock, addr, config, snare_out):
    log.debug("tcp collector; %s connected;" % str(addr))
    ip = inet.get_ip(addr)
    
    try:
        # config_ip can be changed if any device whose cidr belong to this ip is added
        old_config_ips = None
        old_parser_name = None
        old_charset = None
        parser = None
        
        while True:
            config_ips = config["client_map"].keys()
            if config_ips != old_config_ips:
                old_config_ips = config_ips
                config_ip = config_reader.get_config_ip(ip, config)
                if not config_ip:
                    return
                sid = '%s|%s' % (config['col_type'], config_ip)
            
            profile = config["client_map"][config_ip]
            parser_name = profile["parser"]
            charset = profile["charset"]
            if parser_name != old_parser_name or charset != old_charset:
                if old_parser_name and old_charset:
                    log.warn('settings changed for ip %s, old_parser=%s, new_parser=%s, '
                        'old_charset=%s, new_charset=%s', ip, old_parser_name, parser_name,
                        old_charset, charset)
                old_parser_name = parser_name
                old_charset = charset
                new_parser = GetParser(parser_name, sid, charset,
                                   profile.get('regex_pattern'), profile.get('regexparser_name'))
                if parser and parser.buffer:
                    new_parser.write(parser.buffer)
                parser = new_parser
            
            data = sock.recv(4096)
            log.debug("tcp collector; ip=%s, got data=%s", config_ip, data)
            if not data:
                break
            device_name = profile["device_name"]
            collected_at = config["loginspect_name"]
            
            _handle_data(data, sid, parser, snare_out, device_name, ip, collected_at)
    finally:
        sock.close()


def start_tcp_server(port, config, snare_out):
    log.info("Snare Collector; listening tcp server at %s", port)

    def handler(sock, addr):
        return _handle_tcp_client(sock, addr, config, snare_out)

    listener = _create_listener(port)
    tcp_server = StreamServer(listener, handler)
    tcp_server.start()


def _create_listener(port, backlog=256):
    """Creates an IPv6-capable listener.
    """
    # The creating of the socket is similar
    # to gevent.baseserver._tcp_listener().
    sock, sockaddr = inet.create_external_address(port)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(sockaddr)
    sock.listen(backlog)
    sock.setblocking(0)
    return sock


def start_udp_server(port, config, snare_out):
    log.info("Snare Collector; listening udp server at %s", port)
    sock, sockaddr = inet.create_external_address(port, socket.SOCK_DGRAM,
            use_gevent=True)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Asking for 8MB for receive buffer.
    if not sys.platform == 'darwin':
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8388608)

    sock.bind(sockaddr)

    while True:
        data, addr = sock.recvfrom(9216)
        if not data:
            continue
        log.debug('udp collector; from ip=%s, got msg=%s;', addr, data)

        profile_info = _get_profile_info(addr, config)
        if profile_info is not None:
            ip, sid, parser, device_name, collected_at = profile_info
        else:
            continue

        if data[-1] != '\n':
            data += '\n'

        _handle_data(data, sid, parser, snare_out, device_name, ip, collected_at)


# globals used across the green threads
LAST_COL_TS = 0
LOG_COUNTER = 0


def main():
    config = _parse_args()

    port = config["port"]
    
    zmq_context = zmq.Context()

    snare_out = wiring.Wire('collector_out', zmq_context=zmq_context,
                                    conf_path=config.get('wiring_conf_path') or None)

    start_tcp_server(port, config, snare_out)
    
    start_udp_server(port, config, snare_out)


if __name__ == '__main__':
    main()
