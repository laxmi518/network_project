"""
This module helps with creating of IPv4 and IPv6 sockets.
A returned socket address can be
(ipv4, port) or
(ipv6, port, flow_info, scope_id).
"""

from socket import SOCK_STREAM, AI_PASSIVE
import socket as orig_socket
#import gevent.socket


def create_local_address(port, socktype=SOCK_STREAM, use_gevent=False):
    """Returns (socket, socket_address) for a localhost port.
    """
    return create_address(None, port, socktype, use_gevent)


def create_external_address(port, socktype=SOCK_STREAM, use_gevent=False):
    """Returns (socket, socket_address) for an externally visible port.
    """
    return create_address(None, port, socktype, flags=AI_PASSIVE,
            use_gevent=use_gevent)


def create_address(host, port, socktype=SOCK_STREAM, flags=0,
        use_gevent=False):
    """Returns (socket, socket_address) with the specified host and port.
    """
#    if use_gevent:
#        socket = gevent.socket
#    else:
#        socket = orig_socket
    socket = orig_socket
    if host is None:
        # INET6 is able to handle both IPv4 and IPv6 clients.
        wanted_family = socket.AF_INET6
    else:
        wanted_family = socket.AF_UNSPEC

    last_error = ValueError("No address for: [%s]:%s" % (host, port))
    for result in socket.getaddrinfo(host, port, wanted_family,
            socktype, 0, flags):
        family, socktype, proto, canonname, sockaddr = result
        try:
            sock = socket.socket(family, socktype, proto)
            return sock, sockaddr
        except socket.error, last_error:
            continue

    raise last_error



MAPPED_IPV4_PREFIX = "::ffff:"

def get_ip(addr):
    """Returns an IPv4 or IPV6 IP address from the given tuple.
    """
    ip = addr[0]
#    ip = ip.split('%', 1)[0]
    if ip.startswith(MAPPED_IPV4_PREFIX) and "." in ip:
        return ip[len(MAPPED_IPV4_PREFIX):]
    return ip
