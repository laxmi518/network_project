import logging
import netaddr
from pylib import cidr

def get_config_ip(ip, config):
    config_ip = None
    if ip in config["client_map"]:
        config_ip = ip
    else:
        try:
            config_ip = cidr.get_cidr(ip, config["client_map"].iterkeys())
        except netaddr.core.AddrFormatError:
            pass
        if not config_ip:
            logging.warn("Connection attempt from unregistered IP %s", ip)
            return
    return config_ip


