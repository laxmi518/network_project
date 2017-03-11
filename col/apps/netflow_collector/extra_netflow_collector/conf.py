
import os
import logging
import optparse
import json
import re

#import gevent
#import gevent.event
import signal
from ConfigParser import ConfigParser

from pylib import logger

DEFAULT_LOGINSPECT_HOME = "/opt/immune"

_LOADED_CONFIGS = {}

def load(config_path, override=None):
    """Returns a dict with the loaded JSON config.
    The content of the dict will be automatically reloaded on SIGHUP.

    The reloading is done in a greenlet. That will reload the configuration
    only on predictable places. You can assume that the configuration
    will not change when not calling a gevent function.
    """
    #if not _LOADED_CONFIGS:
    #    try:
    #        gevent.signal(signal.SIGHUP, _reload_configs)
    #        signal.siginterrupt(signal.SIGHUP, False)
    #    except AttributeError:
    #        pass

    config = {}
    _load_into(config_path, config, override)
    _LOADED_CONFIGS[config_path] = config
    return config


def _reload_configs():
    for path, config in _LOADED_CONFIGS.iteritems():
        logging.info("conf; reloading config; path=%s", path)
        _load_into(path, config)


def _load_into(config_path, config, override=None):
    with open(config_path) as f:
        data = re.compile("^\s*//.*$", re.MULTILINE).sub("", f.read())
        valid_data = json.loads(data)

    # The event is reused to preserve registered callbacks.
    event = config.get("_event")
    _onreload = config.get("_onreload")
    config.clear()
    config.update(valid_data)
    if override:
        config.update(override)
    _interpret_log_level(config)
    event = event or None#or gevent.event.Event()
    config["_event"] = event
    #event.set()
    
    if _onreload is None:
        def _onreload(timeout=0):
            if event.wait(timeout):
                event.clear()
                return True
            else:
                return False

    config["_onreload"] = _onreload


def _interpret_log_level(config):
    level_name = config.get("core", {}).get("log_level")
    if level_name is not None:
        logging.debug("conf; setting log level; level=%s", level_name)
        log_level = getattr(logging, level_name)
        logger.set_level(log_level)


def parse_config(cli_parser=None, log_to_syslog=False):
    """Loads a config file and setups logging.
    The config file should be the first argument given on the command line.

    Example config file:
        {
            "core": {
                "log_level": "WARN"
            },
            "port": 1514,
        }
    """
    usage = "Usage: %prog CONFIG.json"
    if isinstance(cli_parser, basestring):
        cli_parser = optparse.OptionParser(cli_parser)
    elif cli_parser is None:
        cli_parser = optparse.OptionParser(usage)

    cli_parser.add_option("--override", action="append", default=[],
            help="Override the given key=json_value config option.")

    logger.configure(cli_parser, syslog=log_to_syslog)
    options, args = cli_parser.parse_args()
    if len(args) != 1:
        cli_parser.error("A config file is expected.")
    override = _get_overrides(options)
    config = load(args[0], override)
    return options, config


def _get_overrides(options):
    override = {}
    if options.verbose:
        level_name = logging.getLevelName(logger.get_level(options.verbose))
        override.setdefault("core", {})["log_level"] = level_name

    for spec in options.override:
        key, value = spec.split("=", 1)
        override[key] = json.loads(value)

    return override
