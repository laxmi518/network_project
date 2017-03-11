#!/usr/bin/env python
# -*- coding: utf-8 -*-


import zmq
import ujson as json

from pylib.wiring import Wire

zmq_context = zmq.Context()


# store_in = Wire("normalizer_out", zmq_context=zmq_context,
#                 conf_path=config.get('wiring_conf_path') or None)
store_in = Wire("normalizer_out", zmq_context=zmq_context,
                conf_path="/opt/immune/installed/pylib/pylib/wiring/wiring.conf" or None)
device_ip = "127.0.0.1"
counter = 1
col_ts = 1355729317
mid = "LogInspect720|syslog|%s|%s|%s" % (device_ip, col_ts, counter)

event = {
    "_type_str": "msg col_type device_ip device_name collected_at",
    "_type_ip": "device_ip",
    "_type_num": "col_ts",
    "_counter": counter,
    "device_ip": device_ip,
    "mid": mid,
    "device_name": "localhost",
    "collected_at": "LogInspect500",
    "msg": "User Ritesh logged in.",
    "col_type": "syslog",
    "collected_at": "LogInspect720",
    "col_ts": col_ts
}

repo = "ritesh"  # "_loginspect"
store_in.send_raw(repo + "\n" + json.dumps(event))
