#!/usr/bin/env python
# -*- coding: utf-8 -*-


import zmq
import time
import argparse
import datetime
import ujson as json
from pylib import wiring
from pylib.wiring import Wire


def get_colts(y, m, d):
    t = datetime.datetime(y, m, d)
    col_ts = time.mktime(t.timetuple())
    print "date=", y, m, d, "colts=", col_ts
    return col_ts


def get_out_event(colts, normalizer, repo):
    device_ip = "127.0.0.1"
    mid = "LogInspect500|syslog|%s|1355729317|1" % device_ip
    event = {
        "_type_str": "msg col_type device_ip device_name collected_at",
        "_type_ip": "device_ip",
        "_type_num": "col_ts",
        "_counter": 1,
        "device_ip": device_ip,
        "mid": mid,
        "device_name": "localhost",
        "collected_at": "LogInspect720",
        "msg": "User Ritesh logged in.",
        "normalizer": normalizer,
        "repo": repo,
        "col_type": "syslog",
        "col_ts": colts
    }

    out_event = json.dumps(event)
    return out_event


if __name__ == "__main__":
    usage = """ Usage: python norm_front_input.py -h  //for help"""
    print usage
    parser = argparse.ArgumentParser(
        description="Forward some old cot_ts logs")
    parser.add_argument('-n', default=1000, help="Number of logs.")
    parser.add_argument('-d', default=4, help="day")
    parser.add_argument('-m', default=4, help="month")
    parser.add_argument('-y', default=2013, help="year")
    parser.add_argument('--repo', default="default", help="Repo name")
    parser.add_argument('--norm', default="default", help="Normalizer")
    args = parser.parse_args()

    colts = get_colts(int(args.y), int(args.m), int(args.d))
    out_event = get_out_event(colts, args.norm, args.repo)

    wire = "/opt/immune/var/wire/repo_indexing_in_" + str(args.repo).strip()
    socket = "PUSH:bind:ipc://" + wire

    zmq_context = zmq.Context()

    # collector_out = Wire("collector_out", zmq_context=zmq_context,
    # conf_path="/opt/immune/installed/pylib/pylib/wiring/wiring.conf")
    # wiring.sender = simple('PUSH:connect:tcp://127.0.0.1:5678', format="json")
    indexsearch_in = wiring.create_wire(zmq_context, dict(
        socket=socket, format="json"))

    NUM = int(args.n)
    curr = time.time()
    for i in xrange(NUM):
        indexsearch_in.send_raw(out_event)
    print NUM * 1.0 / (time.time() - curr)
