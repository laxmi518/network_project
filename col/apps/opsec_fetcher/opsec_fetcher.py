#!/usr/bin/env python

import os
import time
import errno
import signal
import logging
import threading
import subprocess
import warnings

from pylib import conf, wiring, homing, msgfilling
from pylib.wiring import gevent_zmq as zmq

log = logging.getLogger(__name__)

LAST_COL_TS = 0
LOG_COUNTER = 0

STOPIT = False
CHILD_PROCESSES = {}

def handler(signum=None, frame=None):
    global CHILD_PROCESSES
    global STOPIT

    STOPIT = True
    for sid, pid in CHILD_PROCESSES.iteritems():
        try:
            os.killpg(pid, 9)
        except OSError, e:
            log.warn(e)

signal.signal(signal.SIGTERM, handler)

def _parse_args():
    options, app_config = conf.parse_config()
    return app_config

class OpsecFetcher():

    def __init__(self, config, sid, opsecfetcher_out):
        """
        """
        self.col_type = config["col_type"]
        self.collected_at = config["loginspect_name"]

        self.set_fields(sid, config["client_map"][sid])
        self.opsecfetcher_out = opsecfetcher_out


        ip_path = homing.home_join("storage/col/opsec_fetcher", self.device_ip)
        #Change directory to the ip of sever because the certificate files are present there
        os.chdir(ip_path)
        #The path of loggrabber utils
        utils_path = homing.home_join("installed/system/apps/opsec_tools")
        #The executor script to export logs
        self.loggrabber_executor = os.path.join(utils_path, "fw1-loggrabber")
        #The configuration to be used with -c
        self.loggrabber_conf = os.path.join(utils_path, "fw1-loggrabber-online.conf")
        #The configuration file to be used with -l
        self.lea_conf_file = os.path.join(os.path.join(ip_path, "lea.conf"))

    def set_fields(self, sid, config):
        self.sid = sid

        self.device_ip = config["device_ip"]
        self.device_name = config["device_name"]
        self.normalizer = config["normalizer"]
        self.repo = config["repo"]
        self.charset = config["charset"]

    def encode(self, buffer):
        """
        encodes the given buffer with charset codec into utf-8
        """
        charset = self.charset or 'utf8'
        try:
            ubuffer = unicode(buffer, charset)
        except UnicodeDecodeError:
            warnings.warn("log data could not be decoded using %s; sid=%s; log=%r" % (
                        charset, self.sid, buffer), UnicodeWarning)
            ubuffer = unicode(buffer, charset, 'replace')
        return ubuffer.encode('utf-8')

    def _forward_event(self, message):
        """
        """
        global LAST_COL_TS
        global LOG_COUNTER

        self.opsecfetcher_out.start_benchmarker_processing()

        col_ts = int(time.time())
        if col_ts > LAST_COL_TS:
            LAST_COL_TS = col_ts
            LOG_COUNTER = 0

        mid_prefix = '%s|%s|%s|%d|' % (self.collected_at, self.col_type, self.device_ip, col_ts)

        LOG_COUNTER += 1

        event = dict(
                    msg = self.encode(message),
                    mid = mid_prefix + "%d" % LOG_COUNTER,
                    device_ip = self.device_ip,
                    device_name = self.device_name,
                    collected_at = self.collected_at,
                    col_ts = col_ts,
                    col_type = self.col_type,
                    _counter = LOG_COUNTER,
                    normalizer = self.normalizer,
                    repo = self.repo
                    )

        msgfilling.add_types(event, "_type_num", "col_ts")
        msgfilling.add_types(event, "_type_str", "msg device_ip device_name collected_at col_type")
        msgfilling.add_types(event, "_type_ip", "device_ip")

        self.opsecfetcher_out.send_with_norm_policy_and_repo(event)

    def _run_script(self):
        """
        Fetch only the most recent logs
        """
        global CHILD_PROCESSES

        command = "%s -l %s -c %s" % (self.loggrabber_executor, self.lea_conf_file, self.loggrabber_conf)
        self.proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        shell=True, preexec_fn=os.setsid)
        CHILD_PROCESSES[self.sid] = self.proc.pid

    def spawn(self):
        """
        """
        self._run_script()

        last_buffer = ""
        while not STOPIT:
            self.proc.poll()
            if self.proc.returncode:
                self._run_script()
                log.warn("Respawned subprocess with new pid=%s", self.proc.pid)

            #Read 4kb of data chunk at a time
            try:
                chunk = os.read(self.proc.stdout.fileno(), 4096)
                #chunk = self.proc.stdout.read(4096)
            except IOError, e:
                # when SIGTERM signal if found (Interrupted system call)
                if e.errno == errno.EINTR:
                    break

                time.sleep(10)
                continue

            if not chunk:
                #If can't read, wait for 5 secs before retry
                time.sleep(5)
                continue

            #If we have last_buffer, then we add it to the existing chunk
            if last_buffer:
                chunk = last_buffer + chunk

            lines = chunk.splitlines(True)

            #Put the last line to last_buffer if it doesnot end with \n
            last_buffer = lines[len(lines)-1]
            if not last_buffer.endswith("\n"):
                lines = lines[:-1]
            else:
                last_buffer = ""

            for line in lines:
                self._forward_event(line)

def update_jobs(config, running_sid_jobs, opsecfetcher_out):
    global CHILD_PROCESSES

    for sid, prop in config["client_map"].iteritems():
        old_job = running_sid_jobs.get(sid)
        if old_job:
            if old_job["prop"] != prop:
                old_job.get("instance").set_fields(sid, prop)
            continue

        logging.debug("adding job for sid=%s", sid)

        of = OpsecFetcher(config, sid, opsecfetcher_out)
        job = threading.Thread(target=of.spawn)
        job.start()
        #job = gevent.spawn_link_exception(of.spawn)

        running_sid_jobs[sid] = dict(job=job, prop=prop, instance=of)

    for sid, job in running_sid_jobs.items():
        if sid not in config["client_map"]:
            del running_sid_jobs[sid]
            job["job"].kill()

            child_pid = CHILD_PROCESSES.get(sid)
            if child_pid:
                os.killpg(child_pid, 9)

def main():
    zmq_context = zmq.Context()

    config = _parse_args()
    opsecfetcher_out = wiring.Wire("collector_out", zmq_context=zmq_context,
                                        conf_path=config.get("wiring_conf_path") or None)

    running_opsecf_jobs = {}

    while not STOPIT:
        if config["_onreload"](timeout = 1):
            update_jobs(config, running_opsecf_jobs, opsecfetcher_out)

main()
