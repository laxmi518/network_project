
import base64
import logging
import os
import time

import gevent

from libcol.collectors import file_handler, shelves
from pylib import disk, homing
import ftpclient

log = logging.getLogger(__name__)

def fetch_job(sid, config, db_file):
    log.debug('fetching files for sid:%s', sid)

    source = config['client_map'][sid]
    basedir = config['basedir'].replace('$LOGINSPECT_HOME',
                                        homing.LOGINSPECT_HOME)

    ip = source['ip']
    port = source['port']
    user = source['user']
    path = source['path']
    password = source['password']
    parser = source['parser']
    charset = source['charset']
    device_name = source['device_name']

    localdir = os.path.join(basedir, ip, base64.urlsafe_b64encode(sid))

    ftp = ftpclient.login(ip, port, user, password)

    for remotefile, mtime in ftpclient.fetch_file_mtime(ftp, path):
        disk.prepare_path(localdir + '/')
        vc = shelves.VersionChecker(db_file, sid, remotefile, mtime)
        if vc.is_older_version():
            continue

        localfile = os.path.join(localdir, base64.urlsafe_b64encode(remotefile))
        log.info('Downloading remote file %r to %r', remotefile, localfile)

        try:
            ftpclient.download(ftp, remotefile, localfile)
        except Exception, err:
            log.warn("fetching failed; remotefile=%s; sid=%s; error=%r", remotefile, sid, err)
            continue

        col_ts = time.time()
        cursor = vc.get_old_cursor(localfile)
        if cursor < 0:
            continue
        file_handler.main(sid, col_ts, parser, localfile, charset, device_name, 
                          source['normalizer'], source['repo'], cursor,
                          source.get('regex_pattern'), source.get('regexparser_name'),
                          conf_path=config.get('wiring_conf_path') or None)
    ftp.quit()


def _run(func, args, seconds):
    sid = args[0]
    while True:
        try:
            func(*args)
        except gevent.GreenletExit:
            raise
        except Exception, err:
            log.warn('exception while running job; sid=%s; err=%r', sid, ftpclient.remove_null_char(repr(err)))
        gevent.sleep(seconds)


def schedule(func, args, seconds):
    return gevent.spawn_link_exception(_run, func, args, seconds)


def update_jobs(config, running_sid_jobs, db_file):
    for sid, source in config['client_map'].iteritems():
        interval = source['fetch_interval_seconds']

        old_job = running_sid_jobs.get(sid)
        if old_job:
            if old_job['interval'] == interval:
                continue
            else:
                old_job['job'].kill()

        log.debug('adding job for sid=%s', sid)

        job = schedule(fetch_job,
                            args=(sid, config, db_file),
                            seconds=interval)
        running_sid_jobs[sid] = dict(job=job, interval=interval)

    # delete removed sources and kill their jobs
    # running_sid_jobs size may change during iteration so using .items()
    for sid, job in running_sid_jobs.items():
        if sid not in config['client_map']:
            del running_sid_jobs[sid]
            job['job'].kill()


def start(config):
    basedir = config['basedir'].replace('$LOGINSPECT_HOME', homing.LOGINSPECT_HOME)
    db_file = os.path.join(basedir, 'checksums.pdict')
    
    running_sid_jobs = {}
    while True:
        if config["_onreload"](timeout=1):
            update_jobs(config, running_sid_jobs, db_file)
