
import base64
import logging
import os
import time
import shutil
import ssh

import gevent

from pylib import disk, homing, ssh_keygen
from libcol.collectors import file_handler, shelves
import scp

log = logging.getLogger(__name__)

def fetch_job(sid, config, db_file):
    log.debug('fetching files for sid:%s', sid)

    try:
        source = config['client_map'][sid]
    except KeyError:
        log.debug('source for sid=%s has been deleted' % (sid))
        return

    basedir = config['basedir'].replace('$LOGINSPECT_HOME',
                                        homing.LOGINSPECT_HOME)

    ip = source['ip']
    port = source['port']
    user = source['user']
    password = source['password']
    remotepath = source['remotepath']
    if remotepath.startswith('~'):
        remotepath = '.' + remotepath[1:]
    parser = source['parser']
    charset = source['charset']
    device_name = source['device_name']

    if '%' in ip:
        old_empty_dir = os.path.join(basedir, ip)
        if os.path.exists(old_empty_dir):
            try:
                shutil.rmtree(old_empty_dir)
            except:
                pass
        ip_dir = ip.replace("%", "_")
    else:
        ip_dir = ip

    localdir = os.path.join(basedir, ip_dir, base64.urlsafe_b64encode(sid))

    try:
        scp.setup(ip, port, user, password)
    except (ssh.SSHException, EOFError, SystemExit), err:
        log.warn('error while setting up connection; sid=%s', sid)
        return

    try:
        for remotefile, mtime in scp.fetch_file_mtime(remotepath):
            disk.prepare_path(localdir + '/')
            vc = shelves.VersionChecker(db_file, sid, remotefile, mtime=mtime)
            if vc.is_older_version():
                continue

            localfile = os.path.join(localdir, base64.urlsafe_b64encode(remotefile))
            log.info('Downloading remote file %r to %r', remotefile, localfile)

            try:
                scp.scp_get(remotefile, localfile)
            except (ssh.SSHException, EOFError, SystemExit), err:
                log.warn("fetching failed; sid=%s; remotefile=%s; error=%r", sid, remotefile, err)
                continue

            col_ts = time.time()
            cursor = vc.get_old_cursor(localfile)
            if cursor < 0:
                continue
            file_handler.main(sid, col_ts, parser, localfile, charset, device_name,
                              source['normalizer'], source['repo'], cursor,
                              source.get('regex_pattern'), source.get('regexparser_name'),
                              conf_path=config.get('wiring_conf_path') or None)
    except gevent.GreenletExit:
        raise
    except (Exception, ssh.SSHException, EOFError, SystemExit), err:
        log.warn('exception while running job; sid=%s; err=%r', sid, err)


def _run(func, args, seconds):
    while True:
        func(*args)
        gevent.sleep(seconds)


def schedule(func, args, seconds):
    return gevent.spawn_link_exception(_run, func, args, seconds)


def update_jobs(config, running_sid_jobs, db_file):
    for sid, source in config['client_map'].iteritems():
        interval = source['fetch_interval']

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


def _ensure_certificates():
    if not os.path.exists(scp.private_keyfile):
        ssh_keygen.generate(private=scp.private_keyfile, public=scp.private_keyfile + ".pub")


def start(config):
    basedir = config['basedir'].replace('$LOGINSPECT_HOME', homing.LOGINSPECT_HOME)
    db_file = os.path.join(basedir, 'checksums.pdict')
    
    running_sid_jobs = {}
    _ensure_certificates()
    while True:
        if config["_onreload"](timeout=1):
            update_jobs(config, running_sid_jobs, db_file)
