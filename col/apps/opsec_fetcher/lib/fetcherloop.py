import logging
import os
import subprocess
import time
import gevent
import re

from pylib import msgfilling, homing
from utility import get_loc_starttime_if_exists, get_memory_file, dump_loc_time_to_file, get_config_file_path, storage_path
# globals used across all jobs
LAST_COL_TS = 0
LOG_COUNTER = 0

pattern = re.compile('[\W]+')

def _handle_data(event, col_type, ip, device_name, loginspect_name, opsecfetcher_out, normalizer, repo):
    #sends data to the normalizer

    global LAST_COL_TS
    global LOG_COUNTER

    opsecfetcher_out.start_benchmarker_processing()

    col_ts = int(time.time())
    if col_ts > LAST_COL_TS:
        LAST_COL_TS = col_ts
        LOG_COUNTER = 0

    mid_prefix = '%s|%s|%s|%d|' % (loginspect_name, col_type, ip, col_ts)

    LOG_COUNTER += 1
    event['mid'] = mid_prefix + "%d" % LOG_COUNTER
    event['device_name'] = device_name
    event['collected_at'] = loginspect_name
    event['col_ts'] = col_ts
    event['col_type'] = col_type

    for key, value in event.items():
        if key == 'mid':
            continue
        if key in ['orig']:
            msgfilling.add_types(event, '_type_ip', key)
        elif key in ['has_accounting', 'loc']:
            msgfilling.add_types(event, '_type_num', key)
        else:
            msgfilling.add_types(event, '_type_str', key)

    event['_counter'] = LOG_COUNTER
    
    event['device_ip'] = ip
    msgfilling.add_types(event, '_type_str', 'device_ip')
    msgfilling.add_types(event, '_type_ip', 'device_ip')

    event['normalizer'] = normalizer
    event['repo'] = repo
    opsecfetcher_out.send_with_norm_policy_and_repo(event)

def _make_ready(data, from_beginning, loc):
    t_l, t_t = None, None
    a_entry = {'msg':''}
    try:
        for each in data.split("|"):
          try:
            key, value = each.split("=", 1)
            key = pattern.sub('_', key)
            if not from_beginning:
                if key == 'loc':
                    if int(value) <= int(loc):
                        break
            if key == 'loc':
                t_l = value
            if key == 'time':
                t_t = value
            a_entry[key.rstrip(":")] = value
          except ValueError, err:
            logging.warn(err)
        if not len(a_entry.keys()) == 1:
            a_entry['msg'] = data
    except AttributeError, err:
        logging.warn(err)
    return a_entry, t_l, t_t

def fetch_job(sid, config, opsecfetcher_out):
    col_type = config['col_type']
    device_name = config['client_map'][sid]['device_name']
    collected_at = config['loginspect_name']

    ip = config['client_map'][sid]['lea_server_ip']
    client_dn   = config['client_map'][sid]['client_dn']
    server_dn = config['client_map'][sid]['server_dn']
    normalizer = config['client_map'][sid]['normalizer']
    repo = config['client_map'][sid]['repo']

    mem_file = get_memory_file(ip)
    #fetches fw logs from lea server using the lea.conf file specified
    try:
        loc, starttime = get_loc_starttime_if_exists(mem_file)
        from_beginning = False
    except:
        loc = -1
        from_beginning = True
    os.chdir(os.path.join(storage_path, ip))
    loggrabber_path = homing.home_join('installed/col/apps/opsec_fetcher/utils')
    loggrabber = os.path.join(loggrabber_path, 'fw1-loggrabber')
    loggrabber_conf = os.path.join(loggrabber_path, 'fw1-loggrabber.conf')
    lea_conf_file = get_config_file_path(ip, client_dn, server_dn)

    if from_beginning:
        proc = subprocess.Popen([loggrabber, '-l', lea_conf_file, \
                                             '-c', loggrabber_conf], \
                                 stdout=subprocess.PIPE
                                 )

    else:
        proc = subprocess.Popen([loggrabber, '-l', lea_conf_file, \
                                             '-c', loggrabber_conf, \
                                             '--filter', 'starttime=%s' % starttime], \
                                stdout=subprocess.PIPE
                                )

    t_loc, t_time = None, None
    while True:
        line = proc.stdout.readline()
        if not line:
            break

        data, t_loc, t_time = _make_ready(line, from_beginning, loc)
        if data['msg']:
            _handle_data(data, col_type, ip, device_name, collected_at, opsecfetcher_out, normalizer, repo)

#    for each in proc.stdout:
#        data, t_loc, t_time = _make_ready(each, from_beginning, loc)
#        if data['msg']:
#            _handle_data(data, col_type, ip, device_name, collected_at, opsecfetcher_out)

    if t_loc == None or t_time == None: #means no data in this fetch
        return
    dump_loc_time_to_file(mem_file, t_loc, t_time)

def _run(func, args, seconds):
    while True:
        try:
            func(*args)
        except gevent.GreenletExit:
            raise
        except Exception, err:
            logging.warn('exception while running job; sid=%s; err=%r', args[0], err)
        gevent.sleep(seconds)

def schedule(func, args, seconds):
    return gevent.spawn_link_exception(_run, func, args, seconds)

def update_jobs(config, running_sid_jobs, opsecfetcher_out):
    for sid, source in config['client_map'].iteritems():
        interval = source['fetch_interval']

        old_job = running_sid_jobs.get(sid)
        if old_job:
            if old_job['interval'] == interval:
                continue
            else:
                old_job['job'].kill()

        logging.debug('adding job for sid=%s', sid)

        job = schedule(fetch_job,
                            args=(sid, config, opsecfetcher_out),
                            seconds=interval)
        running_sid_jobs[sid] = dict(job=job, interval=interval)

    # delete removed sources and kill their jobs
    # running_sid_jobs size may change during iteration so using .items()
    for sid, job in running_sid_jobs.items():
        if sid not in config['client_map']:
            del running_sid_jobs[sid]
            job['job'].kill()

def start(config, opsecfetcher_out):
    running_opsecf_jobs = {}

    while True:
        if config['_onreload'](timeout = 1):
            update_jobs(config, running_opsecf_jobs, opsecfetcher_out)
