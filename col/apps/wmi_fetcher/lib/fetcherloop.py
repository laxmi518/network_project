
import logging
import subprocess
import time

import gevent
from pylib import msgfilling
from libcol.parsers import GetParser, InvalidParserException

log = logging.getLogger(__name__)

wmicPath = '/bin/wmic'
time_zone = None

def from_time(year=None, month=None, day=None, hours=None, minutes=None, seconds=None, microseconds=None):
    """
    returns: A WMI datetime string of the form: `yyyymmddHHMMSS.mmmmmm+UUU`
    """
    def str_or_stars(i, length):
        if i is None:
            return "*" * length
        else:
            return str(i).rjust(length, "0")
    wmi_time = ""
    wmi_time += str_or_stars(year, 4)
    wmi_time += str_or_stars(month, 2)
    wmi_time += str_or_stars(day, 2)
    wmi_time += str_or_stars(hours, 2)
    wmi_time += str_or_stars(minutes, 2)
    wmi_time += str_or_stars(seconds, 2)
    wmi_time += "."
    wmi_time += str_or_stars(microseconds, 6)
    wmi_time += "+"
    wmi_time += str_or_stars(time_zone, 3)

    return wmi_time

def get_wmi_data(host, username, password, wmlQuery):
    wmicArgs = ['%s' % wmicPath, '-U', '%s%%%s' % (username, password), '//%s' % host, '%s' % wmlQuery]
    wmicproc = subprocess.Popen(wmicArgs, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    wmicData, wmi_err_data = wmicproc.communicate()

    if wmi_err_data:
           log.warn('error when executing wmi command; host=%r; username=%r; query=%r, err_data=%r', host, username, wmlQuery, wmi_err_data)
    if wmicData:
        wmicData = wmicData.split('\n')

        if '[wmi/wmic.c:196:main()] ERROR: Login to remote object.' in wmicData:
            log.debug('Invalid IP address or Invalid credentials')
            return None

    return wmicData

def get_current_host_time(host, username, password, parser):
    query = "SELECT Bias FROM Win32_TimeZone"
    wmicData = get_wmi_data(host, username, password, query)
    if not wmicData:
        return None

    global time_zone
    time_zone = parser.parse_wmi_timezone_query(wmicData)

    query = "SELECT * FROM Win32_LocalTime"
    wmicData = get_wmi_data(host, username, password, query)
    if not wmicData:
        return None

    datetime_client = parser.parse_wmi_date_query(wmicData)

    current_time = from_time(*datetime_client.timetuple()[:-2])

    return current_time

def fetch_job(host, config, wmi_out):
    global LAST_COL_TS
    global LOG_COUNTER

    while True:
        try:
            prop = config['client_map'][host]
        except KeyError:
            log.debug('source for %s has been deleted' % host)
            return

        username = prop['username']
        password = prop['password']
        parser_name = prop['parser']
        charset = prop['charset']
        facility = prop['facility']
        severity = prop['severity']
        device_name = prop['device_name']
        normalizer = prop['normalizer']
        repo = prop['repo']

        try:
            assert parser_name == 'WmiParser'
            parser = GetParser(parser_name, charset=charset)
        except InvalidParserException, err:
            log.warn(err)
            return

        parser.set_facility_severity(facility, severity)

        interval = prop['fetch_interval_seconds']

        log.debug('Starting WMI fethcer for host %s with user %s' % (host, username))

        #timeGenerated, interval_ago = get_timegenerated_intervalago(host, username, password, parser, interval)
        timeGenerated = get_current_host_time(host, username, password, parser)
        if not timeGenerated:
            log.debug('Unable to connect to host %s, reconnecting in 5 seconds' % host)
            gevent.sleep(interval)
            continue
        break

    while True:
        log.debug('fetching wmi log')
        query = "SELECT * FROM Win32_NTLogEvent WHERE TimeGenerated>\'%s\'" % timeGenerated
        wmicData = get_wmi_data(host, username, password, query)

        if wmicData:
            wmi_out.start_benchmarker_processing()

            col_ts = int(time.time())
            if col_ts > LAST_COL_TS:
                LAST_COL_TS = col_ts
                LOG_COUNTER = 0

            mid_prefix = '%s|%s|%s|%d|' % (config['loginspect_name'], 'wmi', host, col_ts)
            parser.write(wmicData)

            for event in parser:
                LOG_COUNTER += 1
                event['mid'] = mid_prefix + "%d" % LOG_COUNTER
                
                event['col_ts'] = col_ts
                event['_counter'] = LOG_COUNTER
                event['col_type'] = 'wmi'
                msgfilling.add_types(event, '_type_num', 'col_ts')
                msgfilling.add_types(event, '_type_str', 'col_type')
                
                event['device_ip'] = host
                msgfilling.add_types(event, '_type_str', 'device_ip')
                msgfilling.add_types(event, '_type_ip', 'device_ip')
                
                event['device_name'] = device_name
                event['collected_at'] = config['loginspect_name']
                msgfilling.add_types(event, '_type_str', 'device_name')
                msgfilling.add_types(event, '_type_str', 'collected_at')
                
                event['normalizer'] = normalizer
                event['repo'] = repo
                wmi_out.send_with_norm_policy_and_repo(event)

            time_gen_in_logs = parser.get_last_time()
            if time_gen_in_logs:
                timeGenerated = time_gen_in_logs

        #interval_ago = interval_ago + datetime.timedelta(0, interval)
        #timeGenerated = from_time(*interval_ago.timetuple()[:-2])
        gevent.sleep(interval)


def schedule(func, host, config, wmi_out):
    return gevent.spawn_link_exception(func, host, config, wmi_out)

def update_jobs(config, running_wmihost_jobs, wmi_out):
    for host, prop in config['client_map'].iteritems():
        prop['loginspect_name'] = config['loginspect_name']
        old_job = running_wmihost_jobs.get(host)
        if old_job:
            if old_job['prop'] == prop:
                continue
            else:
                old_job['wmi_job'].kill()

        log.debug('adding job for host:%s', host)

        wmi_job = schedule(fetch_job, host, config, wmi_out)
        running_wmihost_jobs[host] = dict(wmi_job=wmi_job, prop=prop)

    # delete removed sources and kill their jobs
    # running_sid_jobs size may change during iteration so using .items()
    for host, job in running_wmihost_jobs.items():
        if host not in config['client_map']:
            del running_wmihost_jobs[host]
            job['wmi_job'].kill()


# globals used across all jobs
LAST_COL_TS = 0
LOG_COUNTER = 0

def start(config, wmi_out):
    running_wmihost_jobs = {}

    while True:
        if config["_onreload"](timeout=1):
            update_jobs(config, running_wmihost_jobs, wmi_out)
