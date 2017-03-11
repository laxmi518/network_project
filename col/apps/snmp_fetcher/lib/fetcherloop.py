from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.carrier.asynsock.dgram import udp6
from pysnmp.smi import view, builder
from pyasn1.error import PyAsn1Error
from pysnmp.smi.error import NoSuchObjectError, SmiError
from pysnmp.proto.rfc1905 import NoSuchInstance

import re
import gevent
import logging
import time
import netaddr
import socket

from pylib import msgfilling
mib_dir = '/opt/immune/storage/col/snmp_fetcher/mibs'
mib_modules_record = '/opt/immune/storage/col/snmp_fetcher/mib_modules'
#mib_modules = ['IP-MIB', 'IF-MIB', 'SNMPv2-CONF', 'UCD-SNMP-MIB', 'SNMPv2-SMI', 'TCP-MIB', 'UDP-MIB', 'SNMPv2-MIB', 'HOST-RESOURCES-MIB']
pattern = re.compile('[\W]+')
# globals used across all jobs
LAST_COL_TS = 0
LOG_COUNTER = 0

class Udp6TransportTarget(cmdgen.UdpTransportTarget):
    transportDomain = udp6.domainName

    def __init__(self, transportAddr, timeout=1, retries=5):
        self.transportAddr = (
            socket.getaddrinfo(transportAddr[0], transportAddr[1],
                               socket.AF_INET6,
                               socket.SOCK_DGRAM,
                               socket.IPPROTO_UDP)[0][4]
            )
        self.timeout = timeout
        self.retries = retries

    def openClientMode(self):
        self.transport = udp6.Udp6SocketTransport().openClientMode()
        return self.transport

def _get_mib_modules():
    with open(mib_modules_record, 'r') as f:
        for module in f.readlines():
            yield module.rstrip()

def _get_mib_viewer(cmdGen):
    '''
    The mibBuilder.loadModules() can be used to load mib modules
    that can be used for mib lookup.
#    Currently the lookup has been disabled.
    '''
    mibBuilder = cmdGen.mibViewController.mibBuilder
    for path in mib_dir.split(":"):
        mibPath = mibBuilder.getMibSources() + \
            (builder.DirMibSource(str(path)),)
        mibBuilder.setMibSources(*mibPath)
    for module in _get_mib_modules():
        try:
            mibBuilder.loadModules(module)
        except SmiError, msg:
            logging.warn("Error loading mib module (%s), error=(%s)", module, msg)
            pass

    mibView = view.MibViewController(mibBuilder)

    return mibView

def get_community_function(prop):
    if prop["snmp_version"] == 'v12':
        agent = 'test-agent'
        community_string = prop['community_string']
        return cmdgen.CommunityData(agent, community_string)

    elif prop["snmp_version"] == 'v3':
        user = prop['username']
        authorization_key = prop['auth-key']
        private_key = prop['priv-key']
        return cmdgen.UsmUserData(user, authorization_key, private_key)
    else:
        return None

def get_transport_function(ip, port):
    if '%' in ip:
        ip, interface = ip.split('%', 1)
        if not re.match('[a-z][a-z0-9]+$', interface):
            logging.warn("Invalid IP Address")
            return None
        else:
            return Udp6TransportTarget((ip, port))

    elif netaddr.valid_ipv4(ip):
        return cmdgen.UdpTransportTarget ( (ip, port) )

    elif netaddr.valid_ipv6(ip):
        return Udp6TransportTarget ( (ip, port) )

def get_result_with_mib_lookup(cmdGen, oid, val):
    (symName, modName), indices = cmdgen.mibvar.oidToMibName(
        cmdGen.mibViewController, oid
        )
    val = cmdgen.mibvar.cloneFromMibValue(
              cmdGen.mibViewController, modName, symName, val
      )
    #symName = pattern.sub('_', symName)
    #modName = pattern.sub('_', modName)
    #inid = pattern.sub('_', indices.prettyPrint())
    modName = '_'.join(modName.split('-'))
    inid = ['_'.join(all.prettyPrint().split('.')) for all in indices]

    oid = '%s_%s_%s' % (modName, symName, '_'.join(map(lambda v: v, inid)))
    oid_val = val.prettyPrint()
    msg = '%s_%s_%s = %s' % (modName, symName, '.'.join(map(lambda v: v, inid)), oid_val)
    event = {'msg': msg, oid: oid_val}

    _add_types(event, oid, val)
    return event

def get_result_without_mib_lookup(mibView, oid, val):
    name, label, suffix = mibView.getNodeName(oid)
    oidLabel = "_".join(map(str, label))
    oidLabel = pattern.sub('_', oidLabel)
    oidSuffix = "_".join(map(str, suffix))
    oidSuffix = pattern.sub('_', oidSuffix)

    oid = '%s_%s' % (oidLabel, oidSuffix)
    oid_val = val.prettyPrint()
    msg = '%s_%s = %s' % (oidLabel, oidSuffix, oid_val)
    event = {'msg': msg, oid: oid_val}

    _add_types(event, oid, oid_val)
    return event

def _add_types(event, oid, oid_val):
    msgfilling.add_types(event, '_type_str', 'msg')
    oid_type = oid, str(oid_val.__class__).split('.')[-1:][0].upper()

    if oid_type in ['INTEGER', 'INTEGER32', 'TIMETICKS', 'COUNTER32', 'GAUGE32', "COUNTER64"]:
        msgfilling.add_types(event, '_type_num', oid)
    elif oid_type in ['OCTETSTRING', 'OID', 'HEXSTRING', 'PHYSADDRESS']:
        msgfilling.add_types(event, '_type_str', oid)
    elif oid_type in ['IPADDRESS']:
        msgfilling.add_types(event, '_type_ip', oid)
    else:
        msgfilling.add_types(event, '_type_str', oid)

def pack_result_data(walk_flag, varBindTable, errorIndication, errorStatus, errorIndex, oid, cmdGen, mibView):
    return {
            'errorIndication' : errorIndication,
            'errorStatus' : errorStatus,
            'errorIndex' : errorIndex,
            'varBindTable' : varBindTable,
            'oid' : oid,
            'walk_flag' : walk_flag,
            'cmdGen' : cmdGen,
            'mibView' : mibView
           }

def unpack_snmp_data(data_dict):
    return (
            data_dict['walk_flag'],
            data_dict['varBindTable'],
            data_dict['errorIndication'],
            data_dict['errorStatus'],
            data_dict['errorIndex'],
            data_dict['oid'],
            data_dict['cmdGen'],
            data_dict['mibView']
           )

def get_snmpfetcher_data(ip, port, prop, oid):
    result = {}
    cmdGen = cmdgen.CommandGenerator()
    mibView = _get_mib_viewer(cmdGen)

    c_function = get_community_function(prop)
    if c_function == None:
        logging.debug("snmp version not valid")
        return result

    transport_function = get_transport_function(ip, port)
    if transport_function == None:
        logging.debug("invalid ip address")
        return result

    walk_flag = True
    try:
        (errorIndication, errorStatus, errorIndex,
                     varBindTable) = cmdGen.nextCmd (
                                        c_function,
                                        transport_function,
                                        (str(oid))
                                    )
        if not varBindTable:
            (errorIndication, errorStatus, errorIndex,
                    varBindTable) = cmdGen.getCmd (
                                c_function,
                                transport_function,
                                (str(oid))
                                )
            walk_flag = False
    except PyAsn1Error, err:
        logging.warn(err)
        return result
    except Exception, err:
        logging.warn(err)
        return result
    result = pack_result_data(walk_flag, varBindTable, errorIndication, errorStatus, errorIndex, oid, cmdGen, mibView)
    return result

def process_snmp_fetcher_data(data_dict):
    result = {}
    walk_flag, varBindTable, errorIndication, errorStatus, errorIndex, oid, cmdGen, mibView = unpack_snmp_data(data_dict)

    if not walk_flag:
        if not varBindTable:
            logging.warn('%s = %s' % (oid, errorIndication))
            yield result
            return
        if isinstance(varBindTable[0][1], NoSuchInstance):
            logging.warn("%s = No Such Instance currently exists at this OID" % varBindTable[0][0].prettyPrint())
            yield result
            return
    if errorIndication and not varBindTable:
        logging.warn(errorIndication)
        yield result
        return
    else:
        if errorStatus:
            logging.warn( '%s at %s\n' % (
                errorStatus.prettyPrint (),
                errorIndex and varBindTable[-1][int (errorIndex) - 1] or '?'
                ))
            yield result
            return
        else:
            if not walk_flag:
                varBindTable = [varBindTable]
            for varBindTableRow in varBindTable:
                for oid, val in varBindTableRow:
                   try:
                       result = get_result_with_mib_lookup(cmdGen, oid, val)
                   except NoSuchObjectError:
                       result = get_result_without_mib_lookup(mibView, oid, val)
                yield result

def _handle_data(event, ip, col_type, device_name, loginspect_name, snmpfetcher_out, normalizer, repo):
    global LAST_COL_TS
    global LOG_COUNTER
    snmpfetcher_out.start_benchmarker_processing()

    col_ts = int(time.time())
    if col_ts > LAST_COL_TS:
        LAST_COL_TS = col_ts
        LOG_COUNTER = 0

    mid_prefix = '%s|%s|%s|%d|' % (loginspect_name, col_type, ip, col_ts)

    LOG_COUNTER += 1
    event['mid'] = mid_prefix + "%d" % LOG_COUNTER
    
    event['col_ts'] = col_ts
    event['_counter'] = LOG_COUNTER
    event['col_type'] = col_type
    msgfilling.add_types(event, '_type_num', 'col_ts')
    msgfilling.add_types(event, '_type_str', 'col_type')
    
    event['device_ip'] = ip
    msgfilling.add_types(event, '_type_str', 'device_ip')
    msgfilling.add_types(event, '_type_ip', 'device_ip')
    
    event['device_name'] = device_name
    event['collected_at'] = loginspect_name
    msgfilling.add_types(event, '_type_str', 'device_name')
    msgfilling.add_types(event, '_type_str', 'collected_at')
    
    event['normalizer'] = normalizer
    event['repo'] = repo
    snmpfetcher_out.send_with_norm_policy_and_repo(event)

def fetch_job(sid, config, oid, snmpfetcher_out):
    prop = config['client_map'][sid]
    col_type = config['col_type']

    #extract configurations from config file
    ip = prop['device_ip']
    port = prop['port']
    device_name = prop['device_name']
    loginspect_name = config['loginspect_name']
    normalizer = prop['normalizer']
    repo = prop['repo']

    logging.debug('Starting Snmp fethcer for host %s oid %s' % (sid, oid))
    result = get_snmpfetcher_data(ip, port, prop, oid)
    snmp_data_iterator = process_snmp_fetcher_data(result)
    for event in snmp_data_iterator:
        if event:
            _handle_data(event, ip, col_type, device_name, loginspect_name, snmpfetcher_out, normalizer, repo)

def _run(func, args, seconds):
    while True:
        try:
            func(*args)
        except gevent.GreenletExit:
            raise
        except Exception, err:
            logging.warn('exception while running job %s, error=%s', args[0], err)
        gevent.sleep(seconds)

def schedule(func, args, seconds):
    return gevent.spawn_link_exception(_run, func, args, seconds)

def update_jobs(config, running_snmpf_jobs, snmpfetcher_out):
    for sid, prop in config['client_map'].iteritems():
        old_job = running_snmpf_jobs.get(sid)

        if old_job:
            if old_job['prop'] == prop:
                continue
            else:
                for each in old_job["oids"].itervalues():
                    each.kill()

        logging.debug('adding job for source: %s' % sid)

        for oid, interval in prop['oids'].iteritems():
            snmpfetcher_job = schedule(fetch_job,
                                       args = (sid, config, oid, snmpfetcher_out),
                                       seconds = interval)

            host_jobs = running_snmpf_jobs.get(sid)
            if not host_jobs:
                host_jobs = running_snmpf_jobs[sid] = dict(prop=prop, oids={})
            host_jobs['oids'][oid] = snmpfetcher_job

    # delete removed sources and kill their jobs
    # running_sid_jobs size may change during iteration so using .items()
    for sid, oid_jobs in running_snmpf_jobs.items():
        if sid not in config['client_map']:
            del running_snmpf_jobs[sid]
            for each in oid_jobs["oids"].itervalues():
                each.kill()

def start(config, snmpfetcher_out):
    running_snmpf_jobs = {}

    while True:
        if config['_onreload'](timeout = 1):
            update_jobs(config, running_snmpf_jobs, snmpfetcher_out)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    mib_dir = "/Library/Python/2.7/site-packages/pysnmp-mibs-0.1.3rc0/pysnmp_mibs:/Library/Python/2.7/site-packages/pysnmp_mibs"
    #mib_dir = "/usr/share/snmp/mibs/"
    ip = '127.0.0.1'
    port = 161
    oid = '.1.3'
    #oid = '.1.3.6.1.4.1.2021.4'
    #oid = '.1.15454.1.45451.1.1.1.1.1.1.1.1.4.1.1'
    #mib_modules = ["IP-MIB", "IF-MIB", "SNMPv2-CONF"]
    prop = {}
    prop["snmp_version"] = 'v12'
    prop["community_string"] = 'public'

    iterator = get_snmpfetcher_data(ip, port, prop, oid)
    for each in iterator:
        print each
