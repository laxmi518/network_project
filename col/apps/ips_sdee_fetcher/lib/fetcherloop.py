
from libcol.collectors.pysdee.pySDEE import SDEE
from libcol.collectors.pysdee import idsmxml

from pylib import msgfilling

import gevent
import logging
import time
import socket
import binascii
import base64

log = logging.getLogger(__name__)

# globals used across all jobs
LAST_COL_TS = 0
LOG_COUNTER = 0



def _handle_data(event, ip, col_type, device_name, collected_at, normalizer, repo, ipssdee_out):
    global LAST_COL_TS
    global LOG_COUNTER
    ipssdee_out.start_benchmarker_processing()

    col_ts = int(time.time())
    if col_ts > LAST_COL_TS:
        LAST_COL_TS = col_ts
        LOG_COUNTER = 0

    mid_prefix = '%s|%s|%s|%d|' % (collected_at, col_type, ip, col_ts)

    LOG_COUNTER += 1
    event['mid'] = mid_prefix + "%d" % LOG_COUNTER
    event['col_ts'] = col_ts
    event['device_name'] = device_name
    event["collected_at"] = collected_at
    event["col_type"] = col_type
    event["device_ip"] = ip

    ##update msg_types here
    event = remove_NULL_fields(event)
    msg_types_dict = fill_msg_types(event)
    event.update(msg_types_dict)
    
    event['_counter'] = LOG_COUNTER
    
    event['device_ip'] = ip
    msgfilling.add_types(event, '_type_str', 'device_ip')
    msgfilling.add_types(event, '_type_ip', 'device_ip')

    event['normalizer'] = normalizer
    event['repo'] = repo
    ipssdee_out.send_with_norm_policy_and_repo(event)



def is_valid_ipv4(address):
    try:
        addr = socket.inet_aton(address)
    except socket.error:
        return False
    return address.count('.') == 3
    return True


def is_valid_ipv6(address):
    try:
        addr = socket.inet_pton(socket.AF_INET6, address)
    except socket.error: # not a valid address
        return False
    return True


def is_valid_num(s):
    try:
        float(s) # for int, long and float
    except ValueError:
        try:
            complex(s) # for complex
        except ValueError:
            return False
    return True


def remove_NULL_fields(event):
    for k in event.keys():
        if event[k] is "NULL":
            log.info("Removing NULL field %s", k)
            del event[k]
    return event


def fill_msg_types(d):
    msg_types = {}
    for (k, v) in d.iteritems():
        #print k, ": ", v
        if v and type(v) is not type(list()):
            if is_valid_ipv4(v) or is_valid_ipv6(v):
                msgfilling.add_types(msg_types, '_type_ip', k)
                msgfilling.add_types(msg_types, '_type_str', k)
            elif is_valid_num(v):
                msgfilling.add_types(msg_types, '_type_num', k)
            elif isinstance(v, list):
                pass
            else:
                msgfilling.add_types(msg_types, '_type_str', k )
        else:
            msgfilling.add_types(msg_types, '_type_str', k)
    log.debug("msg_types: %s", msg_types)
    return msg_types


def decode(data):
    try:
        decode = base64.b64decode(data)
        return binascii.b2a_qp(decode)
    except:
        return "-"


def get_event(alerts):
    try:
        target_list = []
        alert_dict = {}
        for target in alerts.target_list:
            target_list.append((target.addr,target.port,target.locality))

        alert_dict["destination_list"] = target_list

        if alerts.globalCorrelationScore != "NULL":
            alert_dict["gc_score"] = alerts.globalCorrelationScore
            alert_dict["gc_riskdelta"] = alerts.globalCorrelationRiskDelta
            alert_dict["gc_riskrating"] = alerts.globalCorrelationModifiedRiskRating
            alert_dict["gc_deny_packet"] = alerts.globalCorrelationDenyPacket
            alert_dict["gc_deny_attacker"] = alerts.globalCorrelationDenyAttacker
        #else:
            #alert_dict["gc_score"] = "NULL"
        #    pass

        alert_dict["alert_time"] = alerts.alert_time
        alert_dict["event_id"]=alerts.eventid
        alert_dict["host_id"]=alerts.originator
        alert_dict["severity"]=alerts.severity
        alert_dict["app_name"] = alerts.appname


        alert_dict["app_instance_id"] = alerts.appInstanceId
        alert_dict["signature"] = alerts.signature.sigid
        alert_dict["sub_sig_id"] = alerts.signature.subsig
        alert_dict["sig_details"] = alerts.signature.sigdetail
        alert_dict["description"] = alerts.signature.description
        alert_dict["sig_version"] = alerts.signature.sigversion
        alert_dict["sig_created"] = alerts.signature.sigcreated
        alert_dict["sig_type"] = alerts.signature.sigtype


        alert_dict["mars_category"] = alerts.signature.marsCategory
        alert_dict["source_address"] = alerts.attacker.addr
        alert_dict["source_locality"] = alerts.attacker.locality
        alert_dict["source_port"] = alerts.attacker.port
        alert_dict["protocol"] = alerts.protocol
        alert_dict["risk_rating"] = alerts.riskrating
        alert_dict["threat_rating"] = alerts.threatrating
        alert_dict["target_value_rating"] = alerts.targetvaluerating


        alert_dict["attack_relevance_rating"] = alerts.attackrelevancerating
        alert_dict["vlan"] = alerts.vlan
        alert_dict["interface"] = alerts.interface
        alert_dict["interface_group"] = alerts.intgroup


        alert_dict["context"] = alerts.context
        alert_dict["actions"] = alerts.actions
        alert_dict["ip_logging_activated"] = alerts.ipLoggingActivated
        alert_dict["shun_requested"] = alerts.shunRequested
        alert_dict["dropped_packet"] = alerts.droppedPacket
        alert_dict["denied_attacker"] = alerts.deniedAttacker
        alert_dict["block_connection_requested"] = alerts.blockConnectionRequested
        alert_dict["log_attacker_packets_activated"] = alerts.logAttackerPacketsActivated
        alert_dict["log_victim_packets_activated"] = alerts.logVictimPacketsActivated
        alert_dict["log_pair_packets_activated"] = alerts.logPairPacketsActivated
        alert_dict["snmp_trap_requested"] = alerts.snmpTrapRequested
        alert_dict["denied_attacker_service_pair"] = alerts.deniedAttackerServicePair
        alert_dict["denied_attacker_victim_pair"] = alerts.deniedAttackerVictimPair
        alert_dict["summary_count"] = alerts.summaryCount
        alert_dict["initial_alert"] = alerts.initialAlert


        try:
            if alerts.triggerpacket != "NULL":
                trigger_packet_details = decode(alerts.triggerpacket)
                alert_dict["trigger_packet"] = alerts.triggerpacket
                alert_dict["trigger_packet_details"] = trigger_packet_details
            if alerts.fromtarget!="NULL":
                fromTarget_details = decode(alerts.fromtarget)
                alert_dict["from_target"] = alerts.fromtarget
                alert_dict["from_target_details"] = fromTarget_details
            if alerts.fromattacker!="NULL":
                fromAttacker_details = decode(alerts.fromattacker)
                alert_dict["from_attacker"] = alerts.fromattacker
                alert_dict["from_attacker_details"] = fromAttacker_details
        except Exception, err:
            log.info("ERROR -  exception caught while getting trigger_packet: %s", err)

        if alert_dict["initial_alert"] != "NULL":
            alert_dict["event_ID"] = alert_dict["initial_alert"]

        try:
            for i, target in enumerate(alert_dict["destination_list"]):
                if i == 0:
                    target_index = "destination_address"
                    target_port = "destination_port"
                    target_locality = "destination_locality"
                else:
                    target_index = "destination_address" + str(i)
                    target_port = "destination_port_" + str(i)
                    target_locality = "destination_locality_" + str(i)
                alert_dict[target_index] = target[0]
                alert_dict[target_port] = target[1]
                alert_dict[target_locality] = str(target[2])
        except Exception, e:
            log.warn("ERROR -  exception caught while writing event: %s", e)

        alert_dict["destination_list"] = str(alert_dict["destination_list"])
        return alert_dict

    except Exception, e:
        log.warn("ERRROR - Exception while creating alerts:: %s", e)



def get_event_old(alerts):
        target_list = []
        alert_dict = {}
        for target in alerts.target_list:
            target_list.append((target.addr, target.port, target.locality))    #,target.locality))

        alert_dict["target_list"] = str(target_list)
        if hasattr(alerts, 'isDropped') and alerts.isDropped != "NULL":
            alert_dict["isDropped"] = alerts.isDropped
        else:
            alert_dict["isDropped"] = "NULL"

        if hasattr(alerts, 'globalCorrelationScore') and alerts.globalCorrelationScore != "NULL":
            alert_dict["gc_score"] =  alerts.globalCorrelationScore
            alert_dict["gc_riskdelta"] =  alerts.globalCorrelationRiskDelta
            alert_dict["gc_riskrating"] = alerts.globalCorrelationModifiedRiskRating
            alert_dict["gc_deny_packet"] = alerts.globalCorrelationDenyPacket
            alert_dict["gc_deny_attacker"] = alerts.globalCorrelationDenyAttacker
        else:
            alert_dict["gc_score"] = "NULL"

        alert_dict["alert_time"] = alerts.alert_time
        alert_dict["eventid"]=alerts.eventid
        alert_dict["hostId"]=alerts.originator
        alert_dict["severity"]=alerts.severity
        if hasattr(alerts , 'appname'):
            alert_dict["app_name"] = alerts.appname
        if hasattr(alerts, 'appInstanceId'):
            alert_dict["appInstanceId"] = alerts.appInstanceId

        alert_dict["signature"]=alerts.signature.sigid
        alert_dict["subSigid"]=alerts.signature.subsig
        alert_dict["description"]=alerts.signature.sigdetail
        alert_dict["sig_version"]=alerts.signature.sigversion
        if hasattr(alerts.signature, 'sigcreated'):
            alert_dict["sig_created"] = alerts.signature.sigcreated
        if hasattr(alerts.signature, 'sigtype'):
            alert_dict["sig_type"] = alerts.signature.sigtype
        if hasattr(alerts.signature, 'marsCategory'):
            alert_dict["mars_category"]=alerts.signature.marsCategory

        alert_dict["attacker"]=alerts.attacker.addr
        if hasattr(alerts.attacker, 'locality'):
            alert_dict["attacker_locality"]=alerts.attacker.locality
        alert_dict["attacker_port"]=str(alerts.attacker.port)

        alert_dict["protocol"]=alerts.protocol
        alert_dict["risk_rating"]=str(alerts.riskrating)
        if hasattr(alerts, 'threatrating'):
            alert_dict["threat_rating"]=str(alerts.threatrating)
        if hasattr(alerts, 'targetvaluerating'):
            alert_dict["target_value_rating"]= str(alerts.targetvaluerating)

        if hasattr(alerts, 'attackrelevancerating'):
            alert_dict["attack_relevance_rating"] =  str(alerts.attackrelevancerating)
        if hasattr(alerts, 'vlan'):
            alert_dict["vlan"]= alerts.vlan
        if hasattr(alerts, 'interface'):
            alert_dict["interface"]= alerts.interface
        if hasattr(alerts, 'intgroup'):
            alert_dict["interface_group"] = alerts.intgroup
        target_list_string = ""
        packet_info = ""
        try:
            if alerts.triggerpacket!="NULL":
                trigger_packet_details = decode(alerts.triggerpacket)
                packet_info = ' trigger_packet="'+alerts.triggerpacket+'" trigger_packet_details="'+trigger_packet_details+'"'
            if alerts.fromtarget!="NULL":
                fromTarget_details = decode(alerts.fromtarget)
                packet_info = packet_info +  ' fromTarget="'+alerts.fromtarget+'" fromTarget_details="'+fromTarget_details+'"'
            if alerts.fromattacker!="NULL":
                fromAttacker_details = decode(alerts.fromattacker)
                packet_info = packet_info +  ' fromAttacker="'+alerts.fromattacker+'" fromAttacker_details="'+fromAttacker_details+'"'
        except:
            log.info('Cannot obtain trigger_packet')
        try:
            for target in alert_dict["target_list"]:
                target_list_string = target_list_string + ' target="'+target[0]+'" target_port="'+str(target[1])+'" target_locality="'+str(target[2])+'" '
        except Exception, e:
            log.info('Cannot create the targer list string. %s', repr(e))

        return alert_dict


def fetch_job(sid, config, ipssdee_out):
    global LAST_COL_TS
    global LOG_COUNTER

    try:
        prop = config['client_map'][sid]
    except KeyError:
        log.error('source for %s has been deleted' % sid)
        return

    col_type = config['col_type']
    collected_at = config["loginspect_name"]
    #extract configurations from config file
    ip = prop['device_ip']
    username = prop['username']
    password = prop['password']
    method = prop['method']
    device_name = prop['device_name']
    normalizer = prop['normalizer']
    repo = prop['repo']

    seconds = 10
    #port = prop['port']
    #charset = prop['charset']

    log.debug('Starting Ips Sdee fethcer for host %s and username %s' % (sid, username))

    """connect with SDEE and fetch the sdee data"""
    sdee = SDEE(user = username, password = password, host = ip, method = method, force = 'yes')
    try:
        sdee.open()
    except Exception, err:
        log.warn("Cannot open SDEE server : %r", err)
        return

    while 1:
        try:
            sdee.get()
        except Exception, e:
            log.error("Exception thrown in sdee.get(), %s", e)
            log.error("Attempting to re-connect to the sensor:  %s", sid)
            sdee._subscriptionid = ""

            sdee.open()
            log.info("Successfully connected to: %s", sid)
            log.info("host = %s ; SessionID= %s ; SubscriptionID = %s", sid, sdee._sessionid , sdee._subscriptionid)
            continue

        try:
            result_xml = sdee.data()
        except Exception, e:
            log.error("No sdee data obtained. %s", repr(e))

        try:
            #result_xml = open('IPS SDEE output.xml','r').read()

            alert_obj_list = idsmxml.parse_alerts( result_xml )

            """testing the sample xml against riteshxml.parser"""
            #result_xml = open('result.xml','r').read()
            #log.info("Using riteshxml parser.")
            #alert_obj_list = riteshxml.parse_alerts( result_xml )
            """end of testing sample xml"""

            """testing the sample next result xml against riteshxml2.parser"""
            #result_xml = open('next_result.xml','r').read()
            #log.info("Using riteshxml2 parser.")
            #alert_obj_list = riteshxml2.parse_alerts( result_xml )
            """end of testing next sample xml"""

            """testing the IPS SDEE output against ipssdee parser"""
            #result_xml = open('IPS SDEE output.xml','r').read()
            #log.info("Using ipssdee parser.")
            #alert_obj_list = ips_sdee_parser.parse_alerts( result_xml )
            """end of testing """


        except Exception, e:
            alert_obj_list = []
            log.error("Exception thrown while parsing SDEE payload: %s", repr(e))

        log.debug("Preparing alert_obj list")
        if alert_obj_list:
            for alerts in alert_obj_list:
                #print "alert_time: %s, severity: %s, signature: %s, description: %s, attacker: %s, targets: %i" % (alerts.alert_time,
                #        alerts.severity, alerts.signature.id, alerts.signature.sigdetail, alerts.attacker.addr, len(alerts.target_list) )


                try:
                    event = get_event(alerts)
                    event['msg'] = alerts.xml
                    """Comment/Uncomment here for testing using riteshxml"""
                    #log.info("Using ips sdee getevent.")
                    #event = riteshxml2.get_event(alerts)
                    #log.warn("event is : %s", event)
                except Exception, e:
                    event = {}
                    log.error("Could not create the events from metadata. %s", repr(e))


                #event['msg'] = result_xml
                ### yeta baata event hadle garna baaaki cha
                if event:
                    _handle_data(event, ip, col_type, device_name, collected_at, normalizer, repo, ipssdee_out)

        gevent.sleep(seconds)

def _run(func, args, seconds):
    while True:
        func(*args)
        gevent.sleep(seconds)

def schedule(func, args, seconds):
    log.debug("Inside the schedule")
    return gevent.spawn_link_exception(_run, func, args, seconds)


def update_jobs(config, running_ipssdee_jobs, ipssdee_out):
    for sid, prop in config['client_map'].iteritems():
        old_job = running_ipssdee_jobs.get(sid)

        if old_job:
            if old_job['prop'] == prop:
                continue
            else:
                old_job['ipssdee_job'].kill()

        log.debug('adding job for source: %s' % sid)
        interval = 10
        ipssdee_job = schedule(fetch_job, args=(sid, config, ipssdee_out), seconds=interval)
        running_ipssdee_jobs[sid] = dict(ipssdee_job=ipssdee_job, prop=prop)
        log.info(" runing ipssdee: %s", running_ipssdee_jobs[sid])

    # delete removed sources and kill their jobs
    # running_sid_jobs size may change during iteration so using .items()
    for sid, job in running_ipssdee_jobs.items():
        if sid not in config['client_map']:
            del running_ipssdee_jobs[sid]
            job['ipssdee_job'].kill()


def start(config, ipssdee_out):
    running_ipssdee_jobs = {}
    log_level = config["core"]["log_level"]
    log.debug("warning level set to %s", log_level)

    while True:
        try:
            #print "This is start"
            if config['_onreload'](timeout = 1):
                update_jobs(config, running_ipssdee_jobs, ipssdee_out)
        except Exception, e:
            log.error("Error occured on updating jobs. %s", repr(e))

