#!/usr/bin/env python
"""
SNMP trap listener. It listens for the SNMP traps from the client devices and
sends it to the upper layer
"""
import time
from pylib import logger, conf, wiring, msgfilling
from pylib.wiring import gevent_zmq as zmq
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.entity import engine, config
from pysnmp.carrier.asynsock.dgram import udp, udp6
from pysnmp.smi import builder, view

log = logger.getLogger(__name__)

SNMP_TRAP_OID = (1,3,6,1,6,3,1,1,4,1)
SNMP_SYS_UPTIME = (1,3,6,1,2,1,1,3)

def _parse_args():
    options, app_config = conf.parse_config()
    return app_config

#Callback function for receiving notifications
def cbFun(snmpEngine, stateReference, contextEngineId, contextName,varBinds, cbCtx):
    snmptrapd_out = cbCtx.get("out_wire")
    snmptrapd_out.start_benchmarker_processing()

    event = {"_normalized_fields": {}}
    MIBView = cbCtx.get("MIBView")
    last_col_ts = cbCtx.get("last_col_ts")
    log_counter = cbCtx.get("log_counter")
    app_config = cbCtx.get("app_config")

    transportDomain, transportAddress = snmpEngine.msgAndPduDsp.getTransportInfo(stateReference)
    log_msg = 'Notification from %s :\n' % str(transportAddress)
    log.debug("SNMP Trap; Notification received; client_ip=%s", str(transportAddress))

    #check if from valid client address
    client_list = app_config["client_list"]
    loginspect_name = app_config["loginspect_name"]
    if not transportAddress[0] in client_list:
        log.warn("SNMP Trap; warning; being sent from unregistered IP (%s)", transportAddress[0])
        return

    col_ts = int(time.time())
    if col_ts > last_col_ts:
        last_col_ts = col_ts
        log_counter = 0

    type_str = "msg "
    type_num = ""

    for name, val in varBinds:
        oid, label, suffix = MIBView.getNodeName(name)
        oidLabel = ".".join(map(str, label))
        oidSuffix = ".".join(map(str, suffix))
        oid_string = oid.prettyPrint()
        value = val.prettyPrint()

        log_msg += "%s (%s %s) = %s\n" % (oid_string, oidLabel, oidSuffix, value)

        if  (name[:10] == SNMP_TRAP_OID):
            oid, label, suffix = MIBView.getNodeName(val)
            oidLabel = ".".join(map(str, label))
            oidSuffix = ".".join(map(str, suffix))
            log_msg += "     The snmp trap %s (%s %s) received\n" % (value, oidLabel, oidSuffix)
            oid_string = "snmp_trap_oid"

        if  (name[:8] == SNMP_SYS_UPTIME):
            oid_string = "sys_uptime"

        if value.isdigit():
            #print "Integer Value found ",  val, " =", value
            event["_normalized_fields"][oid_string] = int(value)
            #event[oid_string] =  int(value)
            type_num += oid_string +" "
        else:
            event["_normalized_fields"][oid_string] = value
            #event[oid_string] = value
            type_str += oid_string +" "

    #send to the upper layer
    log_counter += 1
    device_ip = transportAddress[0]
    device_name = app_config["name_ip_mapping"][device_ip]
    sid = 'snmp|%s' % device_ip
    event['mid'] = '%s|%s|%d|%d' % (loginspect_name, sid, col_ts, log_counter)
    
    event['col_type'] = 'snmp'
    event['col_ts'] = col_ts
    event['_counter'] = log_counter
    type_num += 'col_ts '
    type_str += 'col_type '
    
    event['device_ip'] = device_ip
    type_str += 'device_ip '

    event['msg'] = log_msg
    event['_type_str'] = type_str.strip()
    event['_type_num'] = type_num.strip()
    event['_type_ip'] = 'device_ip'
    event['device_name'] = device_name
    event['collected_at'] = loginspect_name
    event['device_ip'] = device_ip
    
    normalizer = app_config["repo_norm_mapping"][device_ip]["normalizer"]
    repo = app_config["repo_norm_mapping"][device_ip]["repo"]

    msgfilling.add_types(event, '_type_str', 'device_ip device_name collected_at')

    event['normalizer'] = normalizer
    event['repo'] = repo
    snmptrapd_out.send_with_norm_policy_and_repo(event)

    cbCtx["last_col_ts"] = last_col_ts
    cbCtx["log_counter"] = log_counter

def getMIBViewer():
    # Create MIB loader/builder
    mibBuilder = builder.MibBuilder()

#    log.info('Loading MIB modules...')
#    mibBuilder.loadModules(
#        'SNMPv2-MIB', 'SNMP-FRAMEWORK-MIB', 'SNMP-COMMUNITY-MIB', "IF-MIB"
#        )
#    log.info('done')

    log.info('Indexing MIB objects...')
    mibView = view.MibViewController(mibBuilder)
    log.info('done')

    return mibView

def getSNMPEngine(address4, address6, snmpv12_agents, SNMPv3_users):
    # Create SNMP engine with autogenernated engineID and pre-bound
    # to socket transport dispatcher
    snmpEngine = engine.SnmpEngine()

    # Setup transport endpoint
    config.addSocketTransport(
        snmpEngine,
        udp.domainName,
        udp.UdpSocketTransport().openServerMode(address4)
        )

    config.addSocketTransport(
        snmpEngine,
        udp6.domainName,
        udp6.Udp6SocketTransport().openServerMode(address6)
        )
    log.info("SNMP Trap; listening; msg=SNMP Trap daemon listening on UDP address %s and %s", address4, address6)

    # v1/2 setup
    for agent in snmpv12_agents:
        agent_val = snmpv12_agents.get(agent)
        community_string = agent_val.get("community_string")
        if community_string :
            config.addV1System(snmpEngine, agent, community_string)
            log.info("SNMP Trap; registering; Registered agent %s", agent)

    # v3 setup
    for user in SNMPv3_users:
        user_val = SNMPv3_users.get(user)
        user_auth_key = user_val.get("auth-key")
        user_priv_key = user_val.get("priv-key")
        if user_auth_key and user_priv_key:
            config.addV3User(snmpEngine, user,
                config.usmHMACMD5AuthProtocol, user_auth_key,
                config.usmDESPrivProtocol, user_priv_key
            )
            log.info("SNMP Trap; registering; Registered snmp v3 user %s", user)

    return snmpEngine

def main():
    app_config = _parse_args()

    port = app_config["port"]
    address4 = ('0.0.0.0', port)
    address6 = ('::1', port)

    zmq_context = zmq.Context()
    snmptrapd_out = wiring.Wire('collector_out', zmq_context=zmq_context,
                                        conf_path=app_config.get('wiring_conf_path') or None)

    snmpEngine = getSNMPEngine(address4, address6, app_config["snmpv12_agents"], app_config["SNMPv3_users"])
    cbCtx = {"out_wire" : snmptrapd_out, "MIBView" : getMIBViewer(), "app_config": app_config,
             "last_col_ts": 0, "log_counter": 0}
    ntfrcv.NotificationReceiver(snmpEngine, cbFun, cbCtx)
    snmpEngine.transportDispatcher.jobStarted(1) # this job would never finish
    snmpEngine.transportDispatcher.runDispatcher()

if __name__ == '__main__':
    main()
