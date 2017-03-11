
import netaddr
from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.carrier.asynsock.dgram import udp6
import socket
import re
import logging
from pysnmp.smi import view
from pyasn1.error import PyAsn1Error
from pysnmp.proto.rfc1905 import NoSuchInstance

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

def _get_mib_viewer(mib_dir, mib_modules, cmdGen):
    mibBuilder = cmdGen.mibViewController.mibBuilder

    mibView = view.MibViewController(mibBuilder)

    return mibView

def get_community_function(prop):
    if prop["snmp_version"] == 'v_12':
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

def test(prop, ip):
    result, _type_lookup = {'msg' : ''}, {}

    cmdGen = cmdgen.CommandGenerator()

    c_function = get_community_function(prop)
    if c_function == None:
        return {'success':False, 'ip':ip, 'message':'Invalid Version'}

    transport_function = get_transport_function(ip, prop['port'])
    if transport_function == None:
        return {'success':False, 'ip':ip, 'message':'Invalid ip'}

    for oid, time in prop['oids'].iteritems():
        walk_flag = True
        try:
            (errorIndication, errorStatus, errorIndex,
                         varBindTable) = cmdGen.nextCmd (
                                            c_function,
                                            transport_function,
                                            str(oid)
                                        )
            if not varBindTable:
                (errorIndication, errorStatus, errorIndex,
                        varBindTable) = cmdGen.getCmd (
                                    c_function,
                                    transport_function,
                                    str(oid)
                                    )
                walk_flag = False
        except PyAsn1Error, err:
            logging.warn(err)
            return {'success':False, 'ip':ip, 'message':str(err)}
        except Exception, err:
            return {'success':False, 'ip':ip, 'message':str(err)}

        if not walk_flag:
            if not varBindTable:
                logging.warn('%s for %s' % (oid, errorIndication))
                return {'success':False, 'ip':ip, 'message':'%s for %s' % (oid, errorIndication)}
            if isinstance(varBindTable[0][1], NoSuchInstance):
                logging.warn("%s = No Such Instance currently exists at this OID" % varBindTable[0][0].prettyPrint())
                return {'success':False, 'ip':ip, 'message':"%s = No Such Instance currently exists at this OID" % varBindTable[0][0].prettyPrint()}
        if errorIndication and not varBindTable:
            logging.warn(errorIndication)
            return {'success': False, 'message':'%s oid does not work. Reason : %s' % (str(oid) ,str(errorIndication)), 'ip':ip}
        else:
            if errorStatus:
                logging.warn( '%s at %s\n' % (
                    errorStatus.prettyPrint (),
                    errorIndex and varBindTable[-1][int (errorIndex) - 1] or '?'
                    ))
                return {'ip':ip,'success':False, 'message':'%s oid does not work. Reason : %s at %s' % (str(oid), (errorStatus.prettyPrint (),
                            errorIndex and varBindTable[-1][int (errorIndex) - 1] or '?') )}
            else:
                continue
    return {'ip':ip,'success':True, 'message':'SNMP Fetcher working properly'}


if __name__ == '__main__':
    snmp = {'ver':'v_12','community_string':'public', 'oids' : ["1.3.6.1.2.1.4.22.1" , "1.3.6.1.2.1.1.3", "1.3.6.1.4.1.2021.4"]}
    ip = '127.0.0.1'

    print test(snmp, ip)

