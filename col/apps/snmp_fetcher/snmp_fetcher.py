#!/usr/bin/env python

from gevent import monkey
monkey.patch_all()

import re
import logging
import netaddr
import socket

import gevent
import gevent.queue

from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.carrier.asynsock.dgram import udp6
from pysnmp.smi import view, builder
from pyasn1.error import PyAsn1Error
from pysnmp.smi.error import NoSuchObjectError, SmiError, InconsistentValueError
from pysnmp.proto.rfc1905 import NoSuchInstance


from libcol.interface.fetcher_runner import FetcherRunner
from libcol.interface.fetcher_interface import Fetcher
from libcol.interface.field_type import TYPE_NUM, TYPE_STR, TYPE_IP

from mib_loader import load_mibs, mib_dir

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


class SnmpFetcher(Fetcher):

    class OidMapper:
        mapper = {}
        (
        mapper['INTEGER'],
        mapper['INTEGER32'],
        mapper['TIMETICKS'],
        mapper['COUNTER32'],
        mapper['COUNTER64'],
        mapper['GAUGE32'],
        mapper['OCTETSTRING'],
        mapper['OID'],
        mapper['HEXSTRING'],
        mapper['PHYSADDRESS'],
        mapper['IPADDRESS']
        ) = range(11)

    """
    Loaded modules can be reused across instances.
    """
    MibModules = load_mibs()

    def __init__(self, **args):
        super(SnmpFetcher, self).__init__(**args)

        self.pattern = re.compile('[\W]+')

        self.event_queue = gevent.queue.JoinableQueue()
        self.initialize_snmpfetcher_engine()

    def initialize_snmpfetcher_engine(self):
        """
        Intitializes cmdGen
        Initializes community function
        Initializes transport function
        Initializes Mib Viewer
        """
        self.cmdGen = cmdgen.CommandGenerator()
        self.initialize_community_function()
        self.initialize_transport_function()
        self.initialize_mib_viewer()

    def initialize_community_function(self):
        if self.snmp_version == 'v12':
            community_string = self.community_string
            self.community_function = cmdgen.CommunityData('test-agent', community_string)

        elif self.snmp_version == 'v3':
            self.community_function = cmdgen.UsmUserData(self.username, self.auth_key, self.prive_key)
        else:
            self.community_function = None

    def initialize_transport_function(self):
        if '%' in self.device_ip:
            ip, interface = self.device_ip.split('%', 1)
            if not re.match('[a-z][a-z0-9]+$', interface):
                logging.warn("Invalid IP Address")
                self.device_ip = None
            else:
                self.transport_function = Udp6TransportTarget((ip, self.port))

        elif netaddr.valid_ipv4(self.device_ip):
            self.transport_function = cmdgen.UdpTransportTarget ( (self.device_ip, self.port) )

        elif netaddr.valid_ipv6(self.device_ip):
            self.transport_function = Udp6TransportTarget ( (self.device_ip, self.port) )

    def initialize_mib_viewer(self):
        '''
        The mibBuilder.loadModules() can be used to load mib modules
        that can be used for mib lookup.
    #    Currently the lookup has been disabled.
        '''
        mibBuilder = self.cmdGen.mibViewController.mibBuilder
        for path in mib_dir.split(":"):
            mibPath = mibBuilder.getMibSources() + \
                (builder.DirMibSource(str(path)),)
            mibBuilder.setMibSources(*mibPath)
        for module in SnmpFetcher.MibModules:
            try:
                mibBuilder.loadModules(module)
            except SmiError, msg:
                logging.warn("Error loading mib module (%s), error=(%s)", module, msg)
                pass

        self.mibView = view.MibViewController(mibBuilder)

    def mib_lookup(self, oid, val):
        (symName, modName), indices = cmdgen.mibvar.oidToMibName(
            self.cmdGen.mibViewController, oid
            )
        val = cmdgen.mibvar.cloneFromMibValue(
                  self.cmdGen.mibViewController, modName, symName, val
          )
        modName = '_'.join(modName.split('-'))
        inid = ['_'.join(all.prettyPrint().split('.')) for all in indices]

        oid = '%s_%s_%s' % (modName, symName, '_'.join(map(lambda v: v, inid)))
        oid_val = val.prettyPrint()
        msg = '%s_%s_%s = %s' % (modName, symName, '.'.join(map(lambda v: v, inid)), oid_val)
        oid_val_type = self.get_oid_value_type(oid_val)
        event = (msg, oid, oid_val, oid_val_type)

        return event

    def non_mib_lookup(self, oid, val):
        name, label, suffix = self.mibView.getNodeName(oid)
        oidLabel = "_".join(map(str, label))
        oidSuffix = "_".join(map(str, suffix))

        oid = '%s_%s' % (oidLabel, oidSuffix)
        oid_val = val.prettyPrint()
        msg = '%s_%s = %s' % (oidLabel, oidSuffix, oid_val)
        oid_val_type = self.get_oid_value_type(oid_val)
        event = (msg, oid, oid_val, oid_val_type)

        return event

    def get_oid_value_type(self, oid_value):
        """
        Returns the type of the value of the given OID
        For eg. if an OID has key, value 1.3.x.x.x.x.2021.2.3.1=Integer(5),
        Then it returns Integer
        """
        return str(oid_value.__class__).split('.')[-1:][0].upper()

    def get_prepare_type(self, _type):
        """
        This method returns the type required for prepare event.
        What it basically does is map the oid_value type to one of the types defined
        in interface.field_types
        """

        if SnmpFetcher.OidMapper.mapper.get(_type.upper()) in range(6):
            return TYPE_NUM
        if SnmpFetcher.OidMapper.mapper.get(_type.upper()) in range(6, 10):
            return TYPE_STR
        if SnmpFetcher.OidMapper.mapper.get(_type.upper()) in range(10, 11):
            return TYPE_IP

        #default
        return TYPE_STR

    def execute_oid_query(self):
        """
        Execute cmdGen.nextCmd or cmdGen.getCmd command to retrieve snmpdata for self.oid
        """
        walk_flag = True
        try:
            (errorIndication, errorStatus, errorIndex,
                         varBindTable) = self.cmdGen.nextCmd (
                                            self.community_function,
                                            self.transport_function,
                                            (self.oid)
                                        )
            if not varBindTable:
                (errorIndication, errorStatus, errorIndex,
                        varBindTable) = self.cmdGen.getCmd (
                                    self.community_function,
                                    self.transport_function,
                                    (self.oid)
                                    )
                walk_flag = False
        except PyAsn1Error, err:
            logging.warn(err)
            return False

        except Exception, err:
            logging.warn(err)
            return False

        if not walk_flag:
            if not varBindTable:
                logging.warn('%s = %s' % (self.oid, errorIndication))
                return False

            if isinstance(varBindTable[0][1], NoSuchInstance):
                logging.warn("%s = No Such Instance currently exists at this OID" % varBindTable[0][0].prettyPrint())
                return False

        if errorIndication and not varBindTable:
            logging.warn(errorIndication)
            return False
        else:
            if errorStatus:
                logging.warn( '%s at %s\n' % (
                    errorStatus.prettyPrint (),
                    errorIndex and varBindTable[-1][int (errorIndex) - 1] or '?'
                    ))
                return False
            else:
                if not walk_flag:
                    varBindTable = [varBindTable]

                return varBindTable

    def add_result(self, result):
        self.event_queue.put(result)

    def terminate_event_handler(self):
        self.add_result(None)

    def event_handler(self):
        """
        Waits for a result. When a result is recieved, further processing on it
        1) MibLookup
        2) Prepare
        3) Add
        is done
        """

        while True:
            event = self.event_queue.get()
            try:
                if not event:
                    break
                oid, value = event.items()[0]
                try:
                    (msg, oid, value, val_type) = self.mib_lookup(oid, value)
                #except (NoSuchObjectError, InconsistentValueError):
                except Exception:
                    (msg, oid, value, val_type) = (self.non_mib_lookup(oid, value))
                    #(msg, oid, value, val_type) = ("%s = %s" % (oid, value), oid, value, TYPE_STR)

                evt = {}
                evt['msg'] = msg
                self.prepare_event(evt, 'msg', msg)
                self.prepare_event(evt, oid, value, self.get_prepare_type(val_type))
                self.add_event(evt)
            finally:
                self.event_queue.task_done()

    def data_fetcher(self):
        """
        Quries self.oid and adds the result to the event_queue for further processing
        """
        result = self.execute_oid_query()

        if result:
            for row in result:
                for oid, val in row:
                    self.add_result({oid:val})

        """
        Now the fetching for this cycle has been complete
        We have to end the event_handler as well after it has completed handling all the
        added results
        """
        gevent.sleep(0)

        """
        Send a dummy data to the event handler so that it can exit its event looop
        """
        self.terminate_event_handler()

    def fetch_job(self):
        try:
            generator = gevent.spawn_link_exception(self.data_fetcher)
            handler = gevent.spawn_link_exception(self.event_handler)
            gevent.joinall([generator, handler])
        except gevent.GreenletExit, err:
            logging.warn(err)
        except Exception, err:
            logging.warn(err)


runner = FetcherRunner()
runner.register_fetcher(SnmpFetcher)
runner.start()



