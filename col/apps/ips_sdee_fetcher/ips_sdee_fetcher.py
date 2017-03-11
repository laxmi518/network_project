#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import binascii
import base64
import logging as log

from libcol.collectors.pysdee.pySDEE import SDEE
from libcol.collectors.pysdee import idsmxml

from libcol.interface.fetcher_runner import FetcherRunner
from libcol.interface.fetcher_interface import Fetcher
from libcol.interface.field_type import *

import gevent

DONT_NORMALIZE = [
    "_normalized_fields", "_type_str", "_type_num", "_type_ip", "_counter", "col_ts",
    "normalizer", "repo", "device_ip", "device_name", "col_type", "collected_at", "msg", "mid"]


class IPSSDEEFetcher(Fetcher):

    def __init__(self, **args):
        super(IPSSDEEFetcher, self).__init__(**args)

    def _remove_NULL_fields(self, event):
        for k in event.keys():
            if event[k] is "NULL":
                log.debug("Removing NULL field %s", k)
                del event[k]
        return event

    def _fill_msg_types(self, ev):
        msg_types = {}
        for (k, v) in ev.iteritems():
            # print k, ": ", v
            if v and type(v) is not type(list()):
                if _is_valid_ipv4(v) or _is_valid_ipv6(v):
                    self.prepare_msgfilling(msg_types, k, TYPE_IP)
                    self.prepare_msgfilling(msg_types, k, TYPE_STR)
                elif _is_valid_num(v):
                    self.prepare_msgfilling(msg_types, k, TYPE_NUM)
                else:
                    self.prepare_msgfilling(msg_types, k, TYPE_STR)
            else:
                self.prepare_msgfilling(msg_types, k, TYPE_STR)
        #log.debug("msg_types: %s", msg_types)
        return msg_types

    def get_event(self, alerts):
        try:
            target_list = []
            alert_dict = {}
            for target in alerts.target_list:
                target_list.append((target.addr, target.port, target.locality))

            alert_dict["destination_list"] = target_list

            if alerts.globalCorrelationScore != "NULL":
                alert_dict["gc_score"] = alerts.globalCorrelationScore
                alert_dict["gc_riskdelta"] = alerts.globalCorrelationRiskDelta
                alert_dict[
                    "gc_riskrating"] = alerts.globalCorrelationModifiedRiskRating
                alert_dict[
                    "gc_deny_packet"] = alerts.globalCorrelationDenyPacket
                alert_dict[
                    "gc_deny_attacker"] = alerts.globalCorrelationDenyAttacker
            # else:
                #alert_dict["gc_score"] = "NULL"
            #    pass

            alert_dict["alert_time"] = alerts.alert_time
            alert_dict["event_id"] = alerts.eventid
            alert_dict["host_id"] = alerts.originator
            alert_dict["severity"] = alerts.severity
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

            alert_dict[
                "attack_relevance_rating"] = alerts.attackrelevancerating
            alert_dict["vlan"] = alerts.vlan
            alert_dict["interface"] = alerts.interface
            alert_dict["interface_group"] = alerts.intgroup

            alert_dict["context"] = alerts.context
            alert_dict["actions"] = alerts.actions
            alert_dict["ip_logging_activated"] = alerts.ipLoggingActivated
            alert_dict["shun_requested"] = alerts.shunRequested
            alert_dict["dropped_packet"] = alerts.droppedPacket
            alert_dict["denied_attacker"] = alerts.deniedAttacker
            alert_dict[
                "block_connection_requested"] = alerts.blockConnectionRequested
            alert_dict[
                "log_attacker_packets_activated"] = alerts.logAttackerPacketsActivated
            alert_dict[
                "log_victim_packets_activated"] = alerts.logVictimPacketsActivated
            alert_dict[
                "log_pair_packets_activated"] = alerts.logPairPacketsActivated
            alert_dict["snmp_trap_requested"] = alerts.snmpTrapRequested
            alert_dict[
                "denied_attacker_service_pair"] = alerts.deniedAttackerServicePair
            alert_dict[
                "denied_attacker_victim_pair"] = alerts.deniedAttackerVictimPair
            alert_dict["summary_count"] = alerts.summaryCount
            alert_dict["initial_alert"] = alerts.initialAlert

            try:
                if alerts.triggerpacket != "NULL":
                    trigger_packet_details = decode(alerts.triggerpacket)
                    alert_dict["trigger_packet"] = alerts.triggerpacket
                    alert_dict[
                        "trigger_packet_details"] = trigger_packet_details
                if alerts.fromtarget != "NULL":
                    fromTarget_details = decode(alerts.fromtarget)
                    alert_dict["from_target"] = alerts.fromtarget
                    alert_dict["from_target_details"] = fromTarget_details
                if alerts.fromattacker != "NULL":
                    fromAttacker_details = decode(alerts.fromattacker)
                    alert_dict["from_attacker"] = alerts.fromattacker
                    alert_dict["from_attacker_details"] = fromAttacker_details
            except Exception, err:
                log.info(
                    "ERROR -  exception caught while getting trigger_packet: %s", err)

            if alert_dict["initial_alert"] != "NULL":
                alert_dict["event_id"] = alert_dict["initial_alert"]

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
                log.warn(
                    "ERROR -  exception caught while writing event: %s", e)

            alert_dict["destination_list"] = str(
                alert_dict["destination_list"])
            return alert_dict

        except Exception, e:
            log.warn("ERRROR - Exception while creating alerts:: %s", e)

    def get_event_old(self, alerts):
        target_list = []
        alert_dict = {}
        for target in alerts.target_list:
            #,target.locality))
            target_list.append((target.addr, target.port, target.locality))

        alert_dict["target_list"] = str(target_list)
        if hasattr(alerts, 'isDropped') and alerts.isDropped != "NULL":
            alert_dict["isDropped"] = alerts.isDropped
        else:
            alert_dict["isDropped"] = "NULL"

        if hasattr(alerts, 'globalCorrelationScore') and alerts.globalCorrelationScore != "NULL":
            alert_dict["gc_score"] = alerts.globalCorrelationScore
            alert_dict["gc_riskdelta"] = alerts.globalCorrelationRiskDelta
            alert_dict[
                "gc_riskrating"] = alerts.globalCorrelationModifiedRiskRating
            alert_dict["gc_deny_packet"] = alerts.globalCorrelationDenyPacket
            alert_dict[
                "gc_deny_attacker"] = alerts.globalCorrelationDenyAttacker
        else:
            alert_dict["gc_score"] = "NULL"

        alert_dict["alert_time"] = alerts.alert_time
        alert_dict["eventid"] = alerts.eventid
        alert_dict["hostId"] = alerts.originator
        alert_dict["severity"] = alerts.severity
        if hasattr(alerts, 'appname'):
            alert_dict["app_name"] = alerts.appname
        if hasattr(alerts, 'appInstanceId'):
            alert_dict["appInstanceId"] = alerts.appInstanceId

        alert_dict["signature"] = alerts.signature.sigid
        alert_dict["subSigid"] = alerts.signature.subsig
        alert_dict["description"] = alerts.signature.sigdetail
        alert_dict["sig_version"] = alerts.signature.sigversion
        if hasattr(alerts.signature, 'sigcreated'):
            alert_dict["sig_created"] = alerts.signature.sigcreated
        if hasattr(alerts.signature, 'sigtype'):
            alert_dict["sig_type"] = alerts.signature.sigtype
        if hasattr(alerts.signature, 'marsCategory'):
            alert_dict["mars_category"] = alerts.signature.marsCategory

        alert_dict["attacker"] = alerts.attacker.addr
        if hasattr(alerts.attacker, 'locality'):
            alert_dict["attacker_locality"] = alerts.attacker.locality
        alert_dict["attacker_port"] = str(alerts.attacker.port)

        alert_dict["protocol"] = alerts.protocol
        alert_dict["risk_rating"] = str(alerts.riskrating)
        if hasattr(alerts, 'threatrating'):
            alert_dict["threat_rating"] = str(alerts.threatrating)
        if hasattr(alerts, 'targetvaluerating'):
            alert_dict["target_value_rating"] = str(alerts.targetvaluerating)

        if hasattr(alerts, 'attackrelevancerating'):
            alert_dict["attack_relevance_rating"] = str(
                alerts.attackrelevancerating)
        if hasattr(alerts, 'vlan'):
            alert_dict["vlan"] = alerts.vlan
        if hasattr(alerts, 'interface'):
            alert_dict["interface"] = alerts.interface
        if hasattr(alerts, 'intgroup'):
            alert_dict["interface_group"] = alerts.intgroup
        target_list_string = ""
        packet_info = ""
        try:
            if alerts.triggerpacket != "NULL":
                trigger_packet_details = decode(alerts.triggerpacket)
                packet_info = ' trigger_packet="' + alerts.triggerpacket + \
                    '" trigger_packet_details="' + trigger_packet_details + '"'
            if alerts.fromtarget != "NULL":
                fromTarget_details = decode(alerts.fromtarget)
                packet_info = packet_info +  ' fromTarget="' + \
                    alerts.fromtarget + '" fromTarget_details="' + \
                    fromTarget_details + '"'
            if alerts.fromattacker != "NULL":
                fromAttacker_details = decode(alerts.fromattacker)
                packet_info = packet_info +  ' fromAttacker="' + alerts.fromattacker + \
                    '" fromAttacker_details="' + fromAttacker_details + '"'
        except:
            log.info('Cannot obtain trigger_packet')
        try:
            for target in alert_dict["target_list"]:
                target_list_string = target_list_string + ' target="' + \
                    target[0] + '" target_port="' + str(
                        target[1]) + '" target_locality="' + str(target[2]) + '" '
        except Exception, e:
            log.info('Cannot create the targer list string. %s', repr(e))

        return alert_dict

    def fetch_job(self):
        global LAST_COL_TS
        global LOG_COUNTER

        log.debug('Starting Ips Sdee fethcer for host %s and username %s' %
                  (self.sid, self.username))

        """connect with SDEE and fetch the sdee data"""
        password = self.get_decrypted_password(self.password)
        sdee = SDEE(
            user=self.username, password=password, host=self.device_ip, method="https",
            force="yes")
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
                log.error(
                    "Attempting to re-connect to the sensor:  %s", self.sid)
                sdee._subscriptionid = ""

                sdee.open()
                log.info("Successfully connected to: %s", self.sid)
                log.info("host = %s ; SessionID= %s ; SubscriptionID = %s",
                         self.sid, sdee._sessionid, sdee._subscriptionid)
                continue

            try:
                result_xml = sdee.data()
            except Exception, e:
                log.error("No sdee data obtained. %s", repr(e))

            try:
                # result_xml = open('IPS SDEE output.xml', 'r').read()

                alert_obj_list = idsmxml.parse_alerts(result_xml)

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
                log.error(
                    "Exception thrown while parsing SDEE payload: %s", repr(e))

            log.debug("Preparing alert_obj list")
            if alert_obj_list:
                for alerts in alert_obj_list:
                    # print "alert_time: %s, severity: %s, signature: %s, description: %s, attacker: %s, targets: %i" % (alerts.alert_time,
                    # alerts.severity, alerts.signature.id,
                    # alerts.signature.sigdetail, alerts.attacker.addr,
                    # len(alerts.target_list) )

                    try:
                        event = self.get_event(alerts)
                        event['msg'] = alerts.xml
                        """Comment/Uncomment here for testing using riteshxml"""
                        #log.info("Using ips sdee getevent.")
                        #event = riteshxml2.get_event(alerts)
                        #log.warn("event is : %s", event)
                    except Exception, e:
                        event = {}
                        log.error(
                            "Could not create the events from metadata. %s", repr(e))

                    #event['msg'] = result_xml
                    # yeta baata event hadle garna baaaki cha
                    if event:
                        event = self._remove_NULL_fields(event)
                        msg_types_dict = self._fill_msg_types(event)
                        event.update(msg_types_dict)
                        event = prepare_normalized_event(event)
                        self.add_event(event)

            # gevent.sleep(self.fetch_interval)
            gevent.sleep(30)


def prepare_normalized_event(event):
    """ Make a _normalized_fields dict for Normalized key value pair from event."""
    normalized_event = {}
    _normalized_fields = {}
    for key, value in event.iteritems():
        if key in DONT_NORMALIZE:
            normalized_event[key] = value
        else:
            _normalized_fields[key] = value
    if _normalized_fields:
        normalized_event["_normalized_fields"] = _normalized_fields
    return normalized_event


def _is_valid_ipv4(address):
    """
    Return True if address is valid ipv4 else return false
    """
    try:
        addr = socket.inet_aton(address)
    except socket.error:
        return False
    return address.count('.') == 3
    return True


def _is_valid_ipv6(address):
    """
    Return True if address is valid ipv6 else return false
    """
    try:
        addr = socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True


def _is_valid_num(s):
    """
    Return True if given str is num else return false
    """
    try:
        float(s)  # for int, long and float
    except ValueError:
        try:
            complex(s)  # for complex
        except ValueError:
            return False
    return True


def decode(data):
    """
    Return the base base64 decoded dataa else return '-'
    """
    try:
        decode = base64.b64decode(data)
        return binascii.b2a_qp(decode)
    except:
        return "-"


runner = FetcherRunner()
runner.register_fetcher(IPSSDEEFetcher)
runner.start()
