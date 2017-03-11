
import binascii
import base64

import logging
import xml.dom.minidom

def decode(data):
	try:
		decode = base64.b64decode(data)
		return binascii.b2a_qp(decode)
	except:
		return "-"


class Participant:

	def __init__(self, **kwargs):

		try: self.xml = kwargs['xml']
		except: self.xml = ''

		try: self.addr = kwargs['addr']
		except: self.addr = ''

		try: self.port = kwargs['port']
		except: self.port = 0

class Signature:

	def __init__(self, **kwargs):

		try: self.xml = kwargs['xml']
		except: self.xml = ''
	
		try: self.id = kwargs['sigid'] 	
		except: self.id = 0

		try: self.version = kwargs['sigversion']
		except: self.version = ''

		try: self.subsig = kwargs['subsig']
		except: self.subsig = 0

		try: self.sigdetail = kwargs['sigdetail']
		except: self.sigdetail = ''

class Alert:

	def __init__(self, **kwargs):

		try: self.xml = kwargs['xml']
		except: self.xml = ''

		try: self.eventid = kwargs['eventid']
		except: self.eventid = 0

		try: self.severity = kwargs['severity']
		except: self.severity = ''

		try: self.originator = kwargs['originator']
		except: self.originator = ''

		try: self.alert_time = kwargs['alert_time']
		except: self.alert_time = 0

		try: self.signature = kwargs['signature']
		except: self.signature = Signature()

		try: self.attacker = kwargs['attacker']
		except: self.attacker = Participant()

		try: self.target_list = kwargs['target_list']
		except: self.target_list = []

		try: self.riskrating = kwargs['riskrating']
		except: self.riskrating = 0

		try: self.protocol = kwargs['protocol']
		except: self.protocol = ''

def build_global(node):

	alert = Alert()
	alert.xml = node.toxml()
	alert.eventid = node.attributes['eventId'].nodeValue
	print "Inside build global of sdee parser: EventId = ", alert.eventid
	alert.severity = node.attributes['severity'].nodeValue
	alert.originator = node.getElementsByTagName('sd:originator')[0].getElementsByTagName('sd:hostId')[0].firstChild.wholeText
	alert.alert_time = node.getElementsByTagName('sd:time')[0].firstChild.wholeText
	alert.riskrating = node.getElementsByTagName('cid:riskRatingValue')[0].firstChild.wholeText
	alert.protocol = node.getElementsByTagName('cid:protocol')[0].firstChild.wholeText
	print "ALERT LIST ---", alert
	return alert

def build_sig(node):
	signature = Signature()
	signature.xml = node.toxml()	
	signature.sigid = node.attributes['id'].nodeValue
	signature.sigversion = node.attributes['cid:version'].nodeValue
	signature.subsig = node.getElementsByTagName('cid:subsigId')[0].firstChild.wholeText

	try:
		signature.sigdetail = node.getElementsByTagName('cid:sigDetails')[0].firstChild.wholeText
	except:
		signature.sigdetail = node.attributes['description'].nodeValue

	return signature

def build_participant(node):

	targetlist = node.getElementsByTagName('sd:target')
	attacklist = node.getElementsByTagName('sd:attacker')
	if len(attacklist) == 1:
		attacker = Participant(xml=attacklist[0].toxml())
		attacker.addr = attacklist[0].getElementsByTagName('sd:addr')[0].firstChild.wholeText
		try:
			attacker.port = attacker.getElementsByTagName('sd:port')[0].firstChild.wholeText
		except:
			attacker.port = '0'
	targetlist = []
	nodelist = node.getElementsByTagName('sd:target')
	for item in nodelist:
		target = Participant(xml=item.toxml())
		target.addr = item.getElementsByTagName('sd:addr')[0].firstChild.wholeText
		try:
			target.port = item.getElementsByTagName('sd:addr')[0].firstChild.wholeText
		except:
			target.port = '0'
		
		targetlist.append(target)

	return attacker, targetlist	

def parse_alerts(xmldata):

	doc = xml.dom.minidom.parseString(xmldata)
	alertlist = doc.getElementsByTagName('sd:evIdsAlert')
	#print "sd: ", sd
	print "alert list from ipssdee", alertlist
	alert_obj_list = []	
	for alert in alertlist:

		alert_obj = build_global(alert)
		print "this is event id: ", alert_obj.eventid
		sig = alert.getElementsByTagName('sd:signature')
		alert_obj.signature = build_sig(sig[0])

		participants = alert.getElementsByTagName('sd:participants')
		alert_obj.attacker, alert_obj.target_list = build_participant(participants[0])
	
		alert_obj_list.append(alert_obj)	

	
#	for alerts in alert_obj_list:
#		print "alert_time: %s, severity: %s, signature: %s, description: %s, attacker: %s, targets: %i" % (alerts.alert_time, 
#					alerts.severity, alerts.signature.id, alerts.signature.sigdetail, alerts.attacker.addr, len(alerts.target_list) )
	
	return alert_obj_list
	
def get_event(alerts):
    #alert_dict = {}
    #for alerts in alert_obj_list:
    
        target_list = []
        alert_dict = {}
        for target in alerts.target_list:
            target_list.append((target.addr,target.port))    #,target.locality))
        
        alert_dict["target_list"] = target_list
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
            logging.error('Exception caught while getting trigger_packet')
        try:
            for target in alert_dict["target_list"]:
                target_list_string = target_list_string + ' target="'+target[0]+'" target_port="'+str(target[1])+'" target_locality="'+str(target[2])+'" '
        except Exception, e:
            logging.warning('Cannot create the targer list string. %s', repr(e))
            
        return alert_dict
  
