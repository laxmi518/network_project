
import xml.dom.minidom

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
	alert.severity = node.attributes['severity'].nodeValue
	alert.originator = node.getElementsByTagName('sd:originator')[0].getElementsByTagName('sd:hostId')[0].firstChild.wholeText
	alert.alert_time = node.getElementsByTagName('sd:time')[0].firstChild.wholeText
	alert.riskrating = node.getElementsByTagName('cid:riskRatingValue')[0].firstChild.wholeText
	alert.protocol = node.getElementsByTagName('cid:protocol')[0].firstChild.wholeText

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
			target.port = item.getElementsByTagName('sd:port')[0].firstChild.wholeText
		except:
			target.port = '0'
		
		targetlist.append(target)

	return attacker, targetlist	

def parse_alerts(xmldata):

	doc = xml.dom.minidom.parseString(xmldata)
	alertlist = doc.getElementsByTagName('sd:evIdsAlert')

	alert_obj_list = []	
	for alert in alertlist:

		alert_obj = build_global(alert)
		
		sig = alert.getElementsByTagName('sd:signature')
		alert_obj.signature = build_sig(sig[0])

		participants = alert.getElementsByTagName('sd:participants')
		alert_obj.attacker, alert_obj.target_list = build_participant(participants[0])
	
		alert_obj_list.append(alert_obj)	

	
#	for alerts in alert_obj_list:
#		print "alert_time: %s, severity: %s, signature: %s, description: %s, attacker: %s, targets: %i" % (alerts.alert_time, 
#					alerts.severity, alerts.signature.id, alerts.signature.sigdetail, alerts.attacker.addr, len(alerts.target_list) )
	
	return alert_obj_list
	
