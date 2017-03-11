
import os
import re
import base64
import json
import logging as log
from jinja2 import Template, TemplateSyntaxError
from flask import Markup
from pylib import disk, homing, textual
from lib import dboperation
from views.contrib.mongoid import is_mongokit_objectid
from pluggables.modules.Notification.controller import Notification

ALERT_TEMPLATES_PATH = homing.home_join('storage/alerttemplates/')
ALERT_SSH_CERTIFICATES_PATH = homing.home_join('storage/alertssh/')

class NewTestEmailNotification(Notification):
    def __init__(self, classname, source_address, params, module=None):
        Notification.__init__(self, classname, source_address, params, module)
        
    def _regex_replacer(self, matchobj):
        command = matchobj.group(1)
        if command == 'readable':
            parameter = 'type, format, timezone, mapped_aliases'
        else:
            parameter = 'format, timezone'
        
        return '| %s(%s)}}' % (command, parameter)

    def pre_extract(self):
        #Collection is 'Alert' by default. Make it dynamic later
        id = is_mongokit_objectid(self.params.get("alert_id", None))
        if id:
            return {"_id":id}
        
        return {}
    
    def extract(self):
        pre = self.pre_extract()
        if isinstance(pre, tuple):
            return pre
        
        if isinstance(pre, dict):
                alert = dboperation.read("AlertRules", pre, True)
                if alert:
                    alert_notifications = alert.get("notification", [])
                    notifications = {}
                    for notification in alert_notifications:
                        nots = {}
                        if notification['type'] == 'newtestemail':
                            nots['notify_newtestemail'] = notification['notify_newtestemail']
                            nots['email_emails'] = notification['email_emails']
                            nots['email_template'] = notification['email_template']
                            threshold = notification.get('threshold')
                            if threshold:
                                if notification['notify_newtestemail']:
                                    nots['email_threshold_enabled'] = True
                                nots['email_threshold_value'] = threshold
                                nots['email_threshold_option'] = notification['threshold_option']
                            notifications.update({"newtestemail":nots})
                            break
                        
                    return self.post_extract(notifications)
                
        return ((0, 102), {})
            
    def post_extract(self, notif):
        email_notif = {}
        if notif:
            email_notif = notif.pop("newtestemail", {})
        
        return ((1, ), {"data":email_notif, "escape":False})
    
    def pre_create(self):
        id = is_mongokit_objectid(self.params.get("alert_id"))
        if id:
            alert = dboperation.read("AlertRules", {"_id":id}, True)
            if alert:
                notifications = alert.get("notification", [])
                if notifications:
                    for notification in notifications:
                        if notification.get("type") == "newtestemail":
                            notifications.remove(notification)
                            break
                if self.params.get("notify_newtestemail") == "on":
                    email_template = textual.utf8(self.params.get('email_template'))
                    try:
                        template = Template(email_template)
                    except TemplateSyntaxError:
                        return ((0, 800), {})
            
                    email_emails = self.params.get('email_emails')
                    
                    if email_emails:
                        email_emails = json.loads(email_emails)
                        email_pattern = re.compile(r"^[-!#$%&'*+/0-9=?A-Z^_a-z{|}~](\.?[-!#$%&'*+/0-9=?A-Z^_a-z{|}~])*@[a-zA-Z](-?[a-zA-Z0-9])*(\.[a-zA-Z](-?[a-zA-Z0-9])*)*$")
                        invalid_emails = []
                        for email in email_emails:
                            if not bool(email_pattern.match(email)):
                                invalid_emails.append(email)
                        
                        if invalid_emails:
                            return ((0, 801), {"errors": {"invalid_emails":invalid_emails}})
                    else:
                        return ((0, 801), {})
            
                    email_threshold_option = self.params.get("email_threshold_option")
                    email_threshold_value = self.params.get("email_threshold_value")
                    if email_threshold_value:
                        email_threshold_value = int(email_threshold_value)
                    template_file = ""
                    if email_template:
                        disk.prepare_path(ALERT_TEMPLATES_PATH)
                        user_id = dboperation.read("User", {'username':self.user.get_user_name()}, True)
                        template_file = 'alert_%s_%s.tmp' % (str(user_id['_id']), base64.b32encode(alert["name"]))
                        template_file_path = os.path.join(ALERT_TEMPLATES_PATH, template_file)
                        email_template = Markup(email_template.decode('utf-8')).unescape()
                        with open(template_file_path, 'w') as f:
                            email_template = email_template.encode('utf-8')
                            format_template = re.sub('\|\s*(readable|date|time|datetime)\s*}}', self._regex_replacer, email_template)
                            f.write(format_template)
                    else:
                        email_template = "<br>"
                        disk.prepare_path(ALERT_TEMPLATES_PATH)
                        template_file = 'alert_%s_%s.tmp' % (self.user.get_user_name().encode('ascii', 'ignore'), base64.b32encode(name))
                        template_file_path = os.path.join(ALERT_TEMPLATES_PATH, template_file)
                        email_template = Markup(email_template.decode('utf-8')).unescape()
                        with open(template_file_path, 'w') as f:
                            email_template = email_template.encode('utf-8')
                            format_template = re.sub('\|\s*(readable|date|time|datetime)\s*}}', self._regex_replacer, email_template)
                            f.write(format_template)
        
                    notifications.append({'template_file':template_file,'type':'newtestemail', 'notify_newtestemail':True, 'email_emails':email_emails,\
                                          'email_template':email_template, 'threshold':email_threshold_value, 'threshold_option':email_threshold_option})
                
                return {"notification":notifications}
    
    def post_create(self, response):
        response.update({"success":802, "error":106})
        
        return super(NewTestEmailNotification, self).post_create(response)
    