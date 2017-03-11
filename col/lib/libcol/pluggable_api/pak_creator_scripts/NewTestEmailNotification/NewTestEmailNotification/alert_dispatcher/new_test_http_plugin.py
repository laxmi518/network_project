"""HTTP plugin to dispatch the alert message
"""
import json
import logging
import requests

from jinja2 import Template
from pylib.jinja_custom_filter import *
from libdispatcher.plugins import Plugin

class HttpRequest:
    """Action class for driving different HTTP(S) requests
    """
    def delete(self, url, params):
        return requests.delete(url, params=params, verify=False)

    def get(self, url, params):
        return requests.get(url, params=params, verify=False)

    def head(self, url, params):
        return requests.head(url, params=params, verify=False)

    def patch(self, url, data):
        return requests.patch(url, data=data, verify=False)

    def post(self, url, data):
        return requests.post(url, data=data, verify=False)

    def put(self, url, data):
        return requests.put(url, data=data, verify=False)

class HttpPlugin(Plugin):
    """
    """
    def setup(self, config):
        logging.info("NewHttpPlugin; setup; HttpPlugin setup complete")

    def teardown(self):
        logging.info("NewHttpPlugin; teardown; HttpPlugin teardown complete")

    def execute(self, dispatch_packet):
        http_info = dispatch_packet.get('http_info')
        
        if not self.pre_execute(http_info):
            return None
        
        query_string = http_info.get("query_string")
        frmtd_query = self._format_query_string(query_string)
                
        request_type = http_info.get("request_type")
        query_stripped_url = http_info.get("query_stripped_url")
        self._substitute_variables(frmtd_query, dispatch_packet)
        try:
            response = getattr(HttpRequest(), request_type.lower())\
                                            (query_stripped_url, frmtd_query)
        except Exception, e:
            logging.warn("NewHttpPlugin; failure; Exception=%s; alert_name=%s; url=%s; Error while calling url",
                         e, dispatch_packet.get("alert_name"), query_stripped_url)
            return None

        if response.status_code == 200: #OK
            logging.info("NewHttpPlugin; Alert processed; alert_id = %s; alert_name='%s'; life_id=%s;",
                         dispatch_packet.get("alert_id"), dispatch_packet.get("alert_name"), dispatch_packet.get("life_id"))
        else:
            logging.info("NewHttpPlugin; Alert not dispatched. alert_id=%s; alert_name='%s'; Response status code not OK",
                         dispatch_packet.get("alert_id"),dispatch_packet.get("alert_name"))

    def _format_query_string(self, query_string):
        """formats the query string into the dictionary format

        e.g.
            query_string: username=kailash&password=buki&result={{rows}}
            data: {'username': 'kailash', 'password': 'buki', 'result': '{{rows}}'}
        """
        query_parts = query_string.split('&')
        data = {}
        for query in query_parts:
            try:
                key, value = query.split('=')
                data[key] = value
            except ValueError:
                pass

        return data

    def _substitute_variables(self, frmtd_query, dispatch_packet):
        """replaces jinja supported variables like {{rows}}, {{rows_count}}, {{alert_name}} etc from the formatted query
        """
        extra_info = dispatch_packet.get("extra_info")
        
        if not extra_info:
            extra_info = dict()

        params = dict(risk_level=dispatch_packet.get("risk_level"),
                      description=dispatch_packet.get("description"),
                      detection_timestamp=dispatch_packet.get("detection_timestamp"),
                      format=extra_info.get("hour_format"),
                      timezone=extra_info.get("user_timezone"))
        
        rule_name = dispatch_packet.get("alert_name")
        dispatch_type = dispatch_packet.get("dispatch_type")
        
        if dispatch_type == "correlation":
            params["correlation_name"] = rule_name
            params["groups"] = dispatch_packet.get("groups")
        elif dispatch_type == "alert_engine":
            rows = dispatch_packet.get("rows")
            params["rows"] = rows
            params["rows_count"] = len(rows)
            params["alert_name"] = rule_name
            
        for key in frmtd_query:
            template = Template(frmtd_query[key])
            rendered_value = template.render(**params)
            frmtd_query[key] = rendered_value