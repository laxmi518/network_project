
import time
import zlib
import cPickle
from gevent import socket
from xml.dom import minidom
from gevent.server import StreamServer
from dateutil import parser as date_parser

from libcol import config_reader
from libcol.parsers import GetParser, InvalidParserException
from pylib import logger, homing, inet, msgfilling, textual, mongo

log = logger.getLogger(__name__)

certificate_file_path = homing.home_join('etc/remote_connection/certificates/ssl.crt')
key_file_path = homing.home_join('etc/remote_connection/certificates/ssl.key')

present_field_names = ["Applicaion", "ClientAddress", "DestAddress", "DestPort",
                       "EventID", "EventRecordID", "EventSourceName", "HandleId",
                       "LogonType", "ObjectName", "Process", "ProcessID", "SourceAddress",
                       "SourcePort", "TargetDomain", "TargetUserName", "UserName",
                       "IpAddress", "IpPort", "NewProcessName", "ObjectName", "PackageName",
                       "ProcessId", "ProcessName", "ServiceName", "Status", "SubjectDomainName",
                       "SubjectLogonId", "SubjectUserName", "TargetDomainName", "TargetLogonId",
                       "TargetUserName", "TokenElevationType", "WorkstationName"]

field_names_renamed = ["application", "source_address", "destination_address", "destination_port",
                       "event_id", "record_number", "event_category", "handle_id",
                       "logon_type", "object", "process", "process_id", "source_address",
                       "source_port", "target_domain", "target_user", "user",
                       "source_address", "source_port", "process", "object", "package",
                       "process_id", "process", "service", "result_code", "caller_domain",
                       "caller_logon_id", "caller_user", "target_domain", "target_logon_id",
                       "target_user", "token_type", "workstation"]

def _get_xml_elements(dom_xml, node, el_dict):
    if node.hasChildNodes():
        for each in node.childNodes:
            _get_xml_elements(dom_xml, each, el_dict)
    else:
        try:
            if node.hasAttributes():
                for each in node.attributes.keys():
                    el_dict[each] = node.getAttribute(each)
                return
        except:
            pass
        if node.parentNode.hasAttributes():
            if node.nodeValue is not None:
                for each in node.parentNode.attributes.keys():
                    if node.parentNode.nodeName != "EventID":
                        el_dict[node.parentNode.getAttribute(each)] = node.nodeValue
        if node.nodeValue:
            el_dict[node.parentNode.nodeName] = node.nodeValue.strip()

def _get_extra_key_values_from_xml(event_xml):
    dom_xml = minidom.parseString(event_xml)
    
    el_dict = {}
    for each in dom_xml.getElementsByTagName("Event")[0].childNodes:
        _get_xml_elements(dom_xml, each, el_dict)
    
    new_dict = {"severity":5, "facility":1}
    for k,v in el_dict.iteritems():
        if k =="SystemTime":
            try:
                struct = date_parser.parse(v).timetuple()
                new_dict["log_ts"] = int(time.mktime(struct))
            except:
                new_dict["log_ts"] = v
        elif k in present_field_names:
            index = present_field_names.index(k)
            new_dict[field_names_renamed[index]] = v
    
    try:
        if "caller_user" in new_dict and "target_user" not in new_dict:
            new_dict["user"] = new_dict["caller_user"]
            new_dict.pop("caller_user")
            
            if "caller_domain" in new_dict:
                new_dict["domain"] = new_dict["caller_domain"]
                new_dict.pop("caller_domain")
            if "caller_logon_id" in new_dict:
                new_dict["logon_id"] = new_dict["caller_logon_id"]
                new_dict.pop("caller_logon_id")
        elif "caller_user" not in new_dict and "target_user" in new_dict:
            new_dict["user"] = new_dict["target_user"]
            new_dict.pop("target_user")
            
            if "target_domain" in new_dict:
                new_dict["domain"] = new_dict["target_domain"]
                new_dict.pop("target_domain")
            if "target_logon_id" in new_dict:
                new_dict["logon_id"] = new_dict["target_logon_id"]
                new_dict.pop("target_logon_id")
    except:
        pass
    
    return new_dict

def _get_client_config(applications):
    config = {"apps": [], "pdict_using_apps": ["file_system_collector"]}
    for app, app_info in applications.iteritems():
        if app_info:
            if app == "FileSystemCollector":
                config["apps"].append("file_system_collector")
                if isinstance(app_info, dict):
                    path = [info.strip() for info in app_info["path"].split(";") if info.strip()]
                    old_logs = app_info["old_logs"]
                else:
                    path = [info.strip() for info in app_info.split(";") if info.strip()]
                    old_logs = False
                config["file_system_collector"] = {"scan_path": path, "old_logs": old_logs}
            if app == "IScanner":
                config["apps"].append("integrity_scanner")
                path = [info.strip() for info in app_info["path"].split(";") if info.strip()]
                config["integrity_scanner"] = {"scan_path": path, "scan_frequency": app_info["interval"] * 60}
            elif app == "IMonitor":
                config["apps"].append("integrity_monitor")
                in_mon_info = {}
                if isinstance(app_info, str) or isinstance(app_info, unicode):
                    path = [info.strip() for info in app_info.split(";") if info.strip()]
                    in_mon_info = {"scan_path": path, "recursive_search":True}
                else:
                    path = [info.strip() for info in app_info["path"].split(";") if info.strip()]
                    in_mon_info = {"scan_path": path, "recursive_search": app_info["recursive_search"]}
                config["integrity_monitor"] = in_mon_info
            elif app == "RegScanner":
                config["apps"].append("registry_scanner")
                path = [info.strip() for info in app_info["path"].split(";") if info.strip()]
                config["registry_scanner"] = {"scan_path": path, "scan_frequency": app_info["interval"] * 60}
            elif app == "SystemWatcher":
                config["apps"].append("windows_system_watcher")
                config["windows_system_watcher"] = {}
            elif app == "EventLogReader":
                config["apps"].append("windows_eventlog_reader")
                sources = [info.strip() for info in app_info["event_sources"].split(";") if info.strip()]
                xml_log = app_info.get("xml_log") or False
                config["windows_eventlog_reader"] = {"event_sources": sources, "xml_log": xml_log}
    return config

def _get_sid_parser(ip, config, config_ip):
    sid = '%s|%s' % (config['col_type'], config_ip)

    profile = config['client_map'].get(config_ip)
    if not profile:
        log.warn("logpoint agent collector; Connection attempt from unregistered IP %s", ip)
        return sid, None

    parser_name = profile.get('parser')
    if parser_name is None:
        log.warn("logpoint agent collector; parser not found for sid=%s", sid)
        return sid, None

    charset = profile.get('charset')
    try:
        parser = GetParser(parser_name, sid, charset,
                profile.get('regex_pattern'), profile.get('regexparser_name'))
    except InvalidParserException, err:
        log.warn(err)
        return sid, None

    return sid, parser

def _handle_message_request(sock, addr, config, fi_out, db):
    global LAST_COL_TS
    global LOG_COUNTER

    log.debug("tcp collector; %s connected;" % str(addr))
    try:
        client_map = config["client_map"]
        client_ip = inet.get_ip(addr)
        config_ip = config_reader.get_config_ip(client_ip, config)

        sid, parser = _get_sid_parser(client_ip, config, config_ip)
        if not parser:
            return

        device_name = config["client_map"][config_ip]["device_name"]
        while True:
            data = sock.recv(4096)
            if not data:
                break

            try:
                message = cPickle.loads(zlib.decompress(data))
            except:
                #in case if complete data is not received
                try:
                    data += sock.recv(4096)
                    message = cPickle.loads(zlib.decompress(data))
                except:
                    log.warn("Dropping the log; log is more than 4 KB")
                    sock.send(zlib.compress(cPickle.dumps({"received" : False})))
                    continue
            
            if message.get("send_app_file"):
                app_name = message["app_name"]
                app_content = open(homing.home_join("storage/col/logpointagent/%s.fi" % app_name), "rb").read()
                sock.send(str(len(app_content)) + "\n" + app_content)
                log.warn("Application file for %s sent to client %s" % (app_name, client_ip))
                continue
            
            if message.get("heartbeat_request"):
                client_id = message["client_id"]
                db_fi_client = db.fileinspectclients.find_one({"ip":client_ip})
                if not db_fi_client:
                    log.warn("Received first request from LogPoint agent with ip=%s and id=%s" % (client_ip, client_id))
                    db.fileinspectclients.insert({"ip":client_ip, "client_id":client_id, "config_changed":True}, safe=True)
                    sock.send(zlib.compress(cPickle.dumps({"type":1, "message": "No applications added for this LogPoint Agent in LogPoint",
                                             "pdict_using_apps": ["file_system_collector"]})))
                elif db_fi_client and not db_fi_client.get("applications"):
                    log.warn("Add applciations for LogPoint Agent with ip=%s and id=%s" % (client_ip, client_id))
                    sock.send(zlib.compress(cPickle.dumps({"type":1, "message": "No applications added for this LogPoint Agent in LogPoint",
                                             "pdict_using_apps": ["file_system_collector"]})))
                elif db_fi_client.get("applications") and (message.get("first_fetch") or db_fi_client["config_changed"]):
                    log.warn("Received config request from LogPoint agent with ip=%s and id=%s" % (client_ip, client_id))
                    client_config = _get_client_config(db_fi_client["applications"])
                    if not client_config.get("apps"):
                        sock.send(zlib.compress(cPickle.dumps({"type":1, "message": "No applications added for this LogPoint Agent in LogPoint",
                                             "pdict_using_apps": ["file_system_collector"]})))
                    else:
                        sock.send(zlib.compress(cPickle.dumps({"type":2, "config":client_config})))
                        db.fileinspectclients.update({"ip":client_ip}, {"$set":{"client_id": client_id, "config_changed":False}})
                else:
                    log.warn("Received heartbeat request from LogPoint agent with ip=%s and id=%s" % (client_ip, client_id))
                    sock.send(zlib.compress(cPickle.dumps({"type":0})))
                continue

            client_id = message['id']

            if message.get('message') and message.get('app_name'):
                app_name = message['app_name']
                
                extra_info = message.get('extra_info') or {}

                fi_out.start_benchmarker_processing()

                if app_name == "windows_eventlog_reader":
                    event = {"msg": textual.utf8(message["message"]), "_type_str": "msg"}
                    if extra_info.get("_is_event_xml"):
                        extra_info.pop("_is_event_xml")
                        #try:
                        #    more_info = _get_extra_key_values_from_xml(message["message"])
                        #except:
                        #    more_info = {}
                        #    log.warn("Couldnot parse windows xml event log sent from LogPoint Agent")
                        #if more_info:
                        #    extra_info.update(more_info)
                    parser_data = [event]
                else:
                    parser.write(textual.utf8(message['message']), old_parser=True)
                    parser_data = []
                    if parser:
                        for event in parser:
                            if event:
                                parser_data.append(event)
                
                for event in parser_data:
                    col_ts = int(time.time())
                    if col_ts > LAST_COL_TS:
                        LAST_COL_TS = col_ts
                        LOG_COUNTER = 0
    
                    mid_prefix = '%s|%s|%s|%s|' % (config['loginspect_name'], config['col_type'], config_ip, col_ts)
    
                    LOG_COUNTER += 1
                    event['mid'] = mid_prefix + "%d" % LOG_COUNTER
                    event['device_name'] = device_name
                    event['device_ip'] = client_ip
                    event['collected_at'] = config['loginspect_name']
                    event['col_ts'] = col_ts
                    event['_counter'] = LOG_COUNTER
                    event['col_type'] = config['col_type']

                    msgfilling.add_types(event, '_type_str', 'device_name')
                    msgfilling.add_types(event, '_type_ip', 'device_ip')
                    msgfilling.add_types(event, '_type_str', 'device_ip')
                    msgfilling.add_types(event, '_type_str', 'collected_at')
                    msgfilling.add_types(event, '_type_num', 'col_ts')
                    msgfilling.add_types(event, '_type_str', 'col_type')


                    event['_normalized_fields'] = {}
                    event['_normalized_fields']['app_name'] = message['app_name']
                    event['_normalized_fields']['lp_agent_id'] = client_id

                    msgfilling.add_types(event, '_type_str', 'app_name')
                    msgfilling.add_types(event, '_type_str', 'lp_agent_id')
    
                    if extra_info:
                        #event.update(extra_info)
                        for key,value in extra_info.iteritems():
                            if type(value) is int:
                                msgfilling.add_types(event, '_type_num', key)
                            else:
                                msgfilling.add_types(event, '_type_str', key)
                            event['_normalized_fields'][key] = value

                    log.debug('sending message to normalizer: %s' % event)

                    event['repo'] = config['client_map'][config_ip]['repo']
                    event['normalizer'] = config['client_map'][config_ip]['normalizer']
    
                    fi_out.send_with_mid(event)

                sock.send(zlib.compress(cPickle.dumps({'received' : True})))
            else:
                sock.send(zlib.compress(cPickle.dumps({'received' : False})))
    except Exception, e:
        log.warn('logpooint agent collector exception: %s' % str(e))
    finally:
        sock.close()

def _create_listener(port, backlog=256):
    """Creates an IPv6-capable listener.
    """
    sock, sockaddr = inet.create_external_address(port)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(sockaddr)
    sock.listen(backlog)
    sock.setblocking(0)
    return sock

def start_message_receive_server_tcp(config, fi_out, db, port):
    log.info('logpoint agent collector; listening tcp server at %s for receiving message' % port)

    def handler(sock, addr):
        log.info("Handling tcp client from %s", addr)
        return _handle_message_request(sock, addr, config, fi_out, db)

    listener = _create_listener(port)
    tcp_server = StreamServer(listener, handler)
    tcp_server.start()

def start_message_receive_server_ssl(config, fi_out, db, port):
    log.info('logpoint agent collector; listening tcp/ssl server at %s for receiving message' % port)

    def handler(sock, addr):
        log.info("Handling tcp/ssl client from %s", addr)
        return _handle_message_request(sock, addr, config, fi_out, db)

    listener = _create_listener(port)
    ssl_server = StreamServer(listener, handler, keyfile=key_file_path,
                              certfile=certificate_file_path)
    ssl_server.start()
    ssl_server.serve_forever()

# globals used across the green threads
LAST_COL_TS = 0
LOG_COUNTER = 0

def main(config, fi_out):
    db = mongo.wait_and_get_db("LogPoint Agent Collector")
    #db = mongo.get_makalu()
    port = 6998
    
    start_message_receive_server_tcp(config, fi_out, db, port)
    start_message_receive_server_ssl(config, fi_out, db, port + 1)

