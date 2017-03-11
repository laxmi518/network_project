
import time
import cPickle
from dateutil import parser as date_parser
from gevent.server import StreamServer
from gevent import socket
from xml.dom import minidom

from libcol.parsers import GetParser, InvalidParserException
from libcol import config_reader
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

def _check_config_changes(db, client_ip):
    fi_client = db.fileinspectclients.find_one({'ip':client_ip})

    if fi_client and fi_client['config_changed']:
        return True

    return False

def _get_client_config(client_config):
    apps = client_config['apps']
    config = {'apps':apps}
    for app in apps:
        app_info = client_config.get(app)
        if app == 'integrity_scanner' or app == 'integrity_monitor' or app == 'registry_scanner' or app == 'file_system_collector':
            path = app_info['path'].split(';')
            config[app] = {'scan_path': path}
            if app == 'integrity_scanner' or app == 'registry_scanner':
                config[app]['scan_frequency'] = app_info['interval'] * 60
            elif app == 'integrity_monitor':
                config[app]['recursive_search'] = app_info.get('recursive_search') or False
        elif app == 'windows_eventlog_reader':
            if app_info.get('sources'):
                config[app] = {
                               'event_sources': [source.strip() for source in app_info['sources'].split(';')]
                               }
            else:
                config[app] = {}
        else:
            config[app] = {}

    config['pdict_using_apps'] = ['file_system_collector']

    return config

def _get_sid_parser(ip, config, config_ip):
    sid = '%s|%s' % (config['col_type'], config_ip)

    profile = config['client_map'].get(config_ip)
    if not profile:
        log.warn("LogPoint agent collector; Connection attempt from unregistered IP %s", ip)
        return sid, None

    parser_name = profile.get('parser')
    if parser_name is None:
        log.warn("LogPoint agent collector; parser not found for sid=%s", sid)
        return sid, None

    charset = profile.get('charset')

    try:
        parser = GetParser(parser_name, sid, charset,
                profile.get('regex_pattern'), profile.get('regexparser_name'))
    except InvalidParserException, err:
        log.warn(err)
        return sid, None

    return sid, parser

def _handle_heartbeat_request(sock, addr, config, db):
    log.debug("tcp collector; %s connected;" % str(addr))
    client_ip = inet.get_ip(addr)
    config_ip = None
    try:
        log.warn('LogPoint agent %s started' % client_ip)
        while True:
            data = sock.recv(4096)
            if not data:
                break

            message = cPickle.loads(data)
            client_id = message['id']
            client_map = config['client_map']

            log.warn('LogPoint agent; received request; client_ip=%s; client_id=%s' % (client_ip, client_id))

            config_changed = _check_config_changes(db, client_ip)

            if message.get('new_start') or config_changed:
                if message.get('new_start'):
                    log.debug('New Start request from client %s' % client_ip)

                config_ip = config_reader.get_config_ip(client_ip, config)
                if config_ip:
                    db.fileinspectclients.update({'ip':client_ip},{'$set':{'config_changed':False}})
                    log.debug('sending application lists to LogPoint agent %s' % config_ip)

                    client_config = _get_client_config(client_map[config_ip])

                    sock.send(cPickle.dumps({'type' : 1, 'config':client_config}))
                else:
                    if not db.fileinspectclients.find_one({'ip':client_ip}):
                        db.fileinspectclients.insert({'ip':client_ip, 'client_id':client_id, 'config_changed':False}, safe=True)
                    log.warn('No applications found for client %s' % client_ip)
                    sock.send(cPickle.dumps({'type' : 2, 'message':'No applications added for this LogPoint agent in LogPoint'}))
            else:
                log.debug('Nothing to send to client %s' % client_ip)
                sock.send(cPickle.dumps({'type' : 0}))
    except Exception, e:
        log.warn('LogPoint agent collector exception: %s' % str(e))
    finally:
        log.warn('LogPoint agent %s stopped' % client_ip)
        sock.close()

def _handle_message_request(sock, addr, config, fi_out):
    global LAST_COL_TS
    global LOG_COUNTER

    log.debug("tcp collector; %s connected;" % str(addr))
    try:
        client_ip = inet.get_ip(addr)
        config_ip = config_reader.get_config_ip(client_ip, config)

        sid, parser = _get_sid_parser(client_ip, config, config_ip)
        if not parser:
            return

        device_name = config['client_map'][config_ip]["device_name"]
        normalizer = config['client_map'][config_ip]["normalizer"]
        repo = config['client_map'][config_ip]["repo"]
        while True:
            data = sock.recv(4096)
            if not data:
                break
            
            try:
                message = cPickle.loads(data)
            except:
                #in case if complete data is not received
                try:
                    data += sock.recv(4096)
                    message = cPickle.loads(data)
                except:
                    log.warn("Dropping the log; log is more than 4 KB")
                    sock.send(cPickle.dumps({'received' : False}))
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
                        try:
                            more_info = _get_extra_key_values_from_xml(message["message"])
                        except:
                            more_info = {}
                            log.warn("Couldnot parse windows xml event log sent from LogPoint Agent")
                        if more_info:
                            extra_info.update(more_info)
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
    

                    col_type = "lpagent"
                    mid_prefix = '%s|%s|%s|%s|' % (config['loginspect_name'], col_type, config_ip, col_ts)
    
                    LOG_COUNTER += 1
                    event['mid'] = mid_prefix + "%d" % LOG_COUNTER
                    
                    event['col_ts'] = col_ts
                    event['_counter'] = LOG_COUNTER
                    event['col_type'] = col_type
                    msgfilling.add_types(event, '_type_num', 'col_ts')
                    msgfilling.add_types(event, '_type_str', 'col_type')
                    
                    event['app_name'] = message['app_name']
                    event['fi_client_id'] = client_id
                    event['device_name'] = device_name
                    event['device_ip'] = client_ip
                    event['collected_at'] = config['loginspect_name']
    
                    if extra_info:
                        event.update(extra_info)
                        for key,value in extra_info.iteritems():
                            if type(value) is int:
                                msgfilling.add_types(event, '_type_num', key)
                            else:
                                msgfilling.add_types(event, '_type_str', key)
    
                    msgfilling.add_types(event, '_type_str', 'app_name')
                    msgfilling.add_types(event, '_type_str', 'device_name')
                    msgfilling.add_types(event, '_type_str', 'fi_client_id')
                    msgfilling.add_types(event, '_type_ip', 'device_ip')
                    msgfilling.add_types(event, '_type_str', 'device_ip')
                    msgfilling.add_types(event, '_type_str', 'collected_at')
    
                    log.debug('sending message to normalizer: %s' % event)
    
                    event['normalizer'] = normalizer
                    event['repo'] = repo
                    fi_out.send_with_norm_policy_and_repo(event)

                sock.send(cPickle.dumps({'received' : True}))
            else:
                sock.send(cPickle.dumps({'received' : False}))
    except Exception, e:
        log.warn('fileinspect collector exception: %s' % str(e))
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

def start_heartbeat_server(config):
    db = mongo.get_makalu()

    port = 6998

    log.info('fileinspect collector; listening ssl enabled tcp server at %s for heartbeat' % port)

    def handler(sock, addr):
        log.info("Handling ssl enabled client from %s", addr)
        return _handle_heartbeat_request(sock, addr, config, db)

    listener = _create_listener(port)
    tcp_server = StreamServer(listener, handler)
    tcp_server.start()

def start_message_receive_server(config, fi_out):
    port = 6999

    log.info('fileinspect collector; listening ssl enabled tcp server at %s for receiving message' % port)

    def handler(sock, addr):
        log.info("Handling ssl enabled client from %s", addr)
        return _handle_message_request(sock, addr, config, fi_out)

    listener = _create_listener(port)
    tcp_server = StreamServer(listener, handler)
    tcp_server.serve_forever()

# globals used across the green threads
LAST_COL_TS = 0
LOG_COUNTER = 0

def main(config, fi_out):
    start_heartbeat_server(config)
    start_message_receive_server(config, fi_out)

