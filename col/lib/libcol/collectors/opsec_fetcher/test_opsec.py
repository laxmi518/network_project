import subprocess
import os
import logging

from pylib import homing, disk
from configuration import generate_certificate, is_certificate_present
storage_path = homing.home_join('storage/col/opsec_fetcher/')

def get_config_file_path(ip, opsec_sic_name, lea_server_opsec_entity_sic_name):
    #make a new lea.cong file and return its path
    config_path = homing.home_join('storage/col/opsec_fetcher/%s/' % ip)
    lea_conf_path = os.path.join(config_path, 'lea.conf')
    opsecp12_path = os.path.join(config_path, 'opsec.p12')
    disk.prepare_path(config_path)
    with open(lea_conf_path, 'w') as conf_file:
        conf_file.write("lea_server auth_type ssl_opsec\n")
        conf_file.write("lea_server ip %s\n" % ip)
        conf_file.write("lea_server auth_port 18184\n")
        conf_file.write("opsec_sic_name %s\n" % opsec_sic_name)
        conf_file.write("opsec_sslca_file %s\n" % opsecp12_path)
        conf_file.write("lea_server opsec_entity_sic_name %s" % lea_server_opsec_entity_sic_name)

    return lea_conf_path

def get_error(line):
    error = ''
    if line.rfind('ERROR:') != -1:
        error = line
    if error == '':
        return False, error
    else:
        return True, error

def test_opsec_fetcher(ip, object_name, sic_one_timer_password, secret_key, opsec_sic_name, lea_server_opsec_entity_sic_name):
    if is_certificate_present(ip) == False:
        result = generate_certificate(ip, object_name, sic_one_timer_password, secret_key)
        if result['success'] == False:
            return {'success': False, 'ip': ip, 'msg': result['msg']}

    os.chdir(os.path.join(storage_path, ip))
    loggrabber_path = homing.home_join('installed/col/apps/opsec_fetcher/utils')
    loggrabber = os.path.join(loggrabber_path, 'fw1-loggrabber')
    loggrabber_conf = os.path.join(loggrabber_path, 'fw1-loggrabber.conf')
    lea_conf_file = get_config_file_path(ip, opsec_sic_name, lea_server_opsec_entity_sic_name)
    proc = subprocess.Popen([loggrabber, '-l', lea_conf_file, \
                                         '-c', loggrabber_conf, \
                                         '--debug-level', '1'], \
                             stdout=subprocess.PIPE, \
                             stderr=subprocess.PIPE)

    if proc.stdout:
        return {'success': True, 'ip': ip, 'msg': 'Logs successfully retrieved'}
    else:
        while True:
            line = proc.stderr.readline()
            if not line:
                break

            error, err_msg = get_error(line)
            if error:
                logging.warn('Test Failed with error %s' % err_msg)
                return {'success': False, 'ip': ip, 'msg': err_msg}

        logging.warn('Test Failed. No Output')
        return {'success': False, 'ip': ip, 'msg': 'No Output'}
