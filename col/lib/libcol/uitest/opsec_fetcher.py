

import subprocess
import os

from pylib import disk, homing

def test(ip, opsec_sic_name, lea_server_opsec_entity_sic_name):
    proc = subprocess.Popen(['./fw1-loggrabber', '-l', '%s' % _get_conf_file_path(ip, opsec_sic_name, \
                                                                        lea_server_opsec_entity_sic_name)], \
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    if proc.stderr:
        return {'ip':ip,'success' : False, 'message' : 'No route to host'}
    else:
        return {'ip':ip,'success':True, 'message':'OPSEC Fetcher working properly'}


def _get_conf_file_path(ip, opsec_sic_name, lea_server_opsec_entity_sic_name):
    #make a new lea.cong file and return its path
    config_path = homing.home_join('storage/col/opsec_fetcher/', ip, 'lea.conf')
    disk.prepare_path(config_path)
    with open(config_path, 'w') as conf_file:
        conf_file.write("lea_server auth_type ssl_opsec\n")
        conf_file.write("lea_server ip %s\n" % ip)
        conf_file.write("lea_server auth_port 18184\n")
        conf_file.write("opsec_sic_name %s\n" % opsec_sic_name)
        conf_file.write("opsec_sslca_file %s\n" % os.path.abspath("lea.conf"))
        conf_file.write("lea_server_opsec_entity_sic_name %s" % lea_server_opsec_entity_sic_name)

    return config_path