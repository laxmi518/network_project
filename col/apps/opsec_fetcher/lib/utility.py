import re
import os
from pylib import disk, homing

storage_path = homing.home_join('storage/col/opsec_fetcher/')
pattern = r'  {2,}'
conf_template = '''lea_server auth_type %s
                   lea_server ip %s
                   lea_server auth_port %s
                   opsec_sic_name %s
                   opsec_sslca_file %s
                   lea_server opsec_entity_sic_name %s
                '''

def get_loc_starttime_if_exists(mem_file):
    with open(mem_file) as f:
        loc = f.readline()
        starttime = f.readline().replace(' ', '').replace('-', '').replace(':', '')
        return loc, starttime

def get_memory_file(ip):
    return os.path.join(storage_path, ip, 'memory.txt')

def dump_loc_time_to_file(filename, t_loc, t_time):
    with open(filename, 'w') as f:
        f.write(t_loc + '\n')
        f.write(t_time)

def get_config_file_path(ip, opsec_sic_name, lea_server_opsec_entity_sic_name):
    #make a new lea.cong file and return its path
    #config_path = homing.home_join('storage/col/opsec_fetcher/%s/' % ip)
    config_path = '%s%s/' % (storage_path, ip)
    lea_conf_path = os.path.join(config_path, 'lea.conf')
    opsecp12_path = os.path.join(config_path, 'opsec.p12')
    disk.prepare_path(config_path)
    config_content = conf_template % ('ssl_opsec', ip, 18184, opsec_sic_name, opsecp12_path, lea_server_opsec_entity_sic_name)
    with open(lea_conf_path, 'w') as writer:
        writer.write(re.sub(pattern, '', config_content))
    return lea_conf_path
