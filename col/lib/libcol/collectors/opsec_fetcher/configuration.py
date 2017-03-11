import os
import shutil
import subprocess
import logging
from pylib import homing, disk

storage_path = homing.home_join('storage/col/opsec_fetcher/')
certificate_path = homing.home_join('installed/col/lib/libcol/collectors/opsec_fetcher/')

def remove_certificates(ip):
    try:
        shutil.rmtree(os.path.join(storage_path, ip))
    except OSError, err:
        logging.warn(err)

def remove_certificate_if_exists(ip):
    #if os.path.exists(os.path.join(storage_path, ip, 'opsec.p12')) or \
    #        os.path.exists(os.path.join(storage_path, ip, 'sslauthkeys.C')) or \
    #            os.path.exists(os.path.join(storage_path, ip, 'sslsess.C')):
    if not is_certificate_present(ip):
            logging.warn('''Partial Certificate info exists. Removing the incomplete info
                            and generating a new certificate. Please use the fw_put_key command on the server
                            and RESET the SIC communication as well''')
            remove_certificates(ip)

def is_certificate_present(ip):
    if os.path.exists(os.path.join(storage_path, ip, 'opsec.p12')) and \
            os.path.exists(os.path.join(storage_path, ip, 'sslauthkeys.C')) and \
                os.path.exists(os.path.join(storage_path, ip, 'sslsess.C')):
        return True
    else:
        return False

def generate_certificate(ip, object_name, sic_one_timer_password, secret_key):
    #if all the cert files are present, no need to extract the certificates
    ip_path = os.path.join(storage_path, ip)
    if is_certificate_present(ip) == True:
        logging.warn("Cretificates already present.")
        return {'success': True, 'msg': 'Certificate already present'}

    #if not all the necessary files are present, remove all and proceed to generating fresh certificates
    elif not os.path.exists(ip_path):
        pass
    else:
        remove_certificate_if_exists(ip)

    #if the path to ip is not present it is created
    disk.prepare_path(ip_path + '/')

    os.chdir(ip_path)
    logging.warn("Creating Opsec Certificate...")
    sp = subprocess.Popen([os.path.join(certificate_path, 'opsec_pull_cert'), '-h', ip, '-n', object_name, '-p',\
                                sic_one_timer_password], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    sp.communicate()
    if not os.path.exists(os.path.join(storage_path, ip, 'opsec.p12')):
        return {'success': False, 'msg': 'couldnt retrieve certificate from the server, RESET SIC in the server \
                                          and try again'}
    logging.warn("Successfully Created Certificate : %r" % 'opsec.p12')

    logging.warn("Creating SSL Authorization Files...")
    sp = subprocess.Popen([os.path.join(certificate_path, 'opsec_putkey'), '-ssl', '-port', '18184', '-p',\
                                secret_key, ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    sp.communicate()
    if not (os.path.exists(os.path.join(storage_path, ip, 'sslauthkeys.C')) or \
                os.path.exists(os.path.join(storage_path, ip, 'sslsess.C'))):
        return {'success': False, 'msg': 'couldnt retrieve ssl authorization certificates. Did you forget to do a \
                                        fw putkey command for the LI on your server'}

    logging.warn("Successfully Created SSL Authorization Files : %r, %r" % ('sslauthkeys.C', 'sslsess.C'))

    logging.warn("Process Complete")
    return {'success': True, 'msg' : 'Certificate Sucessfully Created. Happy Opsecing!'}

if __name__ == '__main__':
    ip = '192.168.2.123'
    object_name = 'newlea'
    sic_one_timer_password = 'ashok'
    secret_key = 'ashok'

    generate_certificate(ip, object_name, sic_one_timer_password, secret_key)
