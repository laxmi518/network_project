import os
import glob
import logging
import subprocess

from pylib import homing, disk

STORAGE_PATH = homing.home_join("storage/col/opsec_fetcher/")
PULLERS_PATH = homing.home_join('installed/col/lib/libcol/collectors/opsec_fetcher/')

class OpsecCommunicator(object):

    def __init__(self, ip, object_name, sic_pwd, putkey_pwd):
        self.ip = ip
        self.object_name = object_name
        self.sic_pwd = sic_pwd
        self.putkey_pwd = putkey_pwd

        self.cert_path = os.path.join(STORAGE_PATH, ip) + "/"
        self.opsec_pull_cert = os.path.join(PULLERS_PATH, "opsec_pull_cert")
        self.opsec_putkey = os.path.join(PULLERS_PATH, "opsec_putkey")

        #make new dir for this ip to store its certificates
        disk.prepare_path(self.cert_path)
        #cd to the newly created dir to perform certificate actions
        os.chdir(self.cert_path)

    def is_certificate_present(self):
        """
        Return true is certificate files are present
        Files -> opsec.p12, two .C files
        """
        #check if opsec.p12 is present or not
        found = glob.glob("opsec.p12")
        if not found:
            return False, "opsec.p12 no present!"

        #check if the two .C files are present or not
        found = glob.glob("*.C")
        if not found:
            return False, ".C files not found!"

        return True, "Success!"

    def clear_certificates(self):
        """
        Clear the certificate contents
        From storage/col/opsec_fetcher/ip
        """
        try:
            os.remove(self.cert_path)
        except OSError, err:
            logging.warn(err)

    def generate_certificate(self):
        """
        Generate certificate by communicating with the checkpoint server
        Commands run for certificate generation are:
            opsec_pull_cert -h <server_ip> -n <lea_application> -p <password>
            opsec_putkey -port 18184 <server_ip>
        """
        if self.is_certificate_present()[0]:
            return True, "Certificates already present!"
        self.clear_certificates()

        #Run the opsec_pull_cert command to generate opsec.p12 file
        print self.opsec_pull_cert
        print self.ip
        print self.object_name
        print self.sic_pwd
        sp = subprocess.Popen(
            [
            self.opsec_pull_cert,
            '-h', self.ip,
            '-n', self.object_name,
            '-p', self.sic_pwd
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        sp.communicate()

        #Run the opsec_putkey command to generate .C files
        sp = subprocess.Popen(
            [
            self.opsec_putkey,
            '-port', '18184',
            '-p', self.putkey_pwd,
            self.ip
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        sp.communicate()

        return self.is_certificate_present()

if __name__ == '__main__':
    ip = '10.45.1.91'
    app = 'new'
    sic_pwd = 'loginspect10'
    putkey_pwd = 'ashok'

    c = OpsecCommunicator(ip, app, sic_pwd, putkey_pwd)
    success = c.generate_certificate()

    print success
