
import os
import shutil
import zipfile

from pylib import disk, homing

def create_zipped_application_packages(basedir):
    
    basedir = basedir.replace('$LOGINSPECT_HOME', homing.LOGINSPECT_HOME)
    if os.path.exists(basedir):
        shutil.rmtree(basedir)
    
    disk.prepare_path(basedir)
    
    applications = []
    apps_path = homing.home_join('storage/col/fileinspect_applications/')
    for path in os.listdir(apps_path):
        if os.path.isdir(os.path.join(apps_path, path)):
            applications.append(path)
    
    for dirname, subdirs, files in os.walk(apps_path):
        for f in files:
            if f.endswith(".pyc"):
                os.unlink(os.path.join(dirname, f))
    
    for app in applications:
        outfilename = os.path.join(basedir, '%s.fi' % app)
        try:
            zf = zipfile.PyZipFile(outfilename, mode='w')
            zf.writepy(os.path.join(apps_path, app))
        finally:
            zf.close()
    return

