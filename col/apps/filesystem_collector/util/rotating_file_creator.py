
import logging
import logging.handlers
import os
import time

from pylib import disk

LOG_DIR = disk.get_sibling(__file__, 'logs')
if not os.path.exists(LOG_DIR):
    os.mkdir(LOG_DIR)

LOG_FILENAME = os.path.join(LOG_DIR, 'rotatingfile.out')

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

handler = logging.handlers.RotatingFileHandler(
            LOG_FILENAME, maxBytes=100, backupCount=5)

log.addHandler(handler)

for i in xrange(int(1e9)):
    time.sleep(1)
    log.debug('i = %d' % i)
    #break
