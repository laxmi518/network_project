

import logging as log
from pysdee.pySDEE import SDEE

def test(username, password, ip, method="https", force="yes"):
    
    if not username:
        return {'success':False, 'message':'User name missing', 'ip':ip}
    if not password:
        return {'success':False, 'message':'Password missing', 'ip':ip}
    if not ip:
        return {'success':False, 'message':'IP missing', 'ip':ip}
    
    sdee = SDEE(user = username, password = password, host = ip, method = method, force = 'yes')
    sdee.open()
    if sdee._sessionid or sdee._subscriptionid:
        if sdee._sessionid:
            log.info("Successful login for %s with sessionid : %s" % (ip, sdee._sessionid))
        else:
            log.info("Successful login for %s with subscriptionid : %s" % (ip, sdee._subscriptionid))
        return {'ip':ip,'success':True, 'message':'SDEE Fetcher working properly'}
    else:
        return {'ip':ip,'success' : False, 'message' : 'No route to host'}