
class RssException(Exception):
    def __init__(self, msg, fault):
        self.message = str(msg)
        self.fault = str(fault)
    def __str__(self):
        return "[%s]: %s" % (self.fault, self.message)


class RssApiException(RssException):
    def __init__(self, e):
        try:
            message = e.fault.args[1]
        except:
            message = str(e)
        try:
            fault = e.fault.detail[0].typecode.pname
        except:
            fault = 'Undefined'

        super(self.__class__, self).__init__(message, fault)

class FaultTypes:
    AUTHENTICATION_ERROR      = "Authentication Error"
    FEED_NOT_FOUND            = "Feed Not Found"
    PERMANENTLY_DELETED_FEED  = "Permanently Deleted Feed"
    INTERNAL_SERVER_EXCEPTION = "Internal Server Exception"
    SAX_PARSER_EXCEPTION      = "SAX Parsing Exception"
    URL_EXCEPTION             = "Urllib2 Exception"
    BOZO_EXCEPTION            = "Unhandled Bozo"
