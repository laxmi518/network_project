
import netaddr

def is_CIDR(ip):
    try:
        netaddr.IPNetwork(ip)
        return True
    except:
        return False

def get_loginspect_name(loginspect):
    loginspect_name = "LogInspect500"
    if loginspect:
        loginspect_name = loginspect[0].get("name") or "LogInspect500"
    return loginspect_name

class RSSFetcherCfgGen:
    def generate_config(self, collections):
        client_map = {}
        for device, col in _get_collectors(collections, "RSSFetcher"):
            if device.get("distributed_collector"):
                continue

            for ip in device["ip"]:
                if is_CIDR(ip):
                    sid = "rss" + ip + '-' + col["url"]
                    client_map[sid] = {
                                       "device_ip": ip,
                                       "charset": col["charset"],
                                       "device_name": device["name"],
                                       "rss_url": col["url"],
                                       "fetch_interval": int(col["interval"]) * 60
                                    }
                    if col.get("username"):
                        client_map[sid]["username"] = col["username"]
                        client_map[sid]["password"] = col["password"]

        loginspect_name = get_loginspect_name(collections["loginspect"])

        return {
                "col_type": "rss",
                "client_map": client_map,
                "loginspect_name": loginspect_name
                }

def _get_collectors(collections, app_name):
    collectors = []
    for device in collections["device"]:
        for app in device["col_apps"]:
            if app["app"] == app_name:
                collectors.append((device, app))
    return collectors
