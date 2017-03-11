

import logging as log

from libcol.pluggable_api import disabling
from pluggables.modules.Collection.controller import Collection

class RSSFetcher(Collection):
    def __init__(self, classname, source_address, params, module=None):
        Collection.__init__(self, classname, source_address, params, module)
    
    def get_list(self):
        pass
    
    def _format_col_apps_of_devices_and_policies(self, col_apps, add_file_system_col=False, _edit=False):
        if _edit:
            apps = {}
            
            for col_app in col_apps:
                charset = col_app.get("charset")
                
                if col_app["app"] == "RSSFetcher":
                    apps.update(dict(
                                id=col_app["sid"],
                                url=col_app["url"],
                                interval=col_app["interval"],
                                normalizer=col_app["normalizer"],
                                repo=col_app["repo"],
                                charset=charset
                                ))
                    break
                
            return apps
        else:
            apps = []
            
            for col_app in col_apps:
                charset = col_app.get("charset")
                
                if col_app["app"] == "RSSFetcher":
                    apps.append(dict(
                                id=col_app["sid"],
                                url=col_app["url"],
                                interval=col_app["interval"],
                                normalizer=col_app["normalizer"],
                                repo=col_app["repo"],
                                charset=charset
                                ))
                
            return apps
    
    def _is_col_apps_count_within_limit(self, count):
        pass
    
    def _get_formatted_app_content(self, deviceips):
        sid = "rss|" + "device-" + self._device["name"] + "-" + self._post_data["url"]
        newItems = [sid, self._post_data["url"], self._post_data["normalizer"],
                    self._post_data["repo"], self._post_data["charset"], self._post_data["interval"]]
        
        self._post_data["app"] = "RSSFetcher"
        self._post_data["sid"] = sid
        
        return newItems
    
    def _validate_during_edit(self, ):
        pass
    
    def _update_content(self, index):
        for key in ["normalizer", "charset", "repo", "url", "interval"]:
            self._device["col_apps"][index][key] = self.params.get("%s" % key)
    
    def _remove_specific_content(self, apps):
        pass
    
    def manage_plugin(self, action):
        response = disabling.enable_disable_plugin("RSSFetcher", "Collection", action)
        if response["success"]:
            return ((1,), {"message": response["message"]})
        else:
            return ((0,), {"message": response["message"]})
    
    def enable(self):
        return self.manage_plugin("enable")
    
    def disable(self):
        return self.manage_plugin("disable")
    