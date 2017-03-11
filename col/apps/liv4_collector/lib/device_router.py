
from pylib import configgenerator

def add(db, ips, config):
    repo = config["repo"]
    remove_old_sources(db, repo)
    col_type = config["col_type"]
    normalizer = config["normalizer"]
    charset = config["charset"]

    sources = []
    for ip in ips:
        source = {
            "repo": repo,
            "app": "liv4_collector",
            "normalizer": normalizer,
            "parser": "LIv4Parser",
            "sid": "%s|%s" % (col_type, ip),
            "charset": charset
        }
        sources.append(source)
    db.device.update({"ip": "127.0.0.1"}, {"$pushAll": {"col_apps": sources}}, safe=True)
    configgenerator.regenerate_config_files()

def remove_old_sources(db, repo):
    source = {
        "app": "liv4_collector",
        "repo": repo
    }
    db.device.update({"ip": "127.0.0.1"}, {"$pull": {"col_apps": source}}, safe=True)
