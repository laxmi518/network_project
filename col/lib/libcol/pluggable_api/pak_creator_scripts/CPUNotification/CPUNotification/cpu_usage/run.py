import psutil

import notification_handler

THRESHOLD = 90

notif = notification_handler.make_notif({})
notif["type"] = "cpu_usage"
notif["title"] = "High Cpu Usage"
notif["message"] = "Cpu Usage is greater than %s percent" % THRESHOLD

def start():
    usage = psutil.cpu_percent()
    percpu = psutil.cpu_percent(percpu=True)

    if usage > THRESHOLD:
        notification_handler.add_notification(notif)
    else:
        notification_handler.notif_logger(notif["type"], usage, percpu)

