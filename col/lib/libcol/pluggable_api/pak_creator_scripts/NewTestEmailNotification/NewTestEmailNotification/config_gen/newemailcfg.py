
def get_threshold_values(notification):
    threshold = notification.get('threshold_option')
    if threshold:
        value = notification['threshold']
        option = notification['threshold_option']
        if option == 'minute':
            return int(value) * 60
        elif option == 'hour':
            return int(value) * 60 * 60
        elif option == 'day':
            return int(value) * 24 * 60 * 60
        else:
            return 0
    else:
        return 0

def get_config(notification):
    """
    """
    info = {"enabled": True}

    emails = notification["email_emails"]
    info["to_address"] = [[email, email] for email in emails]
    info["template"] = ""
    info["html_template"] = notification.get("template_file")
    info["dispatch_interval"] = get_threshold_values(notification)

    return info