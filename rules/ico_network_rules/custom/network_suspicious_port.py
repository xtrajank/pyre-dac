def rule(event):
    # event is the JSON log, already parsed into a dict.
    # Fires when a connection is made to remote port 4444.
    return event.get("remote_port") == 4444


def title(event):
    return "Connection to suspicious port 4444 from {}".format(
        event.get("hostname", "unknown host")
    )

def dedup(event):
    return event.get("remote_ip")


def severity(event):
    return "Medium"