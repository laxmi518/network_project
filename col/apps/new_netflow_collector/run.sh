#!/bin/sh
# Usage: $0 CONFIG.json
# Runs start_syslog_col_c.sh as root.

exec sudo "$LOGINSPECT_HOME"/installed/system/root_actions/start_netflow_col_c.sh "$@"
