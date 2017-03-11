#!/bin/sh
# Usage: $0 CONFIG.json
# Runs start_filesystem_collector.sh as root.

exec sudo "$LOGINSPECT_HOME"/installed/system/root_actions/start_filesystem_collector.sh "$@"
