#!/bin/sh
# Usage: $0 CONFIG.json
# Runs start_scp_fetcher_c.sh as root.

exec sudo "$LOGINSPECT_HOME"/installed/system/root_actions/start_scp_fetcher_c.sh "$@"
