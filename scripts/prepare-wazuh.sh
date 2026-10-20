#!/usr/bin/env bash
set -euo pipefail
if [[ -e wazuh-upstream ]]; then echo 'wazuh-upstream exists; refusing overwrite' >&2; exit 1; fi
git clone --depth 1 --branch "${1:-v4.14.5}" https://github.com/wazuh/wazuh-docker.git wazuh-upstream
printf '%s\n' 'Upstream Wazuh prepared. Generate certificates and configure passwords according to official Wazuh single-node README.'
