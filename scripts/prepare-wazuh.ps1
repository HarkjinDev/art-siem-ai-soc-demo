param([string]$Version = "v4.14.5")
$ErrorActionPreference = "Stop"
if (Test-Path "wazuh-upstream") { throw "wazuh-upstream already exists; refusing to overwrite" }
git clone --depth 1 --branch $Version https://github.com/wazuh/wazuh-docker.git wazuh-upstream
Write-Host "Upstream prepared in wazuh-upstream/single-node."
Write-Host "Follow upstream certificate generation and password setup before starting Wazuh."
Write-Host "Never commit config/wazuh_indexer_ssl_certs, .env or private keys."
