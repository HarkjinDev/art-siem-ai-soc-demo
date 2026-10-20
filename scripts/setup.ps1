$ErrorActionPreference='Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
if (!(Test-Path '.env')) {Copy-Item '.env.example' '.env'; Write-Host 'Created .env (no secrets)'}
Write-Host 'Starting sample replay UI (Wazuh and AI optional)...'
docker compose up -d --build soc-demo
Write-Host 'Open http://localhost:8088 and click Sample Replay.'
