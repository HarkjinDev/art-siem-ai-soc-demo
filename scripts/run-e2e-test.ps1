param([string]$ProjectPath = (Get-Location).Path)
$ErrorActionPreference = 'Stop'
Set-Location $ProjectPath
if (!(Test-Path './compose.yaml')) { throw 'compose.yaml not found. Run from the project root.' }
$names = @(docker compose --profile wazuh --profile ai --profile slack ps --status running --services)
if ($LASTEXITCODE -ne 0) { throw 'docker compose ps failed' }
foreach ($needed in @('soc-demo','wazuh.indexer','docker-agent')) {
    if ($names -notcontains $needed) { throw "Required service not running: $needed" }
}
Write-Host '[PASS] Core services running.' -ForegroundColor Green
Write-Host '[INFO] Synthetic Wazuh-shaped alert is written to a dedicated test index, then read and analyzed.'
Write-Host '[INFO] This does not verify a Wazuh Manager rule firing or Sysmon detection.'
$helper = Join-Path $PSScriptRoot 'e2e_indexer_soc.py'
if (!(Test-Path $helper)) { throw "Missing helper file: $helper" }
# Using stdin avoids PowerShell quoting issues and never writes to the container filesystem.
Get-Content -LiteralPath $helper -Raw -Encoding UTF8 | docker compose exec -T soc-demo python -
if ($LASTEXITCODE -ne 0) {
    Write-Host '[INFO] Diagnosis: docker compose logs --since=5m --tail=100 soc-demo' -ForegroundColor Yellow
    throw 'E2E test failed. See the [FAIL] line above.'
}
Write-Host '[PASS] E2E core test completed. Verify the new Slack thread separately.' -ForegroundColor Green
Write-Host '[INFO] Test document remains in a dedicated wazuh-alerts-soc-e2e-* index for troubleshooting.'
