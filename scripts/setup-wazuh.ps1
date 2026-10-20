param([switch]$SkipCertificates)
$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..'))

if (-not (Test-Path '.env')) {
  throw 'Missing .env. Copy .env.example to .env and configure passwords first.'
}

$vars = @{}
Get-Content '.env' -Encoding UTF8 | ForEach-Object {
  if ($_ -match '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
    $vars[$Matches[1]] = $Matches[2].Trim()
  }
}

foreach ($key in @('WAZUH_INDEXER_PASSWORD', 'WAZUH_KIBANA_PASSWORD', 'WAZUH_API_PASSWORD')) {
  $value = [string]$vars[$key]
  if ([string]::IsNullOrWhiteSpace($value) -or
      $value -match '^(CHANGE|YOUR_|REPLACE|EXAMPLE)' -or
      $value -eq 'SecretPassword') {
    throw "Set a unique non-placeholder password for $key in .env first."
  }
  if ($value.IndexOfAny([char[]]@('$','"',"'",'`')) -ge 0) {
    throw "Avoid dollar signs, quotation marks and backticks in $key for this demo installer."
  }
  if ($value.Length -lt 12) {
    throw "Use a password of at least 12 characters for $key."
  }
}

$certDir = 'wazuh/config/wazuh_indexer_ssl_certs'
New-Item -ItemType Directory -Path $certDir -Force | Out-Null
if (-not $SkipCertificates -and -not (Test-Path (Join-Path $certDir 'root-ca.pem'))) {
  Write-Host 'Generating Wazuh TLS certificates...'
  docker compose -f wazuh/generate-indexer-certs.yml run --rm generator
  if ($LASTEXITCODE -ne 0) { throw 'Certificate generator failed. Check the Docker output above.' }
}
if (-not (Test-Path (Join-Path $certDir 'root-ca.pem'))) {
  throw 'root-ca.pem not found. Run without -SkipCertificates to generate certificates.'
}

$users = 'wazuh/config/wazuh_indexer/internal_users.yml'
if (Test-Path $users) {
  Write-Host 'Existing internal_users.yml found. Leaving it unchanged to avoid resetting user hashes.'
  Write-Host 'If this is a new installation, verify that its hashes match your .env passwords.'
  exit 0
}

$templateFile = 'wazuh/config/wazuh_indexer/internal_users.yml.template'
if (-not (Test-Path $templateFile)) { throw 'Missing Wazuh users template.' }
$template = Get-Content $templateFile -Raw -Encoding UTF8

foreach ($spec in @(
  @('admin','WAZUH_INDEXER_PASSWORD'),
  @('kibanaserver','WAZUH_KIBANA_PASSWORD')
)) {
  $user = [string]$spec[0]
  $secret = [string]$vars[[string]$spec[1]]
  Write-Host "Generating password hash for $user ..."
  $hashOutput = docker run --rm wazuh/wazuh-indexer:4.14.5 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p $secret 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0) { throw "Password hash generation failed for $user." }
  $hashMatch = [regex]::Match($hashOutput, '\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}')
  if (-not $hashMatch.Success) { throw "No bcrypt hash found for $user." }

  # Replace the hash inside this user block, whether it is already populated or a placeholder.
  $pattern = '(?m)^(' + [regex]::Escape($user) + ':\s*\r?\n\s*hash:\s*)[^\r\n]+'
  $regex = [regex]::new($pattern)
  if (-not $regex.IsMatch($template)) { throw "Could not find hash field for $user in template." }
  $newHash = '"' + $hashMatch.Value + '"'
  $template = $regex.Replace($template, [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $m.Groups[1].Value + $newHash }, 1)
}

$target = Join-Path (Get-Location) $users
[System.IO.File]::WriteAllText($target, $template, (New-Object System.Text.UTF8Encoding($false)))
Write-Host 'Wazuh initial certificate and user-hash setup completed.'
Write-Host 'Run: docker compose --profile wazuh --profile ai --profile slack up -d --build'
