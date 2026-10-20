$ErrorActionPreference = 'Stop'
$base='http://localhost:8088'
$samples=Invoke-RestMethod "$base/api/samples"
$event=$samples[1]
$id="ai-test-$(Get-Date -Format yyyyMMddHHmmss)-$([guid]::NewGuid().ToString('N').Substring(0,8))"
$event | Add-Member -NotePropertyName _id -NotePropertyValue $id -Force
$body=@{alert=$event} | ConvertTo-Json -Depth 40 -Compress
$bytes=[Text.Encoding]::UTF8.GetBytes($body)
$result=Invoke-RestMethod -Uri "$base/api/ingest" -Method Post -ContentType 'application/json; charset=utf-8' -Body $bytes
Write-Host "Category:" $result.category
Write-Host "Mode:" $result.mode
Write-Host "L1:" $result.l1
Write-Host "L2:" $result.l2
