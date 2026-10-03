$ErrorActionPreference = "Stop"
Set-Location "E:\GSB\0279\A"
$proc = Start-Process node -ArgumentList "dist/src/cli/index.js","serve","--port","8731" -PassThru -WindowStyle Hidden
Start-Sleep 2
try {
  $imp = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8731/api/imports" -ContentType "application/json" -Body '{"path":"data/fixtures/thunk-fallback.exe"}'
  Write-Output "imported id=$($imp.report.id) duplicated=$($imp.duplicated)"
  $imports = Invoke-RestMethod "http://127.0.0.1:8731/api/reports/$($imp.report.id)/imports"
  Write-Output "usedThunk=$($imports.imports[0].usedThunk) func=$($imports.imports[0].functions[0].name)"
  $map = Invoke-RestMethod "http://127.0.0.1:8731/api/reports/1/map?rva=0x20e0&length=2"
  Write-Output "map 0x20e0 -> mappable=$($map.mappable) offset=$($map.fileOffset) section=$($map.sectionName)"
  try {
    Invoke-RestMethod "http://127.0.0.1:8731/api/reports/999/header" | Out-Null
  } catch {
    Write-Output "missing report status=$($_.Exception.Response.StatusCode.value__)"
  }
} finally {
  Stop-Process -Id $proc.Id -Force
}
