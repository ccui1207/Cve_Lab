param(
    [string]$OutDir = ".\logs"
)

if (!(Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir | Out-Null
}

$Time = Get-Date -Format "yyyyMMdd_HHmmss"
$OutFile = Join-Path $OutDir "logcat_$Time.txt"

Write-Host "Clearing old logcat..."
adb logcat -c

Write-Host "Start collecting logcat."
Write-Host "Press Ctrl+C to stop."
adb logcat | Tee-Object -FilePath $OutFile
