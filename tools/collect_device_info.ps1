param(
    [string]$OutDir = "."
)

$OutFile = Join-Path $OutDir "device_info.txt"

if (!(Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir | Out-Null
}

function Run-AdbCommand($Title, $Args) {
    Add-Content $OutFile "[$Title]"
    $result = adb @Args 2>&1
    Add-Content $OutFile $result
    Add-Content $OutFile ""
    Write-Host "[$Title]"
    Write-Host $result
    Write-Host ""
}

Set-Content $OutFile "=== Android Device Info ==="
Add-Content $OutFile ""

Run-AdbCommand "Manufacturer" @("shell", "getprop", "ro.product.manufacturer")
Run-AdbCommand "Model" @("shell", "getprop", "ro.product.model")
Run-AdbCommand "Device" @("shell", "getprop", "ro.product.device")
Run-AdbCommand "Android Release" @("shell", "getprop", "ro.build.version.release")
Run-AdbCommand "SDK" @("shell", "getprop", "ro.build.version.sdk")
Run-AdbCommand "Security Patch" @("shell", "getprop", "ro.build.version.security_patch")
Run-AdbCommand "Build Fingerprint" @("shell", "getprop", "ro.build.fingerprint")
Run-AdbCommand "Kernel" @("shell", "uname", "-a")
Run-AdbCommand "SELinux" @("shell", "getenforce")
Run-AdbCommand "ADB Devices" @("devices")

Write-Host "Saved to: $OutFile"
