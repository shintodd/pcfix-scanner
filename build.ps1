# pcfix desktop diagnostic scanner build script
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$sourceFile = Join-Path $scriptDir "Program.cs"
$manifestFile = Join-Path $scriptDir "app.manifest"
$outputExe = Join-Path $scriptDir "bin\pcfix-scanner.exe"
$publicExe = Join-Path $scriptDir "..\public\downloads\pcfix-scanner.exe"

# 1. Gracefully terminate any running pcfix-scanner processes so output file isn't locked
Get-Process -Name "*pcfix-scanner*" -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "Stopping running process: $($_.ProcessName) (PID: $($_.Id))..."
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Milliseconds 500

# 2. Clean old output binaries
if (Test-Path $outputExe) {
    Remove-Item $outputExe -Force -ErrorAction SilentlyContinue
}

Write-Host "Locating C# compiler (csc.exe)..."
$csc = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $csc)) {
    $csc = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
}
if (-not (Test-Path $csc)) {
    throw "csc.exe not found on system."
}

Write-Host "Locating WPF assemblies in GAC..."
$pf = (Get-ChildItem "C:\Windows\Microsoft.NET\assembly\GAC_MSIL\PresentationFramework" -Recurse -Filter "PresentationFramework.dll" | Select-Object -First 1).FullName
$pc = (Get-ChildItem "C:\Windows\Microsoft.NET\assembly\GAC_64\PresentationCore" -Recurse -Filter "PresentationCore.dll" -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
if (-not $pc) {
    $pc = (Get-ChildItem "C:\Windows\Microsoft.NET\assembly" -Recurse -Filter "PresentationCore.dll" | Select-Object -First 1).FullName
}
$wb = (Get-ChildItem "C:\Windows\Microsoft.NET\assembly\GAC_MSIL\WindowsBase" -Recurse -Filter "WindowsBase.dll" | Select-Object -First 1).FullName
$sx = (Get-ChildItem "C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Xaml" -Recurse -Filter "System.Xaml.dll" | Select-Object -First 1).FullName
$sm = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Management.dll"
if (-not (Test-Path $sm)) {
    $sm = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\System.Management.dll"
}

Write-Host "Compiling pcfix-scanner.exe..."
$args = @(
    "/target:winexe",
    "/optimize+",
    "/platform:anycpu",
    "/r:System.dll",
    "/r:System.Core.dll",
    "/r:$pf",
    "/r:$pc",
    "/r:$wb",
    "/r:$sx",
    "/r:$sm",
    "/win32manifest:$manifestFile",
    "/out:$outputExe",
    $sourceFile
)

& $csc $args
if ($LASTEXITCODE -ne 0) {
    throw "Compilation failed with exit code $LASTEXITCODE"
}

if (Test-Path $outputExe) {
    $size = (Get-Item $outputExe).Length / 1KB
    Write-Host "Build success! Output: $outputExe ($([math]::Round($size, 1)) KB)" -ForegroundColor Green
    
    # Copy to public/downloads
    Copy-Item $outputExe $publicExe -Force
    Write-Host "Copied to: $publicExe" -ForegroundColor Cyan
} else {
    throw "Build failed: $outputExe not generated."
}
