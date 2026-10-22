$ErrorActionPreference = "Stop"
$fw = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319"
$csc = "C:\Program Files\dotnet\sdk\9.0.101\Roslyn\bincore\csc.dll"
$dotnet = "C:\Program Files\dotnet\dotnet.exe"
$srcDir = Join-Path $PSScriptRoot "src"
$outDir = $PSScriptRoot

Write-Host "[1/2] Building DeviceInternalScanner.exe (Portable GUI + CLI)..." -ForegroundColor Cyan
& $dotnet exec $csc /noconfig /target:exe /platform:anycpu /optimize+ /codepage:65001 `
  /r:"$fw\mscorlib.dll" /r:"$fw\System.dll" /r:"$fw\System.Core.dll" /r:"$fw\System.Drawing.dll" /r:"$fw\System.Windows.Forms.dll" /r:"$fw\System.ServiceProcess.dll" `
  /out:"$outDir\DeviceInternalScanner.exe" `
  "$srcDir\SharedCore.cs" "$srcDir\SharedUi.cs" "$srcDir\AdvancedFeatures.cs" "$srcDir\Phase2Features.cs" "$srcDir\Phase3Features.cs" "$srcDir\Phase4Features.cs" "$srcDir\Phase5Features.cs" "$srcDir\Phase6Features.cs" "$srcDir\CveCatalogGenerator.cs" "$srcDir\InternalScannerProgram.cs"

Write-Host "[2/2] Building DeviceExternalScanner.exe (Portable GUI + CLI)..." -ForegroundColor Cyan
& $dotnet exec $csc /noconfig /target:exe /platform:anycpu /optimize+ /codepage:65001 `
  /r:"$fw\mscorlib.dll" /r:"$fw\System.dll" /r:"$fw\System.Core.dll" /r:"$fw\System.Drawing.dll" /r:"$fw\System.Windows.Forms.dll" /r:"$fw\System.ServiceProcess.dll" `
  /out:"$outDir\DeviceExternalScanner.exe" `
  "$srcDir\SharedCore.cs" "$srcDir\SharedUi.cs" "$srcDir\AdvancedFeatures.cs" "$srcDir\Phase2Features.cs" "$srcDir\Phase3Features.cs" "$srcDir\Phase4Features.cs" "$srcDir\Phase5Features.cs" "$srcDir\Phase6Features.cs" "$srcDir\CveCatalogGenerator.cs" "$srcDir\ExternalScannerProgram.cs"

Copy-Item "$outDir\DeviceInternalScanner.exe" "C:\Users\Anon\Desktop\DeviceInternalScanner.exe" -Force
Copy-Item "$outDir\DeviceExternalScanner.exe" "C:\Users\Anon\Desktop\DeviceExternalScanner.exe" -Force
Write-Host "Build succeeded! Latest binaries deployed to Desktop." -ForegroundColor Green
