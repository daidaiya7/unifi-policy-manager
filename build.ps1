param(
    [string]$DotNet = ""
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Version = "4.1.0"
$PublishDirectory = Join-Path $ProjectRoot "publish-$Version"

if (-not $DotNet) {
    $localDotNet = Join-Path $ProjectRoot ".dotnet\dotnet.exe"
    if (Test-Path -LiteralPath $localDotNet) { $DotNet = $localDotNet }
    else {
        $command = Get-Command dotnet -ErrorAction SilentlyContinue
        if ($command) { $DotNet = $command.Source }
    }
}

if (-not $DotNet -or -not (Test-Path -LiteralPath $DotNet)) {
    throw ".NET 8 SDK not found. Install it or pass -DotNet <path>."
}

& $DotNet publish (Join-Path $ProjectRoot "UniFiDnsManager.csproj") `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:DebugType=None `
    -p:DebugSymbols=false `
    -p:PublishTrimmed=false `
    -o $PublishDirectory

if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed." }

$publishExe = Join-Path $PublishDirectory "UniFi-Policy-Manager.exe"
$readme = Join-Path $ProjectRoot "README.md"
$license = Join-Path $ProjectRoot "LICENSE"
$presets = Join-Path $PublishDirectory "Presets"
$package = Join-Path $ProjectRoot "UniFi-Policy-Manager-$Version-win-x64.zip"
Compress-Archive -LiteralPath @($publishExe, $readme, $license, $presets) -DestinationPath $package -CompressionLevel Optimal -Force

Write-Host "Built: $publishExe"
Write-Host "Package: $package"
