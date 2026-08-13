[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = $PSScriptRoot
$repoRoot = Split-Path -Parent $projectRoot
$sourceRoot = Join-Path $projectRoot 'src'
$outputRoot = Join-Path $projectRoot 'bin'
$toolRoot = Join-Path $projectRoot 'third_party\upx-5.2.0'
$upxPath = Join-Path $toolRoot 'upx.exe'
$licensePath = Join-Path $toolRoot 'LICENSE'
$copyingPath = Join-Path $toolRoot 'COPYING'
$expectedUpxHash = 'F4C0CC7ACA0F1FF0D0B750E966B44139F2FA1A2DB7281F48FC52194400712E1D'
$cscPath = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'

if (-not (Test-Path -LiteralPath $cscPath -PathType Leaf)) {
    throw "C# compiler not found: $cscPath"
}
foreach ($required in @($upxPath, $licensePath, $copyingPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required UPX file not found: $required"
    }
}
$actualUpxHash = (Get-FileHash -LiteralPath $upxPath -Algorithm SHA256).Hash
if ($actualUpxHash -ne $expectedUpxHash) {
    throw "UPX SHA256 mismatch. Expected $expectedUpxHash, got $actualUpxHash"
}

if (-not (Test-Path -LiteralPath $outputRoot)) {
    [void](New-Item -ItemType Directory -Path $outputRoot)
}

$outputPath = Join-Path $outputRoot 'FufuRedirectCraftPatcher.exe'
$sources = @(Get-ChildItem -LiteralPath $sourceRoot -Filter '*.cs' -File |
    Sort-Object Name | ForEach-Object { $_.FullName })

$arguments = @(
    '/nologo',
    '/target:winexe',
    '/platform:x64',
    '/optimize+',
    '/debug-',
    ('/win32manifest:' + (Join-Path $sourceRoot 'app.manifest')),
    ('/out:' + $outputPath),
    '/reference:System.dll',
    '/reference:System.Core.dll',
    '/reference:System.Drawing.dll',
    '/reference:System.Windows.Forms.dll',
    '/reference:System.Web.Extensions.dll',
    ('/resource:' + $upxPath + ',Embedded.upx.exe,private'),
    ('/resource:' + $licensePath + ',Embedded.UPX-LICENSE.txt,private'),
    ('/resource:' + $copyingPath + ',Embedded.UPX-COPYING.txt,private')
) + $sources

& $cscPath @arguments
if ($LASTEXITCODE -ne 0) {
    throw "C# compiler exited with code $LASTEXITCODE"
}

$item = Get-Item -LiteralPath $outputPath
$hash = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash
Write-Host "Built: $($item.FullName)"
Write-Host "Size:  $($item.Length) bytes"
Write-Host "SHA256: $hash"
