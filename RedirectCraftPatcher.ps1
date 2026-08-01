[CmdletBinding()]
param(
    [ValidateSet('Gui', 'Analyze', 'Patch', 'Restore')]
    [string]$Action = 'Gui',

    [string]$Path,

    [string]$ManifestPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$script:ToolName = 'Fufu RedirectCraft Patcher'
$script:ToolVersion = '1.0.0'
$script:PluginRelativePath = 'Plugins\FuFuPlugin\FufuLauncher.UnlockerIsland.dll'
$script:CraftLog = '[Hotkey] Craft function triggered.'
$script:AutoCookLog = '[Hotkey] Auto Cook function triggered.'
$script:ConfigName = 'RedirectCraft'
$script:Nop = [byte]0x90

#region 基础工具函数

function Convert-HexToBytes {
    param([Parameter(Mandatory = $true)][string]$Hex)
    $clean = ($Hex -replace '[^0-9A-Fa-f]', '')
    if (($clean.Length % 2) -ne 0) { throw "Invalid hexadecimal byte string: $Hex" }
    $bytes = New-Object byte[] ($clean.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($clean.Substring($i * 2, 2), 16)
    }
    return $bytes
}

function Convert-BytesToHex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Test-ByteRange {
    param([Parameter(Mandatory = $true)][byte[]]$Data,
          [Parameter(Mandatory = $true)][long]$Offset,
          [Parameter(Mandatory = $true)][byte[]]$Expected)
    if ($Offset -lt 0 -or ($Offset + $Expected.Length) -gt $Data.Length) { return $false }
    for ($i = 0; $i -lt $Expected.Length; $i++) {
        if ($Data[$Offset + $i] -ne $Expected[$i]) { return $false }
    }
    return $true
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$FilePath)
    $stream = [System.IO.File]::OpenRead($FilePath)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '') }
    finally { $sha.Dispose(); $stream.Dispose() }
}

function Get-SignatureStatus {
    param([Parameter(Mandatory = $true)][string]$FilePath)
    try { return (Get-AuthenticodeSignature -LiteralPath $FilePath).Status.ToString() }
    catch { return 'Unavailable' }
}

function Get-VersionText {
    param([Parameter(Mandatory = $true)][string]$FilePath)
    try {
        $v = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($FilePath).FileVersion
        if ([string]::IsNullOrWhiteSpace($v)) {
            return '(none)'
        }
        else {
            return $v
        }
    }
    catch {
        return '(unavailable)'
    }
}

#endregion

#region PE 解析与反汇编辅助

function Assert-Range {
    param([byte[]]$Data, [long]$Offset, [long]$Length, [string]$Description)
    if ($Offset -lt 0 -or $Length -lt 0 -or ($Offset + $Length) -gt $Data.Length) {
        throw "Invalid PE range for $Description."
    }
}

function Get-PeInfo {
    param([Parameter(Mandatory = $true)][byte[]]$Data)

    Assert-Range $Data 0 0x40 'DOS header'
    if ($Data[0] -ne 0x4D -or $Data[1] -ne 0x5A) {
        throw 'The selected file is not a PE file (missing MZ header).'
    }
    $peOffset = [BitConverter]::ToInt32($Data, 0x3C)
    Assert-Range $Data $peOffset 24 'PE header'
    if ($Data[$peOffset] -ne 0x50 -or $Data[$peOffset + 1] -ne 0x45 -or
        $Data[$peOffset + 2] -ne 0 -or $Data[$peOffset + 3] -ne 0) {
        throw 'The selected file has an invalid PE signature.'
    }

    $machine = [BitConverter]::ToUInt16($Data, $peOffset + 4)
    $sectionCount = [BitConverter]::ToUInt16($Data, $peOffset + 6)
    $optionalSize = [BitConverter]::ToUInt16($Data, $peOffset + 20)
    $coffCharacteristics = [BitConverter]::ToUInt16($Data, $peOffset + 22)
    $optionalOffset = $peOffset + 24
    Assert-Range $Data $optionalOffset $optionalSize 'optional header'

    if ($machine -ne 0x8664) { throw "Only AMD64 DLLs are supported. PE machine: 0x$($machine.ToString('X4'))" }
    if ([BitConverter]::ToUInt16($Data, $optionalOffset) -ne 0x20B) { throw 'Only PE32+ (64-bit) images are supported.' }
    if (($coffCharacteristics -band 0x2000) -eq 0) { throw 'The selected PE image is not marked as a DLL.' }
    if ($sectionCount -lt 1 -or $sectionCount -gt 96) { throw "Unreasonable PE section count: $sectionCount" }

    $sectionTable = $optionalOffset + $optionalSize
    Assert-Range $Data $sectionTable ($sectionCount * 40) 'section table'
    $sections = @()
    for ($i = 0; $i -lt $sectionCount; $i++) {
        $off = $sectionTable + ($i * 40)
        $name = [Text.Encoding]::ASCII.GetString($Data, $off, 8).Trim([char]0)
        $virtualSize = [long][BitConverter]::ToUInt32($Data, $off + 8)
        $rva = [long][BitConverter]::ToUInt32($Data, $off + 12)
        $rawSize = [long][BitConverter]::ToUInt32($Data, $off + 16)
        $rawOffset = [long][BitConverter]::ToUInt32($Data, $off + 20)
        $characteristics = [long][BitConverter]::ToUInt32($Data, $off + 36)
        Assert-Range $Data $rawOffset $rawSize "section $name"
        $sections += [pscustomobject]@{
            Name = $name
            Rva = $rva
            VirtualSize = $virtualSize
            RawOffset = $rawOffset
            RawSize = $rawSize
            Executable = (($characteristics -band 0x20000000) -ne 0)
        }
    }
    return [pscustomobject]@{ PeOffset = [long]$peOffset; Machine = $machine; Sections = $sections }
}

function Convert-RawToRva {
    param($Pe, [long]$RawOffset)
    foreach ($sec in $Pe.Sections) {
        if ($RawOffset -ge $sec.RawOffset -and $RawOffset -lt ($sec.RawOffset + $sec.RawSize)) {
            return [long]($sec.Rva + ($RawOffset - $sec.RawOffset))
        }
    }
    return $null
}

function Test-RvaInExecutableSection {
    param($Pe, [long]$Rva)
    foreach ($sec in $Pe.Sections) {
        $mapped = [Math]::Max($sec.VirtualSize, $sec.RawSize)
        if ($sec.Executable -and $Rva -ge $sec.Rva -and $Rva -lt ($sec.Rva + $mapped)) {
            return $true
        }
    }
    return $false
}

function Find-ByteSequence {
    param([byte[]]$Data, [byte[]]$Needle, [long]$Start = 0, [long]$EndExclusive = -1)
    if ($EndExclusive -lt 0 -or $EndExclusive -gt $Data.Length) { $EndExclusive = $Data.Length }
    $hits = New-Object 'System.Collections.Generic.List[long]'
    if ($Needle.Length -eq 0 -or ($EndExclusive - $Start) -lt $Needle.Length) { return $hits.ToArray() }
    $last = $EndExclusive - $Needle.Length
    for ($off = $Start; $off -le $last; $off++) {
        if ($Data[$off] -ne $Needle[0]) { continue }
        $match = $true
        for ($j = 1; $j -lt $Needle.Length; $j++) {
            if ($Data[$off + $j] -ne $Needle[$j]) { $match = $false; break }
        }
        if ($match) { $hits.Add([long]$off) }
    }
    return $hits.ToArray()
}

function Find-AsciiString {
    param([byte[]]$Data, [string]$Text)
    $needle = [Text.Encoding]::ASCII.GetBytes($Text + [char]0)
    return @(Find-ByteSequence $Data $needle)
}

function Find-RipRelativeLeaReferences {
    param([byte[]]$Data, $Pe, [long]$TargetRva)
    $refs = @()
    foreach ($sec in $Pe.Sections | Where-Object { $_.Executable }) {
        $start = [long]$sec.RawOffset
        $end = [long]($sec.RawOffset + $sec.RawSize)
        for ($off = $start; $off -le ($end - 7); $off++) {
            if ($Data[$off] -lt 0x48 -or $Data[$off] -gt 0x4F -or $Data[$off + 1] -ne 0x8D) { continue }
            if (($Data[$off + 2] -band 0xC7) -ne 0x05) { continue }
            $instrRva = Convert-RawToRva $Pe $off
            if ($null -eq $instrRva) { continue }
            $disp = [BitConverter]::ToInt32($Data, [int]($off + 3))
            $resolved = [long]$instrRva + 7 + $disp
            if ($resolved -eq $TargetRva) {
                $refs += [pscustomobject]@{ Offset = [long]$off; Rva = [long]$instrRva }
            }
        }
    }
    return @($refs)
}

function Get-JeInstruction {
    param([byte[]]$Data, $Pe, [long]$Offset)
    if ($Offset -lt 0 -or $Offset -ge $Data.Length) { return $null }
    $len = 0; $disp = 0
    if (($Offset + 6) -le $Data.Length -and $Data[$Offset] -eq 0x0F -and $Data[$Offset + 1] -eq 0x84) {
        $len = 6; $disp = [BitConverter]::ToInt32($Data, [int]($Offset + 2))
    }
    elseif (($Offset + 2) -le $Data.Length -and $Data[$Offset] -eq 0x74) {
        $len = 2; $disp = [int]$Data[$Offset + 1]; if ($disp -ge 128) { $disp -= 256 }
    }
    else { return $null }

    $rva = Convert-RawToRva $Pe $Offset
    if ($null -eq $rva) { return $null }
    return [pscustomobject]@{
        Offset = [long]$Offset
        Rva = [long]$rva
        Length = [int]$len
        TargetRva = [long]($rva + $len + $disp)
    }
}

function Test-ByteConditionEndingAt {
    param([byte[]]$Data, [long]$EndOffset)
    # test reg8, reg8
    if ($EndOffset -ge 2 -and $Data[$EndOffset - 2] -eq 0x84) {
        $modrm = $Data[$EndOffset - 1]
        if (($modrm -band 0xC0) -eq 0xC0 -and (($modrm -shr 3) -band 7) -eq ($modrm -band 7)) { return $true }
    }
    # cmp reg8, 0
    if ($EndOffset -ge 3 -and $Data[$EndOffset - 3] -eq 0x80 -and
        (($Data[$EndOffset - 2] -band 0xF8) -eq 0xF8) -and $Data[$EndOffset - 1] -eq 0) { return $true }
    return $false
}

function Get-Group80Length {
    param([byte[]]$Data, [long]$OpcodeOffset)
    if ($OpcodeOffset -lt 0 -or ($OpcodeOffset + 3) -gt $Data.Length -or $Data[$OpcodeOffset] -ne 0x80) { return 0 }
    $modrm = $Data[$OpcodeOffset + 1]
    $mod = ($modrm -shr 6) -band 3
    $rm = $modrm -band 7
    $pos = $OpcodeOffset + 2
    if ($mod -ne 3 -and $rm -eq 4) {
        if ($pos -ge $Data.Length) { return 0 }
        $sib = $Data[$pos]; $pos++
        if ($mod -eq 0 -and ($sib -band 7) -eq 5) { $pos += 4 }
    }
    if ($mod -eq 0 -and $rm -eq 5) { $pos += 4 }
    elseif ($mod -eq 1) { $pos++ }
    elseif ($mod -eq 2) { $pos += 4 }
    $pos++
    if ($pos -gt $Data.Length) { return 0 }
    return [int]($pos - $OpcodeOffset)
}

function Test-CmpByteZeroEndingAt {
    param([byte[]]$Data, [long]$EndOffset)
    $start = [Math]::Max(0, $EndOffset - 10)
    for ($off = $start; $off -le ($EndOffset - 3); $off++) {
        if ($Data[$off] -ne 0x80) { continue }
        $len = Get-Group80Length $Data $off
        if ($len -le 0 -or ($off + $len) -ne $EndOffset) { continue }
        if (($Data[$off + 1] -band 0x38) -ne 0x38) { continue }
        if ($Data[$EndOffset - 1] -ne 0) { continue }
        return $true
    }
    return $false
}

function Get-RuntimeFunction {
    param([byte[]]$Data, $Pe, [long]$Rva)
    $pdata = $Pe.Sections | Where-Object { $_.Name -eq '.pdata' } | Select-Object -First 1
    if ($null -eq $pdata) { return $null }
    $end = $pdata.RawOffset + $pdata.RawSize
    for ($off = $pdata.RawOffset; ($off + 12) -le $end; $off += 12) {
        $begin = [long][BitConverter]::ToUInt32($Data, [int]$off)
        $endf = [long][BitConverter]::ToUInt32($Data, [int]($off + 4))
        if ($begin -eq 0 -and $endf -eq 0) { continue }
        if ($Rva -ge $begin -and $Rva -lt $endf) { return [pscustomobject]@{ BeginRva = $begin; EndRva = $endf } }
    }
    return $null
}

#endregion

#region 分析、补丁与恢复

function Find-ManifestForHash {
    param([string]$TargetPath, [string]$CurrentSha256)
    $dir = Split-Path -Parent $TargetPath
    $name = [IO.Path]::GetFileName($TargetPath)
    $manifests = @(Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name.StartsWith($name + '.', [StringComparison]::OrdinalIgnoreCase) -and
                       $_.Name.EndsWith('.redirectcraft.json', [StringComparison]::OrdinalIgnoreCase) })
    foreach ($f in $manifests) {
        try {
            $m = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json
            if ($m.PatchedSha256.ToString().ToUpperInvariant() -eq $CurrentSha256) {
                return [pscustomobject]@{ File = $f.FullName; Data = $m }
            }
        } catch { continue }
    }
    return $null
}

function New-AnalysisResult {
    param([string]$FullPath, [string]$Sha256, [string]$Signature, [string]$Version)
    return [pscustomobject]@{
        Path          = $FullPath
        Sha256        = $Sha256
        Signature     = $Signature
        Version       = $Version
        State         = 'Unsupported'
        Detector      = '(none)'
        PatchOffset   = $null
        PatchRva      = $null
        OriginalBytes = [byte[]]@()
        PatchedBytes  = [byte[]]@()
        Message       = 'No supported patch site was found.'
        Manifest      = $null
    }
}

function Get-RedirectCraftAnalysis {
    param([Parameter(Mandatory = $true)][string]$FilePath)

    $item = Get-Item -LiteralPath $FilePath -ErrorAction Stop
    if ($item.PSIsContainer) { throw 'Select the plugin DLL, not a directory.' }
    $fullPath = $item.FullName
    $data = [IO.File]::ReadAllBytes($fullPath)
    $pe = Get-PeInfo $data
    $sha256 = (Get-Sha256 $fullPath).ToUpperInvariant()
    $signature = Get-SignatureStatus $fullPath
    $version = Get-VersionText $fullPath
    $result = New-AnalysisResult $fullPath $sha256 $signature $version

    $manifestMatch = Find-ManifestForHash $fullPath $sha256
    if ($null -ne $manifestMatch) {
        $m = $manifestMatch.Data
        $off = [long]$m.PatchOffset
        $before = Convert-HexToBytes $m.OriginalBytes
        $after = Convert-HexToBytes $m.PatchedBytes
        if (Test-ByteRange $data $off $after) {
            $result.State = 'AlreadyPatched'
            $result.Detector = 'Verified local manifest'
            $result.PatchOffset = $off
            $result.PatchRva = Convert-RawToRva $pe $off
            $result.OriginalBytes = $before
            $result.PatchedBytes = $after
            $result.Message = 'This DLL was patched by this tool and matches its backup manifest.'
            $result.Manifest = $manifestMatch.File
            return $result
        }
    }

    if (-not [string]::Equals([IO.Path]::GetFileName($fullPath), 'FufuLauncher.UnlockerIsland.dll',
                              [StringComparison]::OrdinalIgnoreCase)) {
        $result.Message = "Automatic detection requires the exact file name FufuLauncher.UnlockerIsland.dll."
        return $result
    }
    if ($signature -ne 'Valid') {
        $result.Message = "Automatic detection requires a valid Authenticode signature. Current status: $signature"
        return $result
    }

    $configStrings = @(Find-AsciiString $data $script:ConfigName)
    $craftStrings = @(Find-AsciiString $data $script:CraftLog)
    $autoCookStrings = @(Find-AsciiString $data $script:AutoCookLog)
    if ($configStrings.Count -ne 1 -or $craftStrings.Count -ne 1 -or $autoCookStrings.Count -ne 1) {
        $result.Message = ('Semantic strings missing or ambiguous (RedirectCraft={0}, CraftLog={1}, AutoCookLog={2}).' -f
                           $configStrings.Count, $craftStrings.Count, $autoCookStrings.Count)
        return $result
    }

    $configRva = Convert-RawToRva $pe $configStrings[0]
    $craftRva = Convert-RawToRva $pe $craftStrings[0]
    $autoCookRva = Convert-RawToRva $pe $autoCookStrings[0]
    if ($null -eq $configRva -or $null -eq $craftRva -or $null -eq $autoCookRva) {
        $result.Message = 'One or more semantic strings are outside mapped PE sections.'
        return $result
    }

    $configRefs = @(Find-RipRelativeLeaReferences $data $pe $configRva)
    $craftRefs = @(Find-RipRelativeLeaReferences $data $pe $craftRva)
    $autoCookRefs = @(Find-RipRelativeLeaReferences $data $pe $autoCookRva)
    if ($configRefs.Count -ne 1 -or $craftRefs.Count -ne 1 -or $autoCookRefs.Count -lt 1) {
        $result.Message = ('Semantic references missing or ambiguous (RedirectCraft={0}, CraftLog={1}, AutoCookLog={2}).' -f
                           $configRefs.Count, $craftRefs.Count, $autoCookRefs.Count)
        return $result
    }

    $candidates = @()
    foreach ($cr in $craftRefs) {
        $sceneJe = Get-JeInstruction $data $pe ($cr.Offset - 6)
        if ($null -eq $sceneJe) { $sceneJe = Get-JeInstruction $data $pe ($cr.Offset - 2) }
        if ($null -eq $sceneJe -or ($sceneJe.Offset + $sceneJe.Length) -ne $cr.Offset) { continue }
        if (-not (Test-ByteConditionEndingAt $data $sceneJe.Offset)) { continue }
        if ($sceneJe.TargetRva -le $cr.Rva -or ($sceneJe.TargetRva - $cr.Rva) -gt 0x400 -or
            -not (Test-RvaInExecutableSection $pe $sceneJe.TargetRva)) { continue }

        $guards = @()
        $searchStart = [Math]::Max(0, $sceneJe.Offset - 96)
        for ($off = $searchStart; $off -lt $sceneJe.Offset; $off++) {
            $g = Get-JeInstruction $data $pe $off
            if ($null -eq $g -or $g.TargetRva -ne $sceneJe.TargetRva) { continue }
            if (-not (Test-CmpByteZeroEndingAt $data $g.Offset)) { continue }
            $guards += $g
        }
        if ($guards.Count -ne 1) { continue }

        $func = Get-RuntimeFunction $data $pe $sceneJe.Rva
        if ($null -eq $func -or
            $cr.Rva -lt $func.BeginRva -or $cr.Rva -ge $func.EndRva -or
            $sceneJe.TargetRva -lt $func.BeginRva -or $sceneJe.TargetRva -ge $func.EndRva -or
            $guards[0].Rva -lt $func.BeginRva -or $guards[0].Rva -ge $func.EndRva) { continue }

        $nextAc = @($autoCookRefs | Where-Object { $_.Rva -gt $cr.Rva } | Sort-Object Rva | Select-Object -First 1)
        if ($nextAc.Count -ne 1 -or $sceneJe.TargetRva -ge $nextAc[0].Rva -or
            $nextAc[0].Rva -ge $func.EndRva) { continue }

        $orig = New-Object byte[] $sceneJe.Length
        [Array]::Copy($data, [int]$sceneJe.Offset, $orig, 0, $sceneJe.Length)
        $pat = New-Object byte[] $sceneJe.Length
        for ($i = 0; $i -lt $pat.Length; $i++) { $pat[$i] = $script:Nop }
        $candidates += [pscustomobject]@{
            Branch   = $sceneJe
            Guard    = $guards[0]
            Original = $orig
            Patched  = $pat
        }
    }

    if ($candidates.Count -ne 1) {
        $result.Message = "Structural validation produced $($candidates.Count) candidates; this build was not modified."
        return $result
    }

    $c = $candidates[0]
    $result.State = 'Patchable'
    $result.Detector = 'Signed-build semantic/control-flow detector'
    $result.PatchOffset = [long]$c.Branch.Offset
    $result.PatchRva = [long]$c.Branch.Rva
    $result.OriginalBytes = $c.Original
    $result.PatchedBytes = $c.Patched
    $result.Message = 'Ready. A unique RedirectCraft scene guard was proven; the separate feature switch remains intact.'
    return $result
}

function Format-Analysis {
    param($Analysis)
    $lines = @(
        "Tool:      $($script:ToolName) $($script:ToolVersion)",
        "Path:      $($Analysis.Path)",
        "Version:   $($Analysis.Version)",
        "SHA-256:   $($Analysis.Sha256)",
        "Signature: $($Analysis.Signature)",
        "State:     $($Analysis.State)",
        "Detector:  $($Analysis.Detector)"
    )
    if ($null -ne $Analysis.PatchOffset) {
        $lines += "File offset: 0x$($Analysis.PatchOffset.ToString('X'))"
        if ($null -ne $Analysis.PatchRva) { $lines += "RVA:         0x$($Analysis.PatchRva.ToString('X'))" }
        $lines += "Before:      $(Convert-BytesToHex $Analysis.OriginalBytes)"
        $lines += "After:       $(Convert-BytesToHex $Analysis.PatchedBytes)"
    }
    $lines += ''; $lines += $Analysis.Message
    return $lines -join [Environment]::NewLine
}

function Assert-FileUnlocked {
    param([string]$FilePath)
    try {
        $s = [IO.File]::Open($FilePath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $s.Dispose()
    } catch { throw 'The DLL is locked or not writable. Close the game and launcher, then try again.' }
}

function Write-Manifest {
    param([string]$ManifestFile, $Manifest)
    $json = $Manifest | ConvertTo-Json -Depth 5
    $utf8 = New-Object System.Text.UTF8Encoding -ArgumentList $false
    [IO.File]::WriteAllText($ManifestFile, $json, $utf8)
}

function Invoke-RedirectCraftPatch {
    param([Parameter(Mandatory = $true)]$Analysis)

    if ($Analysis.State -eq 'AlreadyPatched') {
        return [pscustomobject]@{
            Message      = 'No change was needed; this DLL is already patched.'
            BackupPath   = $null
            ManifestPath = $Analysis.Manifest
            PatchedSha256 = $Analysis.Sha256
        }
    }
    if ($Analysis.State -ne 'Patchable') { throw "This DLL is not patchable: $($Analysis.Message)" }

    $target = $Analysis.Path
    Assert-FileUnlocked $target
    $currentHash = (Get-Sha256 $target).ToUpperInvariant()
    if ($currentHash -ne $Analysis.Sha256) { throw 'The DLL changed after analysis. Analyze it again.' }

    $original = [IO.File]::ReadAllBytes($target)
    if (-not (Test-ByteRange $original $Analysis.PatchOffset $Analysis.OriginalBytes)) {
        throw 'Patch-site bytes changed after analysis. No file was modified.'
    }
    $patched = [byte[]]$original.Clone()
    for ($i = 0; $i -lt $Analysis.PatchedBytes.Length; $i++) {
        $patched[$Analysis.PatchOffset + $i] = $Analysis.PatchedBytes[$i]
    }

    $diffCount = 0
    for ($i = 0; $i -lt $original.Length; $i++) {
        if ($original[$i] -ne $patched[$i]) {
            $diffCount++
            if ($i -lt $Analysis.PatchOffset -or $i -ge ($Analysis.PatchOffset + $Analysis.PatchedBytes.Length)) {
                throw 'Internal verification failed: a byte outside the patch range changed.'
            }
        }
    }
    if ($diffCount -ne $Analysis.PatchedBytes.Length) {
        throw "Internal verification failed: expected $($Analysis.PatchedBytes.Length) changed bytes, got $diffCount."
    }

    $dir = Split-Path -Parent $target
    $fileName = [IO.Path]::GetFileName($target)
    $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
    $hashPrefix = $Analysis.Sha256.Substring(0, 12)
    $base = "$fileName.$ts.$hashPrefix"
    $backupPath = Join-Path $dir ($base + '.fufu-backup')
    if (Test-Path -LiteralPath $backupPath) {
        $backupPath = Join-Path $dir ($base + '.' + [Guid]::NewGuid().ToString('N') + '.fufu-backup')
    }
    $manifestPath = $backupPath + '.redirectcraft.json'
    $temp = Join-Path $dir ('.' + $fileName + '.' + [Guid]::NewGuid().ToString('N') + '.tmp')

    try {
        [IO.File]::WriteAllBytes($temp, $patched)
        $tempData = [IO.File]::ReadAllBytes($temp)
        [void](Get-PeInfo $tempData)
        if (-not (Test-ByteRange $tempData $Analysis.PatchOffset $Analysis.PatchedBytes)) {
            throw 'Temporary-file verification failed.'
        }
        $expectedPatchedHash = (Get-Sha256 $temp).ToUpperInvariant()
        [IO.File]::Replace($temp, $target, $backupPath, $true)
        $patchedHash = (Get-Sha256 $target).ToUpperInvariant()
        $backupHash = (Get-Sha256 $backupPath).ToUpperInvariant()
        if ($patchedHash -ne $expectedPatchedHash) {
            if ($backupHash -eq $Analysis.Sha256) { [IO.File]::Copy($backupPath, $target, $true) }
            throw 'Patched-file verification failed after replacement; the original DLL was restored.'
        }
        if ($backupHash -ne $Analysis.Sha256) { throw 'Backup verification failed after replacement.' }

        $manifest = [ordered]@{
            FormatVersion  = 1
            Tool           = $script:ToolName
            ToolVersion    = $script:ToolVersion
            CreatedUtc     = [DateTime]::UtcNow.ToString('o')
            TargetFileName = $fileName
            FileVersion    = $Analysis.Version
            Detector       = $Analysis.Detector
            OriginalSha256 = $Analysis.Sha256
            PatchedSha256  = $patchedHash
            PatchOffset    = [long]$Analysis.PatchOffset
            PatchRva       = [long]$Analysis.PatchRva
            OriginalBytes  = Convert-BytesToHex $Analysis.OriginalBytes
            PatchedBytes   = Convert-BytesToHex $Analysis.PatchedBytes
            BackupFileName = [IO.Path]::GetFileName($backupPath)
        }
        Write-Manifest $manifestPath $manifest

        return [pscustomobject]@{
            Message       = 'Patch installed successfully. The modified DLL no longer has a valid Authenticode signature.'
            BackupPath    = $backupPath
            ManifestPath  = $manifestPath
            PatchedSha256 = $patchedHash
        }
    }
    finally { if (Test-Path $temp) { Remove-Item $temp -Force } }
}

function Get-RestoreDescriptor {
    param([string]$TargetPath, [string]$RequestedManifest)
    $targetHash = (Get-Sha256 $TargetPath).ToUpperInvariant()
    if (-not [string]::IsNullOrWhiteSpace($RequestedManifest)) {
        $mfile = (Get-Item -LiteralPath $RequestedManifest).FullName
        $m = Get-Content -LiteralPath $mfile -Raw | ConvertFrom-Json
        $mdir = [IO.Path]::GetFullPath((Split-Path -Parent $mfile))
        if (-not [string]::Equals($m.TargetFileName.ToString(), [IO.Path]::GetFileName($TargetPath),
                                  [StringComparison]::OrdinalIgnoreCase)) {
            throw 'The selected manifest belongs to a different target file.'
        }
        $bp = [IO.Path]::GetFullPath((Join-Path $mdir $m.BackupFileName))
        if ((Split-Path -Parent $bp) -ne $mdir) { throw 'The manifest backup path must remain in the manifest directory.' }
        return [pscustomobject]@{
            Label          = $mfile
            BackupPath     = $bp
            OriginalSha256 = $m.OriginalSha256.ToString().ToUpperInvariant()
            PatchedSha256  = $m.PatchedSha256.ToString().ToUpperInvariant()
        }
    }

    $match = Find-ManifestForHash $TargetPath $targetHash
    if ($null -ne $match) {
        $m = $match.Data
        $mdir = [IO.Path]::GetFullPath((Split-Path -Parent $match.File))
        if (-not [string]::Equals($m.TargetFileName.ToString(), [IO.Path]::GetFileName($TargetPath),
                                  [StringComparison]::OrdinalIgnoreCase)) {
            throw 'The matching manifest belongs to a different target file.'
        }
        $bp = [IO.Path]::GetFullPath((Join-Path $mdir $m.BackupFileName))
        if ((Split-Path -Parent $bp) -ne $mdir) { throw 'The manifest backup path must remain in the manifest directory.' }
        return [pscustomobject]@{
            Label          = $match.File
            BackupPath     = $bp
            OriginalSha256 = $m.OriginalSha256.ToString().ToUpperInvariant()
            PatchedSha256  = $m.PatchedSha256.ToString().ToUpperInvariant()
        }
    }
    throw 'No verified backup manifest matches the selected DLL.'
}

function Invoke-RedirectCraftRestore {
    param([string]$TargetPath, $Descriptor)
    $target = (Get-Item -LiteralPath $TargetPath).FullName
    $backup = (Get-Item -LiteralPath $Descriptor.BackupPath).FullName
    $targetHash = (Get-Sha256 $target).ToUpperInvariant()
    $backupHash = (Get-Sha256 $backup).ToUpperInvariant()
    if ($targetHash -ne $Descriptor.PatchedSha256) { throw 'The current DLL does not match the patched hash in the manifest.' }
    if ($backupHash -ne $Descriptor.OriginalSha256) { throw 'The backup DLL hash does not match its manifest.' }

    Assert-FileUnlocked $target
    $dir = Split-Path -Parent $target
    $fileName = [IO.Path]::GetFileName($target)
    $temp = Join-Path $dir ('.' + $fileName + '.' + [Guid]::NewGuid().ToString('N') + '.restore.tmp')
    $emerg = Join-Path $dir ('.' + $fileName + '.' + [Guid]::NewGuid().ToString('N') + '.restore-backup')
    try {
        [IO.File]::Copy($backup, $temp, $false)
        [IO.File]::Replace($temp, $target, $emerg, $true)
        $restoredHash = (Get-Sha256 $target).ToUpperInvariant()
        if ($restoredHash -ne $Descriptor.OriginalSha256) {
            [IO.File]::Copy($emerg, $target, $true)
            throw 'Restore verification failed; the patched DLL was put back.'
        }
        return [pscustomobject]@{
            Message    = 'The verified official DLL was restored successfully.'
            Sha256     = $restoredHash
            BackupPath = $backup
        }
    }
    finally {
        if (Test-Path $temp) { Remove-Item $temp -Force }
        if (Test-Path $emerg) { Remove-Item $emerg -Force }
    }
}

function Write-ToolLog {
    param([string]$Text)
    try {
        $root = Join-Path $env:LOCALAPPDATA 'FufuRedirectCraftPatcher\Logs'
        if (-not (Test-Path $root)) { [void](New-Item -ItemType Directory -Path $root -Force) }
        $logPath = Join-Path $root ((Get-Date -Format 'yyyyMMdd') + '.log')
        $entry = ('[{0}] {1}{2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Text, [Environment]::NewLine)
        [IO.File]::AppendAllText($logPath, $entry)
    } catch { }
}

#endregion

#region GUI

function Start-Gui {
    if ([Threading.Thread]::CurrentThread.GetApartmentState().ToString() -ne 'STA') {
        throw 'GUI mode requires STA. Start it with Launch-RedirectCraftPatcher.cmd.'
    }

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [Windows.Forms.Application]::EnableVisualStyles()

    $form = New-Object Windows.Forms.Form
    $form.Text = "$($script:ToolName) $($script:ToolVersion)"
    $form.StartPosition = 'CenterScreen'
    $form.Size = New-Object Drawing.Size(860, 640)
    $form.MinimumSize = New-Object Drawing.Size(770, 540)
    $form.AutoScaleMode = 'Dpi'
    $form.Font = New-Object Drawing.Font('Segoe UI', 9)

    $pathLabel = New-Object Windows.Forms.Label
    $pathLabel.Text = 'Launcher root:'
    $pathLabel.Location = New-Object Drawing.Point(14, 18)
    $pathLabel.AutoSize = $true

    $pathBox = New-Object Windows.Forms.TextBox
    $pathBox.Location = New-Object Drawing.Point(110, 14)
    $pathBox.Size = New-Object Drawing.Size(620, 24)
    $pathBox.Anchor = 'Top,Left,Right'

    $browseButton = New-Object Windows.Forms.Button
    $browseButton.Text = 'Browse...'
    $browseButton.Location = New-Object Drawing.Point(740, 12)
    $browseButton.Size = New-Object Drawing.Size(82, 28)
    $browseButton.Anchor = 'Top,Right'

    $analyzeButton = New-Object Windows.Forms.Button
    $analyzeButton.Text = 'Analyze'
    $analyzeButton.Location = New-Object Drawing.Point(14, 52)
    $analyzeButton.Size = New-Object Drawing.Size(100, 32)

    $patchButton = New-Object Windows.Forms.Button
    $patchButton.Text = 'Apply patch'
    $patchButton.Location = New-Object Drawing.Point(122, 52)
    $patchButton.Size = New-Object Drawing.Size(110, 32)
    $patchButton.Enabled = $false

    $restoreButton = New-Object Windows.Forms.Button
    $restoreButton.Text = 'Restore backup'
    $restoreButton.Location = New-Object Drawing.Point(240, 52)
    $restoreButton.Size = New-Object Drawing.Size(120, 32)

    $copyButton = New-Object Windows.Forms.Button
    $copyButton.Text = 'Copy report'
    $copyButton.Location = New-Object Drawing.Point(368, 52)
    $copyButton.Size = New-Object Drawing.Size(110, 32)

    $statusLabel = New-Object Windows.Forms.Label
    $statusLabel.Text = 'Select the Fufu Launcher root folder, then click Analyze.'
    $statusLabel.Location = New-Object Drawing.Point(14, 95)
    $statusLabel.Size = New-Object Drawing.Size(810, 22)
    $statusLabel.Anchor = 'Top,Left,Right'
    $statusLabel.Font = New-Object Drawing.Font('Segoe UI', 9, [Drawing.FontStyle]::Bold)

    $reportBox = New-Object Windows.Forms.RichTextBox
    $reportBox.Location = New-Object Drawing.Point(14, 120)
    $reportBox.Size = New-Object Drawing.Size(810, 450)
    $reportBox.Anchor = 'Top,Bottom,Left,Right'
    $reportBox.ReadOnly = $true
    $reportBox.WordWrap = $false
    $reportBox.Font = New-Object Drawing.Font('Consolas', 9)
    $reportBox.BackColor = [Drawing.Color]::White

    $form.Controls.AddRange(@($pathLabel, $pathBox, $browseButton, $analyzeButton,
        $patchButton, $restoreButton, $copyButton, $statusLabel, $reportBox))

    $script:GuiAnalysis = $null

    function Set-StatusColor {
        param([string]$State)
        switch ($State) {
            'Patchable'      { $statusLabel.ForeColor = 'Green' }
            'AlreadyPatched' { $statusLabel.ForeColor = 'Blue' }
            'Unsupported'    { $statusLabel.ForeColor = 'Red' }
            default          { $statusLabel.ForeColor = 'Red' }
        }
    }

    $analyzeAction = {
        try {
            $patchButton.Enabled = $false
            $statusLabel.Text = 'Analyzing...'
            $statusLabel.ForeColor = [Drawing.Color]::Black
            $form.Refresh()

            $launcherRoot = $pathBox.Text.Trim()
            if (-not (Test-Path -LiteralPath $launcherRoot -PathType Container)) {
                throw 'The selected launcher root folder does not exist or is not a directory.'
            }
            $dllPath = Join-Path $launcherRoot $script:PluginRelativePath
            if (-not (Test-Path -LiteralPath $dllPath -PathType Leaf)) {
                throw "Plugin DLL not found at expected location:`n$dllPath"
            }

            $script:GuiAnalysis = Get-RedirectCraftAnalysis $dllPath
            $reportBox.Text = Format-Analysis $script:GuiAnalysis
            $statusLabel.Text = "State: $($script:GuiAnalysis.State)"
            Set-StatusColor $script:GuiAnalysis.State
            $patchButton.Enabled = ($script:GuiAnalysis.State -eq 'Patchable')
            Write-ToolLog ("ANALYZE`r`n" + $reportBox.Text)
        }
        catch {
            $script:GuiAnalysis = $null
            $reportBox.Text = $_.Exception.Message
            $statusLabel.Text = 'State: Unsupported'
            $statusLabel.ForeColor = 'Red'
            Write-ToolLog ("ANALYZE ERROR: " + $_.Exception.Message)
        }
    }

    $browseButton.Add_Click({
        $dialog = New-Object Windows.Forms.FolderBrowserDialog
        $dialog.Description = 'Select the Fufu Launcher root folder'
        if (-not [string]::IsNullOrWhiteSpace($pathBox.Text) -and (Test-Path -LiteralPath $pathBox.Text -PathType Container)) {
            $dialog.SelectedPath = $pathBox.Text
        }
        if ($dialog.ShowDialog() -eq [Windows.Forms.DialogResult]::OK) {
            $pathBox.Text = $dialog.SelectedPath
            & $analyzeAction
        }
    })

    $analyzeButton.Add_Click($analyzeAction)

    $patchButton.Add_Click({
        try {
            if ($null -eq $script:GuiAnalysis -or $script:GuiAnalysis.State -ne 'Patchable') {
                throw 'Analyze a supported original DLL first.'
            }
            $answer = [Windows.Forms.MessageBox]::Show(
                "Close the game and launcher before continuing.`r`n`r`n" +
                'The tool will create a verified backup. Modifying the DLL invalidates its digital signature. Continue?',
                $script:ToolName,
                [Windows.Forms.MessageBoxButtons]::YesNo,
                [Windows.Forms.MessageBoxIcon]::Warning)
            if ($answer -ne [Windows.Forms.DialogResult]::Yes) { return }

            $patchButton.Enabled = $false
            $outcome = Invoke-RedirectCraftPatch $script:GuiAnalysis
            $reportBox.AppendText([Environment]::NewLine + [Environment]::NewLine +
                $outcome.Message + [Environment]::NewLine +
                "Backup:  $($outcome.BackupPath)" + [Environment]::NewLine +
                "Manifest: $($outcome.ManifestPath)" + [Environment]::NewLine +
                "Patched SHA-256: $($outcome.PatchedSha256)")
            Write-ToolLog ("PATCH OK: $($outcome.PatchedSha256); backup=$($outcome.BackupPath)")
            # 重新分析以更新状态
            $script:GuiAnalysis = Get-RedirectCraftAnalysis $script:GuiAnalysis.Path
            $statusLabel.Text = "State: $($script:GuiAnalysis.State)"
            Set-StatusColor $script:GuiAnalysis.State
            $patchButton.Enabled = ($script:GuiAnalysis.State -eq 'Patchable')
        }
        catch {
            $statusLabel.Text = 'State: Error'
            $statusLabel.ForeColor = 'Red'
            $reportBox.AppendText([Environment]::NewLine + [Environment]::NewLine + 'ERROR: ' + $_.Exception.Message)
            Write-ToolLog ("PATCH ERROR: " + $_.Exception.Message)
        }
    })

    $restoreButton.Add_Click({
        try {
            if ([string]::IsNullOrWhiteSpace($pathBox.Text)) {
                throw 'Select the currently patched DLL first.'
            }
            $launcherRoot = $pathBox.Text.Trim()
            $dllPath = Join-Path $launcherRoot $script:PluginRelativePath
            if (-not (Test-Path -LiteralPath $dllPath -PathType Leaf)) {
                throw "Plugin DLL not found at expected location:`n$dllPath"
            }

            $descriptor = $null
            try {
                $descriptor = Get-RestoreDescriptor $dllPath $null
            }
            catch {
                $dialog = New-Object Windows.Forms.OpenFileDialog
                $dialog.Filter = 'RedirectCraft manifest (*.redirectcraft.json)|*.redirectcraft.json|JSON files (*.json)|*.json'
                $dialog.InitialDirectory = Split-Path -Parent $dllPath
                if ($dialog.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) { return }
                $descriptor = Get-RestoreDescriptor $dllPath $dialog.FileName
            }

            $answer = [Windows.Forms.MessageBox]::Show(
                "Restore the verified original DLL from:`r`n$($descriptor.BackupPath)?",
                $script:ToolName,
                [Windows.Forms.MessageBoxButtons]::YesNo,
                [Windows.Forms.MessageBoxIcon]::Question)
            if ($answer -ne [Windows.Forms.DialogResult]::Yes) { return }

            $outcome = Invoke-RedirectCraftRestore $dllPath $descriptor
            $reportBox.Text = $outcome.Message + [Environment]::NewLine +
                "SHA-256: $($outcome.Sha256)" + [Environment]::NewLine +
                "Backup retained at: $($outcome.BackupPath)"
            # 重新分析恢复后的 DLL
            $script:GuiAnalysis = Get-RedirectCraftAnalysis $dllPath
            $statusLabel.Text = "State: $($script:GuiAnalysis.State)"
            Set-StatusColor $script:GuiAnalysis.State
            $patchButton.Enabled = ($script:GuiAnalysis.State -eq 'Patchable')
            Write-ToolLog ("RESTORE OK: $($outcome.Sha256)")
        }
        catch {
            $statusLabel.Text = 'State: Error'
            $statusLabel.ForeColor = 'Red'
            $reportBox.AppendText([Environment]::NewLine + [Environment]::NewLine + 'ERROR: ' + $_.Exception.Message)
            Write-ToolLog ("RESTORE ERROR: " + $_.Exception.Message)
        }
    })

    $copyButton.Add_Click({
        if (-not [string]::IsNullOrWhiteSpace($reportBox.Text)) {
            [Windows.Forms.Clipboard]::SetText($reportBox.Text)
            $statusLabel.Text = 'Report copied to the clipboard.'
            $statusLabel.ForeColor = [Drawing.Color]::Black
        }
    })

    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        $pathBox.Text = $Path
    }
    else {
        $guessedRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { $null }
        if ($guessedRoot -and (Test-Path (Join-Path $guessedRoot $script:PluginRelativePath))) {
            $pathBox.Text = $guessedRoot
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($pathBox.Text)) {
        & $analyzeAction
    }

    [void]$form.ShowDialog()
}

#endregion

#region 入口点

try {
    switch ($Action) {
        'Gui' {
            Start-Gui
        }
        'Analyze' {
            if ([string]::IsNullOrWhiteSpace($Path)) { throw '-Path is required (launcher root folder).' }
            $dllPath = Join-Path $Path $script:PluginRelativePath
            if (-not (Test-Path $dllPath)) { throw "Plugin DLL not found: $dllPath" }
            $analysis = Get-RedirectCraftAnalysis $dllPath
            Format-Analysis $analysis
            if ($analysis.State -eq 'Unsupported') { exit 2 }
        }
        'Patch' {
            if ([string]::IsNullOrWhiteSpace($Path)) { throw '-Path is required (launcher root folder).' }
            $dllPath = Join-Path $Path $script:PluginRelativePath
            if (-not (Test-Path $dllPath)) { throw "Plugin DLL not found: $dllPath" }
            $analysis = Get-RedirectCraftAnalysis $dllPath
            Format-Analysis $analysis
            $outcome = Invoke-RedirectCraftPatch $analysis
            $outcome | Format-List | Out-String
        }
        'Restore' {
            if ([string]::IsNullOrWhiteSpace($Path)) { throw '-Path is required (launcher root folder).' }
            $dllPath = Join-Path $Path $script:PluginRelativePath
            if (-not (Test-Path $dllPath)) { throw "Plugin DLL not found: $dllPath" }
            $descriptor = Get-RestoreDescriptor $dllPath $ManifestPath
            $outcome = Invoke-RedirectCraftRestore $dllPath $descriptor
            $outcome | Format-List | Out-String
        }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}

#endregion