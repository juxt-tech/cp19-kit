# Pure text helpers for secedit .inf files + thin export/import wrappers.
# secedit /export gives the local security policy as an INI-like file; we edit the text and
# re-import it with secedit /configure. This is how Local Security Policy settings are scripted.

function Get-CpInfValue {
    param([Parameter(Mandatory)][string]$InfText, [Parameter(Mandatory)][string]$Section, [Parameter(Mandatory)][string]$Key)
    $in = $false
    foreach ($line in ($InfText -split "`r?`n")) {
        if ($line -match '^\s*\[(.+)\]\s*$') { $in = ($Matches[1] -eq $Section); continue }
        if ($in -and $line -match '^\s*(.+?)\s*=\s*(.*?)\s*$' -and $Matches[1] -ieq $Key) { return $Matches[2] }
    }
    return $null
}

function Set-CpInfValue {
    param([Parameter(Mandatory)][string]$InfText, [Parameter(Mandatory)][string]$Section,
          [Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][string]$Value)
    $nl    = if ($InfText -match "`r`n") { "`r`n" } else { "`n" }
    $lines = [System.Collections.Generic.List[string]]($InfText -split "`r?`n")
    $sep   = if ($Section -eq 'Registry Values') { '=' } else { ' = ' }
    $in = $false; $secStart = -1; $secEnd = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -match '^\s*\[(.+)\]\s*$') {
            if ($in) { $secEnd = $i; $in = $false }
            if ($Matches[1] -eq $Section) { $in = $true; $secStart = $i }
            continue
        }
        if ($in -and $line -match '^(\s*)(.+?)(\s*=\s*)(.*?)\s*$' -and $Matches[2] -ieq $Key) {
            $lines[$i] = $Matches[1] + $Matches[2] + $Matches[3] + $Value      # keep original spacing
            return ($lines -join $nl)
        }
    }
    if ($in) { $secEnd = $lines.Count }
    if ($secStart -ge 0) {
        $ins = $secEnd
        while ($ins -gt $secStart + 1 -and $lines[$ins - 1] -eq '') { $ins-- }
        $lines.Insert($ins, "$Key$sep$Value")
    } else {
        $ver = -1
        for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^\s*\[Version\]') { $ver = $i; break } }
        if ($ver -lt 0) { $ver = $lines.Count }
        $lines.Insert($ver, "$Key$sep$Value")
        $lines.Insert($ver, "[$Section]")
    }
    return ($lines -join $nl)
}

function Export-CpSecPolicy {
    $f = Join-Path $env:TEMP ('cpkit-export-' + [guid]::NewGuid().ToString('N') + '.inf')
    & secedit.exe /export /cfg $f /quiet | Out-Null
    $t = Get-Content $f -Raw -Encoding Unicode
    Remove-Item $f -ErrorAction SilentlyContinue
    return $t
}

function Import-CpSecPolicy {
    param([Parameter(Mandatory)][string]$InfText, [string]$Areas = 'SECURITYPOLICY')
    $f  = Join-Path $env:TEMP ('cpkit-import-' + [guid]::NewGuid().ToString('N') + '.inf')
    $db = Join-Path $env:TEMP ('cpkit-' + [guid]::NewGuid().ToString('N') + '.sdb')
    Set-Content -Path $f -Value $InfText -Encoding Unicode
    $out = & secedit.exe /configure /db $db /cfg $f /areas $Areas /quiet 2>&1
    $code = $LASTEXITCODE
    Remove-Item $f, $db -ErrorAction SilentlyContinue
    if ($code -ne 0) { throw "secedit /configure failed ($code): $out" }
    & gpupdate.exe /target:computer /force 2>&1 | Out-Null
}

Export-ModuleMember -Function Get-CpInfValue, Set-CpInfValue, Export-CpSecPolicy, Import-CpSecPolicy
