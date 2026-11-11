# Linux practice-VM batch: apply each kit module as its own job, health + score after each,
# then a second apply-all (must log 0 ACTION lines). Output: %USERPROFILE%\cpvmtest\batch-<Tag>.txt
#
#   .\tools\vmtest\linux-batch.ps1 -Vm debian -Config eth007-deb11-config.txt -Pw 'NEW_PASSWORD' -Tag run1
#
# Needs: server running, kit staged (vmt.ps1 stage-kit), config staged
# (vmt.ps1 stage -Path ...\cp-config.txt). health.sh is served from guest/ at /g/health.sh.
# Revert the VM to its agent snapshot first for a clean run (vmrun stop hard -> revertToSnapshot ->
# wait for vmware.exe to exit -> Start-Process vmrun start). Wait ~2 scorer passes after boot: the
# first pass can report a critical service as stopped before it has started.
param(
    [string]$Vm = 'debian',
    [Parameter(Mandatory)][string]$Config,
    [string]$Pw = '',
    [string]$Tag = 'batch',
    [string[]]$Modules = @('users','sources','integrity','passwords','firewall','ssh','apps','sysctl','perms','services','software','updates','persistence','media'),
    [switch]$FullUpgrade
)
Set-Location (Resolve-Path "$PSScriptRoot\..\..")
$out = Join-Path $env:USERPROFILE "cpvmtest\batch-$Tag.txt"
"batch $Tag start $(Get-Date -Format HH:mm:ss)" | Out-File -Encoding utf8 $out
$skip = if ($FullUpgrade) { '' } else { 'export CP_SKIP_UPGRADE=1; ' }
$pre = 'source <(curl -s "$CP_SERVER/g/cpk.sh"); . <(curl -s "$CP_SERVER/g/health.sh"); ' + $skip
$first = $true
foreach ($m in $Modules) {
    $inst = if ($first) { "install_kit $Config; " } else { '' }
    $first = $false
    $code = $pre + $inst + "run_kit $Tag-$m --apply --yes --module $m; health '$Pw'; score 150"
    "`n################ $m  $(Get-Date -Format HH:mm:ss)" | Out-File -Append -Encoding utf8 $out
    & "$PSScriptRoot\vmt.ps1" run -Vm $Vm -Code $code -Timeout 1800 -Wait 1800 2>&1 | Out-File -Append -Encoding utf8 $out
}
"`n################ second-apply-all  $(Get-Date -Format HH:mm:ss)" | Out-File -Append -Encoding utf8 $out
$code = $pre + "run_kit $Tag-again --apply --yes --all >/dev/null 2>&1; r=`$(ls -1d /root/cpkit-runs/* | tail -1); echo ""ACTION lines in 2nd apply: `$(grep -c ' | ACTION | ' `$r/log.txt)""; grep ' | ACTION | ' `$r/log.txt"
& "$PSScriptRoot\vmt.ps1" run -Vm $Vm -Code $code -Timeout 1800 -Wait 1800 2>&1 | Out-File -Append -Encoding utf8 $out
"`nbatch $Tag end $(Get-Date -Format HH:mm:ss)" | Out-File -Append -Encoding utf8 $out
Write-Host "done: $out"
