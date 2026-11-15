# The four local batches the first chain skipped. Same batches and flags as overnight.ps1.
# Before each batch: wait (up to 6 minutes) for Ollama to unload the previous model, then
# require 8 GB of free physical memory. The first chain checked while the previous model
# was still loaded, which is why it skipped these.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File scripts\overnight_local_rest.ps1

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$console = Join-Path $root 'results\_console'
New-Item -ItemType Directory -Force $console | Out-Null
$chainLog = Join-Path $console 'overnight-chain.log'
$py = Join-Path $root '.venv\Scripts\python.exe'
$minFreeKb = 8GB / 1KB

function Note([string]$text) {
    "$((Get-Date).ToUniversalTime().ToString('s'))Z  $text" | Out-File -FilePath $chainLog -Append -Encoding utf8
}

function Wait-OllamaIdle {
    for ($i = 0; $i -lt 36; $i++) {
        try {
            $ps = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/ps' -TimeoutSec 5
            if (-not $ps.models -or $ps.models.Count -eq 0) { return $true }
        } catch {
            Note "OLLAMA /api/ps failed: $($_.Exception.Message)"
        }
        Start-Sleep -Seconds 10
    }
    return $false
}

Note "second local chain started at commit $(git rev-parse --short HEAD)"
$local = @(
    @('night-gemma2-3temps',     'gemma2:9b-instruct-q4_K_M'),
    @('night-phi4mini-3temps',   'phi4-mini:latest'),
    @('night-ministral3-3temps', 'ministral-3:8b'),
    @('night-llama32-3temps',    'llama3.2:3b')
)
foreach ($b in $local) {
    if (-not (Wait-OllamaIdle)) { Note "OLLAMA still has a model loaded after 6 minutes; checking memory anyway" }
    $freeKb = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory
    if ($freeKb -lt $minFreeKb) {
        Note "MEMORY free=$([math]::Round($freeKb / 1MB, 1)) GB is under 8 GB with Ollama idle: $($b[0]) and the remaining local batches are not started"
        break
    }
    $log = Join-Path $console "$($b[0]).log"
    Note "START $($b[0]) : run_eval.py --models $($b[1]) --batch-id $($b[0]) (free=$([math]::Round($freeKb / 1MB, 1)) GB)"
    cmd /c "`"$py`" run_eval.py --models $($b[1]) --batch-id $($b[0]) > `"$log`" 2>&1"
    Note "END   $($b[0]) exit=$LASTEXITCODE"
}
Note 'second local chain finished'
