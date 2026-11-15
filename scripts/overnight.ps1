# Overnight chain: local batches, then hosted batches, one at a time (one listener).
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File scripts\overnight.ps1
# Console output of each batch goes to results\_console\<batch_id>.log; the chain's own
# progress goes to results\_console\overnight-chain.log. Keys are read from the Windows
# user environment into this process and are never printed.

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

function Run-Batch([string]$batchId, [string]$flags) {
    $log = Join-Path $console "$batchId.log"
    Note "START $batchId : run_eval.py $flags --batch-id $batchId"
    cmd /c "`"$py`" run_eval.py $flags --batch-id $batchId > `"$log`" 2>&1"
    $code = $LASTEXITCODE
    Note "END   $batchId exit=$code"
    return $code
}

Note "chain started at commit $(git rev-parse --short HEAD)"

$local = @(
    @('night-llama31-3temps',    'llama3.1:latest'),
    @('night-gemma2-3temps',     'gemma2:9b-instruct-q4_K_M'),
    @('night-phi4mini-3temps',   'phi4-mini:latest'),
    @('night-ministral3-3temps', 'ministral-3:8b'),
    @('night-llama32-3temps',    'llama3.2:3b')
)
foreach ($b in $local) {
    $freeKb = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory
    if ($freeKb -lt $minFreeKb) {
        Note "MEMORY free=$([math]::Round($freeKb / 1MB, 1)) GB is under 8 GB: $($b[0]) and the remaining local batches are not started"
        break
    }
    Run-Batch $b[0] "--models $($b[1])" | Out-Null
}

foreach ($name in 'ANTHROPIC_API_KEY', 'GROQ_API_KEY') {
    $value = [Environment]::GetEnvironmentVariable($name, 'User')
    if ($value) { Set-Item -Path "Env:$name" -Value $value } else { Note "KEY $name is not set in the user environment" }
}

$hosted = @(
    @('night-haiku45-3temps',      '--models anthropic/claude-haiku-4-5'),
    @('night-haiku55',             '--models anthropic/claude-haiku-5-5'),
    @('night-sonnet55',            '--models anthropic/claude-sonnet-5-5'),
    @('night-opus55',              '--models anthropic/claude-opus-5-5'),
    @('night-groq-gptoss120b-t03', '--models groq/openai/gpt-oss-120b --temperatures 0.3')
)
$failedInARow = 0
foreach ($b in $hosted) {
    if ($failedInARow -ge 2) {
        Note "HOSTED stopped: two hosted batches in a row ended with a non-zero exit; $($b[0]) not started"
        continue
    }
    $code = Run-Batch $b[0] $b[1]
    if ($code -ne 0) { $failedInARow++ } else { $failedInARow = 0 }
}
Note 'chain finished'
