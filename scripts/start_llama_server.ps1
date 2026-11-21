<#
.SYNOPSIS
    Start, check, or stop the local llama-server sidecar for AGY Guardian.

.DESCRIPTION
    Loads machine-local settings from .env (CLI params > OS env vars > .env > defaults),
    launches llama-server with required Decision Model flags (--ctx-size 2048 -b 2048 -ub 2048 -np 1),
    and waits for /health readiness. Idempotent when already running.

.EXAMPLE
    .\scripts\start_llama_server.ps1 -Background
    .\scripts\start_llama_server.ps1 -Status
    .\scripts\start_llama_server.ps1 -Stop
#>
[CmdletBinding()]
param(
    [switch]$Background,
    [switch]$Foreground,
    [switch]$Status,
    [switch]$Stop,
    [ValidateSet("systemone", "completion")]
    [string]$Backend = "",
    [string]$ModelPath = "",
    [string]$LlamaServer = "",
    [string]$BindHost = "",
    [int]$Port = 0,
    [int]$GpuLayers = -1,
    [int]$WaitSeconds = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$LocalDir = Join-Path $RepoRoot ".local"
$PidFile = Join-Path $LocalDir "llama-server.pid"
$LogFile = Join-Path $LocalDir "llama-server.log"
$EnvFile = Join-Path $RepoRoot ".env"

function Import-DotEnvFile {
    param([string]$Path)
    $map = @{}
    if (-not (Test-Path -LiteralPath $Path)) {
        return $map
    }
    foreach ($rawLine in (Get-Content -LiteralPath $Path -Encoding UTF8)) {
        $line = $rawLine.Trim()
        if (-not $line -or $line.StartsWith("#") -or ($line.IndexOf("=") -lt 1)) {
            continue
        }
        if ($line.StartsWith("export ")) {
            $line = $line.Substring(7).Trim()
        }
        $idx = $line.IndexOf("=")
        $key = $line.Substring(0, $idx).Trim()
        $val = $line.Substring($idx + 1).Trim()
        if ($val.Length -ge 2 -and (($val.StartsWith('"') -and $val.EndsWith('"')) -or ($val.StartsWith("'") -and $val.EndsWith("'")))) {
            $val = $val.Substring(1, $val.Length - 2)
        }
        if ($key) {
            $map[$key] = $val
        }
    }
    return $map
}

$DotEnv = Import-DotEnvFile -Path $EnvFile

function Get-Setting {
    param(
        [string]$ParamVal,
        [string]$EnvKey,
        [string]$DefaultVal = ""
    )
    if ($ParamVal) { return $ParamVal }
    $osVal = [Environment]::GetEnvironmentVariable($EnvKey)
    if ($osVal) { return $osVal }
    if ($DotEnv.ContainsKey($EnvKey) -and $DotEnv[$EnvKey]) { return $DotEnv[$EnvKey] }
    return $DefaultVal
}

function Expand-TemplatePath {
    param([string]$RawPath)
    if (-not $RawPath) { return "" }
    $expanded = [regex]::Replace($RawPath, '\$\{([A-Za-z_][A-Za-z0-9_]*)\}', {
        param($m)
        $k = $m.Groups[1].Value
        $v = [Environment]::GetEnvironmentVariable($k)
        if (-not $v -and $DotEnv.ContainsKey($k)) { $v = $DotEnv[$k] }
        if ($v) { return $v }
        return $m.Value
    })
    $expanded = [Environment]::ExpandEnvironmentVariables($expanded)
    if ($expanded.StartsWith("~")) {
        $expanded = Join-Path $env:USERPROFILE $expanded.Substring(1).TrimStart("\", "/")
    }
    return $expanded
}

function Test-ServerHealth {
    param([string]$Endpoint)
    try {
        $resp = Invoke-WebRequest -Uri "$Endpoint/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
        return ($resp.StatusCode -eq 200)
    } catch {
        return $false
    }
}

$EffectiveHost = Get-Setting -ParamVal $BindHost -EnvKey "AGY_GUARDIAN_HOST" -DefaultVal "127.0.0.1"
$PortStr = if ($Port -gt 0) { "$Port" } else { Get-Setting -ParamVal "" -EnvKey "AGY_GUARDIAN_PORT" -DefaultVal "8099" }
$EffectivePort = [int]$PortStr
$Endpoint = "http://${EffectiveHost}:${EffectivePort}"

if ($Status) {
    $healthy = Test-ServerHealth -Endpoint $Endpoint
    $pidInfo = "none"
    if (Test-Path -LiteralPath $PidFile) {
        $savedPid = (Get-Content -LiteralPath $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($savedPid -and (Get-Process -Id ([int]$savedPid) -ErrorAction SilentlyContinue)) {
            $pidInfo = "PID $savedPid (running)"
        } elseif ($savedPid) {
            $pidInfo = "PID $savedPid (stale)"
        }
    }
    if ($healthy) {
        Write-Host "[OK] llama-server is healthy at $Endpoint ($pidInfo)"
        exit 0
    } else {
        Write-Host "[DOWN] llama-server is not responding at $Endpoint ($pidInfo)"
        exit 1
    }
}

if ($Stop) {
    if (-not (Test-Path -LiteralPath $PidFile)) {
        Write-Host "No PID file found at $PidFile."
        exit 0
    }
    $savedPid = (Get-Content -LiteralPath $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($savedPid) {
        $proc = Get-Process -Id ([int]$savedPid) -ErrorAction SilentlyContinue
        if ($proc) {
            Stop-Process -Id $proc.Id -Force
            Write-Host "Stopped llama-server (PID $($proc.Id))."
        } else {
            Write-Host "Process $savedPid is not running."
        }
    }
    Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
    exit 0
}

# Idempotency check before starting
if (Test-ServerHealth -Endpoint $Endpoint) {
    Write-Host "[OK] llama-server is already running and healthy at $Endpoint."
    exit 0
}

$EffectiveBackend = Get-Setting -ParamVal $Backend -EnvKey "AGY_GUARDIAN_BACKEND" -DefaultVal "systemone"
if ($EffectiveBackend -eq "auto") { $EffectiveBackend = "systemone" }

$RawServer = Get-Setting -ParamVal $LlamaServer -EnvKey "AGY_GUARDIAN_LLAMA_SERVER" -DefaultVal ""
$ServerExe = if ($RawServer) { Expand-TemplatePath $RawServer } else {
    $cmd = Get-Command "llama-server" -ErrorAction SilentlyContinue
    if ($cmd) { $cmd.Source } else { "" }
}
if (-not $ServerExe -or -not (Test-Path -LiteralPath $ServerExe)) {
    Write-Error "Could not locate llama-server. Set AGY_GUARDIAN_LLAMA_SERVER in .env or add llama-server to PATH."
    exit 2
}

$DefaultModelTemplate = '${AGY_GUARDIAN_DECISION_MODELS_DIR}/Cloudflare_clef-flash-Q5_K_M.gguf'
$RawModel = Get-Setting -ParamVal $ModelPath -EnvKey "AGY_GUARDIAN_MODEL_PATH" -DefaultVal $DefaultModelTemplate
$ResolvedModel = Expand-TemplatePath $RawModel
if (-not $ResolvedModel -or -not (Test-Path -LiteralPath $ResolvedModel)) {
    Write-Error "Model file not found: $ResolvedModel. Configure AGY_GUARDIAN_MODEL_PATH or AGY_GUARDIAN_DECISION_MODELS_DIR in .env."
    exit 2
}

$GpuLayersStr = if ($GpuLayers -ge 0) { "$GpuLayers" } else { Get-Setting -ParamVal "" -EnvKey "AGY_GUARDIAN_GPU_LAYERS" -DefaultVal "99" }
$EffectiveGpuLayers = [int]$GpuLayersStr

$ArgsList = @(
    "-m", $ResolvedModel,
    "--host", $EffectiveHost,
    "--port", "$EffectivePort",
    "-ngl", "$EffectiveGpuLayers",
    "--ctx-size", "2048",
    "-np", "1"
)
if ($EffectiveBackend -eq "systemone") {
    # Decision Models run in embedding mode: n_batch and n_ubatch must match ctx-size to avoid HTTP 500
    $ArgsList += @("-b", "2048", "-ub", "2048")
}

if (-not (Test-Path -LiteralPath $LocalDir)) {
    New-Item -ItemType Directory -Path $LocalDir -Force | Out-Null
}

if ($Foreground -and -not $Background) {
    Write-Host "Starting llama-server in foreground at $Endpoint (backend=$EffectiveBackend)..."
    & $ServerExe @ArgsList
    exit $LASTEXITCODE
}

$ErrLogFile = Join-Path $LocalDir "llama-server.err.log"
Write-Host "Starting llama-server in background at $Endpoint (backend=$EffectiveBackend)..."
$proc = Start-Process -FilePath $ServerExe `
    -ArgumentList $ArgsList `
    -WindowStyle Hidden `
    -RedirectStandardOutput $LogFile `
    -RedirectStandardError $ErrLogFile `
    -PassThru

Set-Content -LiteralPath $PidFile -Value $proc.Id -Encoding ASCII

$deadline = (Get-Date).AddSeconds($WaitSeconds)
while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) {
        Write-Error "llama-server exited prematurely (code $($proc.ExitCode)). Check $LogFile and $ErrLogFile."
        exit 1
    }
    if (Test-ServerHealth -Endpoint $Endpoint) {
        Write-Host "[OK] llama-server ready at $Endpoint (PID $($proc.Id), logs: $LogFile)"
        exit 0
    }
    Start-Sleep -Milliseconds 500
}

Write-Error "Timed out waiting for $Endpoint/health after ${WaitSeconds}s (PID $($proc.Id)). Check $LogFile and $ErrLogFile."
exit 1
