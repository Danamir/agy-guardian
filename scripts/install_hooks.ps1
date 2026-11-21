<#
.SYNOPSIS
    Safely install or uninstall the agy-guardian PreToolUse hook in %USERPROFILE%\.gemini\config\hooks.json.

.DESCRIPTION
    Merges the "agy-guardian" hook entry into %USERPROFILE%\.gemini\config\hooks.json without
    clobbering other hooks. Uses %USERPROFILE% relative paths when the repo is inside the user profile.

.EXAMPLE
    .\scripts\install_hooks.ps1
    .\scripts\install_hooks.ps1 -Disabled
    .\scripts\install_hooks.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [switch]$Disabled,
    [switch]$Uninstall,
    [string]$HooksPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$HookScript = Join-Path $RepoRoot "scripts\agy_guardian_hook.py"
if (-not $HooksPath) {
    $HooksPath = Join-Path $env:USERPROFILE ".gemini\config\hooks.json"
}

$ConfigDir = Split-Path -Parent $HooksPath
if (-not (Test-Path -LiteralPath $ConfigDir)) {
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
}

# Load existing hooks.json as an ordered dictionary if present
$RootObj = [ordered]@{}
if (Test-Path -LiteralPath $HooksPath) {
    $raw = Get-Content -LiteralPath $HooksPath -Raw -Encoding UTF8
    if ($raw.Trim()) {
        $parsed = $raw | ConvertFrom-Json
        foreach ($prop in $parsed.PSObject.Properties) {
            $RootObj[$prop.Name] = $prop.Value
        }
    }
}

if ($Uninstall) {
    if ($RootObj.Contains("agy-guardian")) {
        $RootObj.Remove("agy-guardian")
        $RootObj | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $HooksPath -Encoding UTF8
        Write-Host "Removed 'agy-guardian' from $HooksPath."
    } else {
        Write-Host "'agy-guardian' not present in $HooksPath."
    }
    exit 0
}

# Build portable command path using %USERPROFILE% when repo is under user home
$UserProfileNorm = $env:USERPROFILE.TrimEnd("\")
if ($HookScript.StartsWith($UserProfileNorm + "\", [System.StringComparison]::OrdinalIgnoreCase)) {
    $Relative = $HookScript.Substring($UserProfileNorm.Length)
    $CommandPath = "%USERPROFILE%$Relative"
} else {
    $CommandPath = $HookScript
}

$HookEntry = [ordered]@{}
if ($Disabled) {
    $HookEntry["enabled"] = $false
}
$HookEntry["PreToolUse"] = @(
    [ordered]@{
        matcher = "run_command"
        hooks   = @(
            [ordered]@{
                type    = "command"
                command = "python `"$CommandPath`""
                timeout = 10
            }
        )
    }
)

$RootObj["agy-guardian"] = $HookEntry
$RootObj | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $HooksPath -Encoding UTF8
$state = if ($Disabled) { "disabled" } else { "enabled" }
Write-Host "Installed 'agy-guardian' ($state) into $HooksPath -> python `"$CommandPath`""
