<#
.SYNOPSIS
    Configures project-level pipeline security settings in Azure DevOps.

.DESCRIPTION
    Applies the recommended pipeline security hardening settings at the project level:

    - Protect access to repositories in YAML pipelines
      Prevents a malicious PR from exfiltrating secrets by restricting repository
      access to pipelines that have been explicitly authorised. Without this, any
      pipeline in the project can read any repository it can see — including cloning
      repos that contain secrets embedded in code.

    - Limit job authorisation scope to current project
      Prevents pipelines from accessing resources (repos, feeds, service connections)
      in other projects within the same organisation. Reduces lateral movement risk
      if a pipeline is compromised — an attacker cannot pivot to other projects.

    - Limit job authorisation scope for release pipelines
      Same restriction applied to classic release pipelines. Ensures release jobs
      cannot reach across project boundaries.

    - Private status badge URLs
      Prevents anonymous users from querying pipeline status via badge URLs, which
      can leak information about build frequency, branch names, and failure patterns.

    Also reports the current state of all settings before applying changes,
    so you can see what is and isn't already hardened.

.PARAMETER Organization
    Azure DevOps organization name (e.g. "myorg" from dev.azure.com/myorg)

.PARAMETER Project
    Azure DevOps project name

.PARAMETER ReportOnly
    Report current setting state without making any changes.

.PARAMETER Force
    Skips confirmation prompts

.EXAMPLE
    # Step 1 — check what is already hardened before making changes
    .\Set-AzureDevOpsPipelineSecurity.ps1 `
        -Organization "myorg" `
        -Project "MyProject" `
        -ReportOnly

.EXAMPLE
    # Step 2 — Best practice: apply all recommended settings
    # isJobAuthorizationEnabled           : pipelines can only access resources in their own project
    # isJobAuthorizationForReleaseEnabled : same restriction applied to classic release pipelines
    # enforceSettableVar (repo protection): YAML pipelines can only access explicitly authorised repos
    # statusBadgesArePrivate              : pipeline status cannot be queried anonymously
    .\Set-AzureDevOpsPipelineSecurity.ps1 `
        -Organization "myorg" `
        -Project "MyProject" `
        -Force

.NOTES
    Author: Andrew Wood
    Version: 1.0

    Prerequisites:
    - Azure DevOps login: Connect-AzAccount, AZURE_DEVOPS_EXT_PAT, or az devops login
    - Permissions: Project Administrator

    Recommended hardening order:
    1. Set-AzureDevOpsBranchPolicies.ps1         — protect main branch
    2. Get-AzureDevOpsAdminAudit.ps1             — identify over-privileged accounts
    3. Set-AzureDevOpsServiceConnectionSecurity.ps1 — lock service connections
    4. Set-AzureDevOpsPipelineSecurity.ps1       — this script

    API References:
    - Build General Settings: https://learn.microsoft.com/en-us/rest/api/azure/devops/build/general-settings

.LINK
    https://learn.microsoft.com/en-us/azure/devops/pipelines/security/misc
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string]$Organization,

    [Parameter(Mandatory = $true)]
    [string]$Project,

    [Parameter(Mandatory = $false)]
    [switch]$ReportOnly,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "=== Azure DevOps Pipeline Security Settings ===" -ForegroundColor Cyan
Write-Host ""

. "$PSScriptRoot\_Helpers.ps1"

function Write-SettingStatus {
    param(
        [string]$Label,
        [bool]$CurrentValue,
        [bool]$TargetValue,
        [bool]$ReportOnly
    )
    $currentText  = if ($CurrentValue) { "ON" } else { "OFF" }
    $targetText   = if ($TargetValue)  { "ON" } else { "OFF" }
    $statusColor  = if ($CurrentValue -eq $TargetValue) { "Green" } else { "Yellow" }
    $changeMarker = if (-not $ReportOnly -and $CurrentValue -ne $TargetValue) { " → will set to $targetText" } else { "" }

    Write-Host "  $Label" -ForegroundColor White
    Write-Host "    Current: $currentText$changeMarker" -ForegroundColor $statusColor
}

#endregion

# Confirm
if (-not $ReportOnly -and -not $Force -and -not $WhatIfPreference) {
    Write-Host "`n⚠️  This will update pipeline security settings:" -ForegroundColor Yellow
    Write-Host "   - Organization: $Organization" -ForegroundColor Gray
    Write-Host "   - Project:      $Project" -ForegroundColor Gray
    $confirmation = Read-Host "`nContinue? (yes/no)"
    if ($confirmation -ne "yes") {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        exit 0
    }
}

# Authenticate
Write-Host "[1/3] Authenticating to Azure DevOps..." -ForegroundColor Yellow
try {
    $authHeader = Get-AzureDevOpsAuthHeader
    Write-Host "✓ Successfully authenticated" -ForegroundColor Green
}
catch {
    Write-Error "Failed to authenticate: $_"
    exit 1
}

# Read current settings
Write-Host "`n[2/3] Reading current pipeline security settings..." -ForegroundColor Yellow
$settingsUrl = "https://dev.azure.com/$Organization/$Project/_apis/build/generalsettings?api-version=7.1-preview.1"
try {
    $currentSettings = Invoke-AzureDevOpsApi -Uri $settingsUrl -AuthHeader $authHeader
    Write-Host "✓ Current settings retrieved" -ForegroundColor Green
}
catch {
    Write-Error "Failed to read pipeline settings: $_"
    exit 1
}

Write-Host ""
Write-Verbose "Raw API response: $($currentSettings | ConvertTo-Json -Depth 3)"
Write-Host "Current state:" -ForegroundColor Cyan

# Map API field names to human-readable labels and desired values
# enforceJobAuthScope              = Limit job authorization scope to current project (non-release)
# enforceJobAuthScopeForReleases   = Limit job authorization scope to current project (release)
# enforceReferencedRepoScopedToken = Protect access to repositories in YAML pipelines
# statusBadgesArePrivate           = Disable anonymous access to badge status URLs
# enforceSettableVar                    = Limit variables that can be set at queue time
# disableClassicBuildPipelineCreation   = Disable creation of classic build pipelines
# disableClassicReleasePipelineCreation = Disable creation of classic release pipelines
# enableShellTasksArgsSanitizing        = Enable shell tasks arguments validation

Write-SettingStatus `
    -Label "Limit job authorisation scope — non-release pipelines" `
    -CurrentValue ($currentSettings.enforceJobAuthScope -eq $true) `
    -TargetValue $true `
    -ReportOnly $ReportOnly.IsPresent

Write-SettingStatus `
    -Label "Limit job authorisation scope — release pipelines" `
    -CurrentValue ($currentSettings.enforceJobAuthScopeForReleases -eq $true) `
    -TargetValue $true `
    -ReportOnly $ReportOnly.IsPresent

Write-SettingStatus `
    -Label "Protect access to repositories in YAML pipelines" `
    -CurrentValue ($currentSettings.enforceReferencedRepoScopedToken -eq $true) `
    -TargetValue $true `
    -ReportOnly $ReportOnly.IsPresent

Write-SettingStatus `
    -Label "Status badge URLs are private (not anonymous)" `
    -CurrentValue ($currentSettings.statusBadgesArePrivate -eq $true) `
    -TargetValue $true `
    -ReportOnly $ReportOnly.IsPresent

Write-SettingStatus `
    -Label "Limit variables settable at queue time" `
    -CurrentValue ($currentSettings.enforceSettableVar -eq $true) `
    -TargetValue $true `
    -ReportOnly $ReportOnly.IsPresent

Write-SettingStatus `
    -Label "Disable creation of classic build pipelines" `
    -CurrentValue ($currentSettings.disableClassicBuildPipelineCreation -eq $true) `
    -TargetValue $true `
    -ReportOnly $ReportOnly.IsPresent

Write-SettingStatus `
    -Label "Disable creation of classic release pipelines" `
    -CurrentValue ($currentSettings.disableClassicReleasePipelineCreation -eq $true) `
    -TargetValue $true `
    -ReportOnly $ReportOnly.IsPresent

Write-SettingStatus `
    -Label "Shell tasks arguments validation" `
    -CurrentValue ($currentSettings.enableShellTasksArgsSanitizing -eq $true) `
    -TargetValue $true `
    -ReportOnly $ReportOnly.IsPresent

Write-Host ""

if ($ReportOnly) {
    Write-Host "Report mode — no changes applied." -ForegroundColor Yellow
    Write-Host "Re-run without -ReportOnly to apply the recommended settings." -ForegroundColor Yellow
    Write-Host ""
    exit 0
}

# Apply settings
Write-Host "[3/3] Applying pipeline security settings..." -ForegroundColor Yellow

$updatedSettings = @{
    enforceJobAuthScope              = $true   # Limit scope to current project (non-release)
    enforceJobAuthScopeForReleases   = $true   # Limit scope to current project (release)
    enforceReferencedRepoScopedToken = $true   # Protect repo access in YAML pipelines
    statusBadgesArePrivate           = $true   # Private status badges
    enforceSettableVar               = $true   # Limit variables settable at queue time
    disableClassicBuildPipelineCreation   = $true   # Disable classic build pipeline creation
    disableClassicReleasePipelineCreation = $true   # Disable classic release pipeline creation
    enableShellTasksArgsSanitizing   = $true   # Shell tasks arguments validation
}

try {
    if ($PSCmdlet.ShouldProcess("$Organization/$Project", "Apply pipeline security settings")) {
        Invoke-AzureDevOpsApi -Uri $settingsUrl -Method Patch -Body $updatedSettings -AuthHeader $authHeader | Out-Null
        Write-Host "✓ Pipeline security settings applied" -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to apply settings: $_"
    exit 1
}

# Re-read and confirm
try {
    $confirmedSettings = Invoke-AzureDevOpsApi -Uri $settingsUrl -AuthHeader $authHeader
    Write-Host ""
    Write-Host "Confirmed applied state:" -ForegroundColor Cyan
    Write-Host "  Limit job scope (non-release): $($confirmedSettings.enforceJobAuthScope)" -ForegroundColor White
    Write-Host "  Limit job scope (release):     $($confirmedSettings.enforceJobAuthScopeForReleases)" -ForegroundColor White
    Write-Host "  Protect repo access:           $($confirmedSettings.enforceReferencedRepoScopedToken)" -ForegroundColor White
    Write-Host "  Private status badges:         $($confirmedSettings.statusBadgesArePrivate)" -ForegroundColor White
    Write-Host "  Limit queue-time variables:    $($confirmedSettings.enforceSettableVar)" -ForegroundColor White
    Write-Host "  No classic build pipelines:    $($confirmedSettings.disableClassicBuildPipelineCreation)" -ForegroundColor White
    Write-Host "  No classic release pipelines:  $($confirmedSettings.disableClassicReleasePipelineCreation)" -ForegroundColor White
    Write-Host "  Shell args validation:         $($confirmedSettings.enableShellTasksArgsSanitizing)" -ForegroundColor White
}
catch {
    Write-Warning "Could not re-read settings to confirm: $_"
}

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Green
Write-Host "Pipeline security settings applied to: $Organization/$Project" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Verify in Azure DevOps: Project Settings → Pipelines → Settings" -ForegroundColor Gray
Write-Host "  2. Run Set-AzureDevOpsServiceConnectionSecurity.ps1 to lock service connection access" -ForegroundColor Gray
Write-Host "  3. Run Set-AzureDevOpsBranchPolicies.ps1 to add build validation to protected branches" -ForegroundColor Gray
Write-Host ""
