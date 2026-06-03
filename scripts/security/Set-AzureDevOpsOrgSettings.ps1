<#
.SYNOPSIS
    Applies organisation-level security hardening settings in Azure DevOps.

.DESCRIPTION
    Configures security settings at the Azure DevOps organisation level — settings
    that apply across all projects, not just a single one.

    Pipeline settings (via Contribution/HierarchyQuery API):
    - Disable creation of classic release pipelines
      Classic release pipelines lack the auditability and YAML-as-code benefits of
      modern pipelines and cannot be scoped or reviewed as easily. Disabling creation
      prevents new ones being added while leaving existing ones intact.

    - Enable shell task argument sanitisation
      Validates arguments passed to built-in shell tasks (Bash, PowerShell, etc.)
      to detect inputs that could inject commands. When set at org level, this cannot
      be overridden at the project level.

    - Disable creation of classic build pipelines
      Classic build pipelines (designer-based builds) carry the same audit and
      code-review limitations as classic release pipelines. Disabling creation
      prevents new ones being added while leaving existing ones intact.

    - Disable Node 6 task execution
      Node.js 6 has been end-of-life since 2019 and poses a supply-chain risk.
      Disabling it forces tasks to run on a supported Node.js version.

    - Disable Marketplace tasks
      Prevents pipelines from using tasks installed from the Azure DevOps Marketplace.
      Audit all Marketplace extensions in use before enabling — any pipeline using a
      third-party extension task will fail. Default: $false.

    Organisation policies (via Organisation Policy API):
    - Restrict PAT creation
      Without this, any user can create a PAT with full organisation-scoped access.
      When enabled, PAT creation can be limited to specific scopes or specific users.

    - Disable external guest access
      Prevents Microsoft Entra guest accounts from accessing the organisation.
      Only disable if your organisation has no legitimate external collaborators.

    - Disable third-party OAuth application access
      Prevents third-party applications from accessing the organisation via OAuth.
      Enable only if you have audited and approved all OAuth-connected applications.

    - Enforce audit event logging
      Ensures all authentication and authorisation events are sent to the Azure DevOps
      audit log. Disabling this removes forensic capability and is rarely justified.

    - Disable SSH authentication
      Blocks SSH-based git operations across the organisation. Unless your team
      specifically uses SSH keys, HTTPS (with tokens) is preferred and easier to govern.

    All pipeline settings are reported with current state before changes are applied.
    Organisation policies are write-only via the API — current state cannot be read;
    the script reports what will be applied. Use -ReportOnly to preview without changes.

.PARAMETER Organization
    Azure DevOps organization name (e.g. "myorg" from dev.azure.com/myorg)

.PARAMETER DisableClassicReleasePipelines
    Prevent creation of new classic release pipelines. Default: $true

.PARAMETER EnableShellTaskValidation
    Enable shell task argument sanitisation to detect command injection.
    Default: $true

.PARAMETER RestrictPATCreation
    Restrict users from creating PATs with broad scopes. Default: $false
    Note: Enabling this affects all users in the organisation. Test with a
    small group first using the Azure DevOps UI allowlist before scripting.

.PARAMETER DisableExternalGuestAccess
    Block Microsoft Entra guest accounts from accessing the organisation.
    Default: $false — only set $true if you have no external collaborators.

.PARAMETER DisableOAuthAppAccess
    Block third-party applications from connecting via OAuth.
    Default: $false — only set $true after auditing connected OAuth applications.

.PARAMETER DisableClassicBuildPipelines
    Prevent creation of new classic (designer-based) build pipelines. Default: $true

.PARAMETER DisableNode6Tasks
    Prevent tasks from running on the end-of-life Node.js 6 execution handler.
    Default: $true

.PARAMETER EnforceAuditLogging
    Ensure audit event logging is enabled for the organisation. Default: $true

.PARAMETER DisableSSHAuth
    Block SSH-based git authentication across the organisation. Default: $true

.PARAMETER DisableMarketplaceTasks
    Prevent pipelines from using tasks from the Azure DevOps Marketplace.
    Default: $false — audit all Marketplace task usage before enabling.

.PARAMETER ReportOnly
    Report current state without making any changes.

.PARAMETER Force
    Skip confirmation prompts.

.EXAMPLE
    # Report current state
    .\Set-AzureDevOpsOrgSettings.ps1 `
        -Organization "myorg" `
        -ReportOnly

.EXAMPLE
    # Best practice: apply safe defaults (pipeline hardening only)
    # DisableClassicReleasePipelines and EnableShellTaskValidation are low-risk.
    # RestrictPATCreation and DisableExternalGuestAccess default to $false —
    # review your organisation before enabling those.
    .\Set-AzureDevOpsOrgSettings.ps1 `
        -Organization "myorg" `
        -DisableClassicReleasePipelines $true `
        -EnableShellTaskValidation $true `
        -Force

.EXAMPLE
    # Full lockdown — only appropriate if you have no external users, OAuth apps, or Marketplace task dependencies
    .\Set-AzureDevOpsOrgSettings.ps1 `
        -Organization "myorg" `
        -DisableClassicReleasePipelines $true `
        -DisableClassicBuildPipelines $true `
        -EnableShellTaskValidation $true `
        -DisableNode6Tasks $true `
        -RestrictPATCreation $true `
        -EnforceAuditLogging $true `
        -DisableSSHAuth $true `
        -DisableExternalGuestAccess $true `
        -DisableOAuthAppAccess $true `
        -DisableMarketplaceTasks $true `
        -Force

.NOTES
    Author: Andrew Wood
    Version: 1.3

    Prerequisites:
    - Azure DevOps login: Connect-AzAccount, AZURE_DEVOPS_EXT_PAT, or az devops login
    - Permissions: Organisation Administrator

    Pipeline settings are applied via the internal Contribution/HierarchyQuery API
    (the same endpoint the Azure DevOps UI uses). This is not a documented public REST
    API but is stable and widely used for automation.

    Settings NOT covered by this script (UI only):
    - PAT allowlist management (specific users/groups allowed to create full-scope PATs)
      Configure at: dev.azure.com/{org}/_settings/organizationPolicy
    - IP allowlisting for Conditional Access
      Configure at: dev.azure.com/{org}/_settings/organizationPolicy

    API References:
    - Contribution/HierarchyQuery: https://learn.microsoft.com/en-us/rest/api/azure/devops/contribution/
    - Organisation Policies:       https://learn.microsoft.com/en-us/rest/api/azure/devops/ims/policies

.LINK
    https://learn.microsoft.com/en-us/azure/devops/organizations/security/
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string]$Organization,

    [Parameter(Mandatory = $false)]
    [bool]$DisableClassicReleasePipelines = $true,

    [Parameter(Mandatory = $false)]
    [bool]$EnableShellTaskValidation = $true,

    [Parameter(Mandatory = $false)]
    [bool]$RestrictPATCreation = $false,

    [Parameter(Mandatory = $false)]
    [bool]$DisableExternalGuestAccess = $false,

    [Parameter(Mandatory = $false)]
    [bool]$DisableOAuthAppAccess = $false,

    [Parameter(Mandatory = $false)]
    [bool]$DisableClassicBuildPipelines = $true,

    [Parameter(Mandatory = $false)]
    [bool]$DisableNode6Tasks = $true,

    [Parameter(Mandatory = $false)]
    [bool]$EnforceAuditLogging = $true,

    [Parameter(Mandatory = $false)]
    [bool]$DisableSSHAuth = $true,

    [Parameter(Mandatory = $false)]
    [bool]$DisableMarketplaceTasks = $false,

    [Parameter(Mandatory = $false)]
    [switch]$ReportOnly,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "=== Azure DevOps Organisation Security Settings ===" -ForegroundColor Cyan
Write-Host ""

. "$PSScriptRoot\_Helpers.ps1"

function Write-SettingStatus {
    param(
        [string]$Label,
        [string]$CurrentDisplay,
        [string]$TargetDisplay,
        [bool]$AlreadyCorrect,
        [bool]$ReportOnly
    )
    $statusColor  = if ($AlreadyCorrect) { "Green" } else { "Yellow" }
    $changeMarker = if (-not $ReportOnly -and -not $AlreadyCorrect) { " → will set to $TargetDisplay" } else { "" }
    Write-Host "  $Label" -ForegroundColor White
    Write-Host "    Current: $CurrentDisplay$changeMarker" -ForegroundColor $statusColor
}

# Confirm
if (-not $ReportOnly -and -not $Force -and -not $WhatIfPreference) {
    Write-Host "⚠️  This will update organisation-level security settings for: $Organization" -ForegroundColor Yellow
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

# ─────────────────────────────────────────────────────────────
# Pipeline Settings (org-level via HierarchyQuery)
# ─────────────────────────────────────────────────────────────
Write-Host "`n[2/3] Reading organisation pipeline settings..." -ForegroundColor Yellow

$hierarchyQueryUrl = "https://dev.azure.com/$Organization/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1"

# Read current pipeline settings by querying the data provider without any property updates
$readBody = @{
    contributionIds     = @("ms.vss-build-web.pipelines-org-settings-data-provider")
    dataProviderContext = @{ properties = @{} }
}

try {
    $pipelineSettingsResponse = Invoke-AzureDevOpsApi -Uri $hierarchyQueryUrl -Method Post -Body $readBody -AuthHeader $authHeader
    $currentPipelineSettings  = $pipelineSettingsResponse.dataProviders."ms.vss-build-web.pipelines-org-settings-data-provider"

    Write-Host "✓ Pipeline settings retrieved" -ForegroundColor Green
    Write-Host ""
    Write-Host "Pipeline Settings:" -ForegroundColor Cyan

    Write-SettingStatus `
        -Label "Disable creation of classic release pipelines" `
        -CurrentDisplay $(if ($currentPipelineSettings.disableClassicReleasePipelineCreation) { "ON" } else { "OFF" }) `
        -TargetDisplay "ON" `
        -AlreadyCorrect ($currentPipelineSettings.disableClassicReleasePipelineCreation -eq $DisableClassicReleasePipelines) `
        -ReportOnly $ReportOnly.IsPresent

    Write-SettingStatus `
        -Label "Enable shell task argument sanitisation" `
        -CurrentDisplay $(if ($currentPipelineSettings.enableShellTasksArgsSanitizing) { "ON" } else { "OFF" }) `
        -TargetDisplay "ON" `
        -AlreadyCorrect ($currentPipelineSettings.enableShellTasksArgsSanitizing -eq $EnableShellTaskValidation) `
        -ReportOnly $ReportOnly.IsPresent

    Write-SettingStatus `
        -Label "Disable creation of classic build pipelines" `
        -CurrentDisplay $(if ($currentPipelineSettings.disableClassicBuildPipelineCreation) { "ON" } else { "OFF" }) `
        -TargetDisplay "ON" `
        -AlreadyCorrect ($currentPipelineSettings.disableClassicBuildPipelineCreation -eq $DisableClassicBuildPipelines) `
        -ReportOnly $ReportOnly.IsPresent

    Write-SettingStatus `
        -Label "Disable Node 6 tasks" `
        -CurrentDisplay $(if ($currentPipelineSettings.disableNode6Tasks) { "ON" } else { "OFF" }) `
        -TargetDisplay "ON" `
        -AlreadyCorrect ($currentPipelineSettings.disableNode6Tasks -eq $DisableNode6Tasks) `
        -ReportOnly $ReportOnly.IsPresent

    Write-SettingStatus `
        -Label "Disable Marketplace tasks" `
        -CurrentDisplay $(if ($currentPipelineSettings.disableMarketplaceTasks) { "ON" } else { "OFF" }) `
        -TargetDisplay "ON" `
        -AlreadyCorrect ($currentPipelineSettings.disableMarketplaceTasks -eq $DisableMarketplaceTasks) `
        -ReportOnly $ReportOnly.IsPresent

    Write-Host ""
}
catch {
    Write-Warning "Could not retrieve organisation pipeline settings: $_"
    Write-Host ""
}

# ─────────────────────────────────────────────────────────────
# Organisation Policies
# ─────────────────────────────────────────────────────────────
Write-Host "[3/3] Organisation policies (write-only — current state not readable via API)..." -ForegroundColor Yellow
Write-Host ""
Write-Host "Organisation Policies:" -ForegroundColor Cyan

$policyActions = [ordered]@{
    "Restrict PAT creation"                   = @{ Param = $RestrictPATCreation;      Name = "DisablePATCreation";        Apply = "Restricted";  Skip = "Unrestricted (not changing)" }
    "External guest access"                   = @{ Param = $DisableExternalGuestAccess; Name = "DisallowAadGuestUserAccess"; Apply = "Blocked";      Skip = "Allowed (not changing)" }
    "Third-party OAuth application access"    = @{ Param = $DisableOAuthAppAccess;     Name = "DisallowOAuthAuthentication"; Apply = "Blocked";     Skip = "Allowed (not changing)" }
    "Audit event logging"                     = @{ Param = $EnforceAuditLogging;       Name = "LogAuditEvents";            Apply = "Enabled";      Skip = "Not enforcing (not changing)" }
    "SSH authentication"                      = @{ Param = $DisableSSHAuth;            Name = "DisableSSHAuthentication";  Apply = "Will disable"; Skip = "Enabled (not changing)" }
}

foreach ($label in $policyActions.Keys) {
    $action = $policyActions[$label]
    $display = if ($action.Param) { $action.Apply } else { $action.Skip }
    $color   = if ($action.Param) { "Yellow" } else { "Gray" }
    Write-Host "  $label" -ForegroundColor White
    Write-Host "    Action: $display" -ForegroundColor $color
}

Write-Host ""
Write-Host "  Note: The Organisation Policy API is write-only. Current state cannot" -ForegroundColor DarkGray
Write-Host "  be read via REST — verify at: dev.azure.com/$Organization/_settings/organizationPolicy" -ForegroundColor DarkGray
Write-Host ""

if ($ReportOnly) {
    Write-Host "Report mode — no changes applied." -ForegroundColor Yellow
    Write-Host "Re-run without -ReportOnly to apply the settings." -ForegroundColor Yellow
    Write-Host ""
    exit 0
}

# ─────────────────────────────────────────────────────────────
# Apply pipeline settings
# ─────────────────────────────────────────────────────────────
Write-Host "Applying organisation pipeline settings..." -ForegroundColor Yellow

$pipelineProps = @{
    disableClassicReleasePipelineCreation = if ($DisableClassicReleasePipelines) { "true" } else { "false" }
    disableClassicBuildPipelineCreation   = if ($DisableClassicBuildPipelines)   { "true" } else { "false" }
    enableShellTasksArgsSanitizing        = if ($EnableShellTaskValidation)      { "true" } else { "false" }
    disableNode6Tasks                     = if ($DisableNode6Tasks)              { "true" } else { "false" }
    disableMarketplaceTasks               = if ($DisableMarketplaceTasks)        { "true" } else { "false" }
}

$writeBody = @{
    contributionIds     = @("ms.vss-build-web.pipelines-org-settings-data-provider")
    dataProviderContext = @{ properties = $pipelineProps }
}

try {
    if ($PSCmdlet.ShouldProcess($Organization, "Apply organisation pipeline security settings")) {
        Invoke-AzureDevOpsApi -Uri $hierarchyQueryUrl -Method Post -Body $writeBody -AuthHeader $authHeader | Out-Null
        Write-Host "✓ Organisation pipeline settings applied" -ForegroundColor Green
    }
}
catch {
    Write-Warning "Failed to apply pipeline settings: $_"
}

# ─────────────────────────────────────────────────────────────
# Apply organisation policies
# ─────────────────────────────────────────────────────────────
$policiesToApply = @()

if ($RestrictPATCreation) {
    $policiesToApply += @{ name = "DisablePATCreation"; value = "true" }
}
if ($DisableExternalGuestAccess) {
    $policiesToApply += @{ name = "DisallowAadGuestUserAccess"; value = "true" }
}
if ($DisableOAuthAppAccess) {
    $policiesToApply += @{ name = "DisallowOAuthAuthentication"; value = "true" }
}
if ($EnforceAuditLogging) {
    $policiesToApply += @{ name = "LogAuditEvents"; value = "true" }
}
if ($DisableSSHAuth) {
    $policiesToApply += @{ name = "DisableSSHAuthentication"; value = "true" }
}

if ($policiesToApply.Count -gt 0) {
    Write-Host "Applying organisation policies..." -ForegroundColor Yellow
    foreach ($policy in $policiesToApply) {
        try {
            $policyUrl  = "https://dev.azure.com/$Organization/_apis/OrganizationPolicy/Policies/Policy.$($policy.name)?api-version=5.1-preview.1"
            $patchBody  = @(
                @{ from = ""; op = 2; path = "/Value"; value = $policy.value }
            )
            if ($PSCmdlet.ShouldProcess("Policy.$($policy.name)", "Apply organisation policy")) {
                Invoke-AzureDevOpsApi -Uri $policyUrl -Method Patch -Body $patchBody `
                    -ContentType "application/json-patch+json" -AuthHeader $authHeader | Out-Null
                Write-Host "  ✓ Policy.$($policy.name)" -ForegroundColor Green
            }
        }
        catch {
            Write-Warning "  Failed to apply Policy.$($policy.name): $_"
        }
    }
}
# ─────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Green
Write-Host "Organisation settings applied to: $Organization" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Verify in Azure DevOps: Organisation Settings → Pipelines → Settings" -ForegroundColor Gray
Write-Host "  2. Verify in Azure DevOps: Organisation Settings → Security → Policies" -ForegroundColor Gray
if ($RestrictPATCreation) {
    Write-Host "  3. Review PAT allowlist if needed: https://dev.azure.com/$Organization/_settings/organizationPolicy" -ForegroundColor Gray
}
Write-Host ""
