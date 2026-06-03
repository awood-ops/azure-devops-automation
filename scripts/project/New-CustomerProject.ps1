<#
.SYNOPSIS
    Creates and secures a customer Azure DevOps project.

.DESCRIPTION
    Orchestrates full project setup for a given customer:
      Step 1 — Creates the ADO project
      Step 2 — Wires Entra ID security groups into Project Administrators and Readers (optional)
      Step 3 — Applies the standard 10-step security hardening baseline

    Entra ID groups are assumed to already exist in the tenant. ADO will materialise
    them on first access if they have not been seen before.

.PARAMETER Organization
    Azure DevOps organization name (e.g. "my-org" from dev.azure.com/my-org).

.PARAMETER ProjectName
    Display name of the ADO project to create.

.PARAMETER ProjectDescription
    Short description for the ADO project. Defaults to "<ProjectName> customer project".

.PARAMETER AdminGroups
    Entra ID group display names to add to Project Administrators. Optional.
    Example (Simpson Associates): @("SG_PFG_ADO_CloudPlatform_Admins", "SG_PFG_ADO_CloudPlatform_ApprovalRequired")

.PARAMETER ReaderGroup
    Entra ID group display name to add to Readers. Optional.
    Example (Simpson Associates): "SG_PFG_ADO_CloudPlatform_Readers"

.PARAMETER Force
    Skip all confirmation prompts.

.EXAMPLE
    # Minimal — no group wiring
    .\New-CustomerProject.ps1 -Organization "my-org" -ProjectName "Acme Corp" -AdminGroups @() -ReaderGroup "" -Force

.EXAMPLE
    # With Entra ID group wiring
    .\New-CustomerProject.ps1 -Organization "my-org" -ProjectName "Acme Corp" `
        -AdminGroups @("MyAdminGroup", "MyApprovalGroup") -ReaderGroup "MyReadersGroup" -Force

.NOTES
    Author: Andrew Wood
    Prerequisites:
    - Connect-AzAccount (recommended) or AZURE_DEVOPS_EXT_PAT
    - Project Collection Administrator in the target organisation
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string]$Organization,

    [Parameter(Mandatory = $true)]
    [string]$ProjectName,

    [Parameter(Mandatory = $false)]
    [string]$ProjectDescription,

    [Parameter(Mandatory = $false)]
    [string[]]$AdminGroups = @(),

    [Parameter(Mandatory = $false)]
    [string]$ReaderGroup = "",

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

if (-not $ProjectDescription) { $ProjectDescription = "$ProjectName customer project" }

$ErrorActionPreference = "Stop"
$scriptRoot = $PSScriptRoot

$groupMemberScript = Join-Path $scriptRoot "..\security\Set-AzureDevOpsGroupMember.ps1"
$hardeningScript   = Join-Path $scriptRoot "..\security\Invoke-AzureDevOpsHardening.ps1"
$createScript      = Join-Path $scriptRoot "New-AzureDevOpsProject.ps1"

function Write-StepHeader {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host ""
}

$urlSafe = $ProjectName -replace ' ', '%20'

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       $($ProjectName.PadRight(50)) ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host "  Organisation : $Organization" -ForegroundColor White
Write-Host "  Project      : $ProjectName" -ForegroundColor White
Write-Host ""

if (-not $Force -and -not $WhatIfPreference) {
    $confirmation = Read-Host "This will create and secure '$ProjectName' in '$Organization'. Continue? (yes/no)"
    if ($confirmation -ne "yes") {
        Write-Host "Cancelled." -ForegroundColor Yellow
        exit 0
    }
}

# ── Step 1: Create project ─────────────────────────────────────────────────────
Write-StepHeader "Step 1 of 3 — Create Project"

& $createScript `
    -Organization    $Organization `
    -ProjectName     $ProjectName `
    -Description     $ProjectDescription `
    -ProcessTemplate "Agile" `
    -VersionControl  "Git" `
    -Visibility      "private" `
    -Force:$Force

# ── Step 2: Wire Entra ID groups ──────────────────────────────────────────────
Write-StepHeader "Step 2 of 3 — Wire Entra ID Groups"

if ($AdminGroups.Count -eq 0 -and -not $ReaderGroup) {
    Write-Host "  No groups specified — skipping group wiring." -ForegroundColor Gray
} else {
    foreach ($group in $AdminGroups) {
        Write-Host "  Adding '$group' → Project Administrators..." -ForegroundColor White
        & $groupMemberScript `
            -Organization $Organization `
            -Project      $ProjectName `
            -Group        "Project Administrators" `
            -Action       "Add" `
            -Member       $group `
            -Force
    }

    if ($ReaderGroup) {
        Write-Host "  Adding '$ReaderGroup' → Readers..." -ForegroundColor White
        & $groupMemberScript `
            -Organization $Organization `
            -Project      $ProjectName `
            -Group        "Readers" `
            -Action       "Add" `
            -Member       $ReaderGroup `
            -Force
    }
}

# ── Step 3: Security hardening ────────────────────────────────────────────────
Write-StepHeader "Step 3 of 3 — Security Hardening"

$hardeningParams = @{
    Organization = $Organization
    Project      = $ProjectName
    Force        = $Force.IsPresent
}
if ($AdminGroups.Count -gt 0) { $hardeningParams.ExpectedAdmins = $AdminGroups }

& $hardeningScript @hardeningParams

# ── Done ───────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host ("=" * 60) -ForegroundColor Green
Write-Host "  $ProjectName project setup complete." -ForegroundColor Green
Write-Host ("=" * 60) -ForegroundColor Green
Write-Host ""
Write-Host "  URL: https://dev.azure.com/$Organization/$urlSafe" -ForegroundColor White
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Yellow
Write-Host "    - Create repositories and pipelines" -ForegroundColor Gray
Write-Host "    - Add a service connection (New-AzureDevOpsServiceConnection.ps1)" -ForegroundColor Gray
Write-Host "    - Confirm PIM group materialization in ADO Security settings" -ForegroundColor Gray
Write-Host ""
