<#
.SYNOPSIS
    Applies all Azure DevOps security hardening steps for a project in a single run.

.DESCRIPTION
    Orchestrates the full security hardening sequence for an Azure DevOps project:

    Step 1 — Branch Policies (Set-AzureDevOpsBranchPolicies.ps1)
      Applies protection to the default branch of every repository (or a specified
      subset): minimum reviewers, self-approval prohibition, comment resolution,
      squash-only merge strategy, and optional build validation.

    Step 2 — Admin Audit (Get-AzureDevOpsAudit.ps1)
      Lists all Project Administrator group members and flags anyone not on the
      expected allowlist. Read-only — remediation is manual.

    Step 3 — Service Connection Security (Set-AzureDevOpsServiceConnectionSecurity.ps1)
      Locks all service connections so no pipeline can use them by default.
      Only explicitly authorised pipeline IDs will be granted access.

    Step 4 — Pipeline Security Settings (Set-AzureDevOpsPipelineSecurity.ps1)
      Applies project-level pipeline settings: job scope limited to current project,
      YAML repository protection, and private status badges.

    Step 5 — Per-repository Policies
      Applies commit author email validation and required work item linking to every
      repository in the project via the Policy Configurations API.

    Step 6 — Variable Group Library Security
      Restricts inherited ACEs on the project Library security namespace so that
      Contributors and Build Administrators hold only View permissions.
      Prevents broader groups from creating, using, or administering variable groups.

    Step 7 — Agent Pool Auto-Provisioning
      Identifies self-hosted pools accessible to this project that have
      autoProvision enabled. Attempts to disable it so pools must be granted
      per-project explicitly rather than auto-attaching to every new project.
      Requires Manage pool permission at the organisation level; warns gracefully
      if insufficient rights.

    Step 8 — Build Pipeline Security
      Restricts inherited ACEs on the project-default Build security namespace so
      that Contributors and Build Administrators hold only View permissions.
      Prevents broader groups from queueing, editing, deleting, or administering
      build pipelines at the project level.

    Step 9 — Repository ACL Security
      Restricts inherited ACEs on the Git Repositories security namespace so that
      Contributors and Build Administrators hold only Read permissions at the
      project level. Prevents broader groups from contributing, creating branches,
      creating tags, managing notes, or contributing to pull requests on any
      repository in the project. Addresses PERM-06 audit findings.

    Step 10 — Release Pipeline Security
      Restricts inherited ACEs on the Release Management security namespace so
      that Contributors hold only View permissions at the project level.
      Prevents the Contributors group from editing, deleting, creating, or managing
      release pipelines and deployments. Addresses PERM-02 audit findings.

    Individual steps can be skipped with -Skip* switches if already hardened.
    Use -ReportOnly to audit current state across all steps without making changes.

.PARAMETER Organization
    Azure DevOps organization name (e.g. "myorg" from dev.azure.com/myorg)

.PARAMETER Project
    Azure DevOps project name

.PARAMETER RepositoryNames
    Repository names to apply branch policies to. If omitted, branch policies are
    applied to every repository in the project.

.PARAMETER Branch
    Branch to protect with policies. Default: "main"

.PARAMETER MinimumReviewerCount
    Minimum number of PR reviewers required. Default: 2

.PARAMETER RequiredReviewerEmails
    Email addresses to automatically add as required reviewers on every PR.

.PARAMETER ExpectedAdmins
    Expected Project Administrator email addresses for the admin audit.
    Anyone not on this list will be flagged as unexpected.

.PARAMETER AdminAuditCsvPath
    Optional path to export the admin audit results as a CSV file.

.PARAMETER ReportOnly
    Run all steps in report/audit mode — no changes applied.

.PARAMETER SkipBranchPolicies
    Skip the branch policies step.

.PARAMETER SkipAdminAudit
    Skip the admin audit step.

.PARAMETER SkipServiceConnectionSecurity
    Skip the service connection security step.

.PARAMETER SkipPipelineSecurity
    Skip the pipeline security settings step.

.PARAMETER SkipProjectPolicies
    Skip the project-level repository policies step (commit author email validation and work item linking).

.PARAMETER AuthorEmailPattern
    Glob pattern for commit author email validation. Default: "*@*.*" (any valid domain).
    Example: "*@mycompany.com" to restrict commits to corporate email addresses only.

.PARAMETER SkipLibrarySecurity
    Skip the variable group library security step.

.PARAMETER SkipPoolAutoProvision
    Skip the agent pool auto-provisioning check/disable step.

.PARAMETER SkipBuildSecurity
    Skip the build pipeline security step.

.PARAMETER SkipRepositoryAcl
    Skip the repository ACL security step (PERM-06).

.PARAMETER SkipReleasePipelineSecurity
    Skip the release pipeline security step (PERM-02).

.PARAMETER Force
    Skip all confirmation prompts.

.EXAMPLE
    # Audit current state across all steps — no changes
    .\Invoke-AzureDevOpsHardening.ps1 `
        -Organization "myorg" `
        -Project "MyProject" `
        -ReportOnly

.EXAMPLE
    # Best practice: full hardening run with required reviewers and admin allowlist
    # Run -ReportOnly first to review current state before applying
    .\Invoke-AzureDevOpsHardening.ps1 `
        -Organization "myorg" `
        -Project "MyProject" `
        -RequiredReviewerEmails "tech.lead@company.com","security@company.com" `
        -ExpectedAdmins "admin@company.com","devops@company.com" `
        -AdminAuditCsvPath "C:\Reports\admin-audit.csv" `
        -Force

.EXAMPLE
    # Harden specific repositories only, skip steps already completed
    .\Invoke-AzureDevOpsHardening.ps1 `
        -Organization "myorg" `
        -Project "MyProject" `
        -RepositoryNames "api-repo","frontend-repo" `
        -SkipAdminAudit `
        -SkipPipelineSecurity `
        -Force

.NOTES
    Author: Andrew Wood
    Version: 1.0

    Prerequisites:
    - Azure DevOps login: Connect-AzAccount, AZURE_DEVOPS_EXT_PAT, or az devops login
    - Permissions: Project Administrator

    Hardening order rationale:
    1. Branch policies  — protects main before anything else; highest immediate impact
    2. Admin audit      — identifies who can bypass all controls (read-only)
    3. Service connections — locks production credentials to specific pipelines
    4. Pipeline settings   — limits runtime access scope; final layer of defence

.LINK
    https://learn.microsoft.com/en-us/azure/devops/organizations/security/
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string]$Organization,

    [Parameter(Mandatory = $true)]
    [string]$Project,

    [Parameter(Mandatory = $false)]
    [string[]]$RepositoryNames = @(),

    [Parameter(Mandatory = $false)]
    [string]$Branch = "main",

    [Parameter(Mandatory = $false)]
    [int]$MinimumReviewerCount = 2,

    [Parameter(Mandatory = $false)]
    [string[]]$RequiredReviewerEmails = @(),

    [Parameter(Mandatory = $false)]
    [string[]]$ExpectedAdmins = @(),

    [Parameter(Mandatory = $false)]
    [string]$AdminAuditCsvPath,

    [Parameter(Mandatory = $false)]
    [switch]$ReportOnly,

    [Parameter(Mandatory = $false)]
    [switch]$SkipBranchPolicies,

    [Parameter(Mandatory = $false)]
    [switch]$SkipAdminAudit,

    [Parameter(Mandatory = $false)]
    [switch]$SkipServiceConnectionSecurity,

    [Parameter(Mandatory = $false)]
    [switch]$SkipPipelineSecurity,

    [Parameter(Mandatory = $false)]
    [switch]$SkipProjectPolicies,

    [Parameter(Mandatory = $false)]
    [string]$AuthorEmailPattern = "*@*.*",

    [Parameter(Mandatory = $false)]
    [switch]$SkipLibrarySecurity,

    [Parameter(Mandatory = $false)]
    [switch]$SkipPoolAutoProvision,

    [Parameter(Mandatory = $false)]
    [switch]$SkipBuildSecurity,

    [Parameter(Mandatory = $false)]
    [switch]$SkipRepositoryAcl,

    [Parameter(Mandatory = $false)]
    [switch]$SkipReleasePipelineSecurity,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$scriptRoot = $PSScriptRoot

# Track results for final summary
$results = [ordered]@{}

function Write-StepHeader {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host ""
}

function Write-StepResult {
    param([string]$Step, [bool]$Success, [string]$Detail = "")
    $icon  = if ($Success) { "✓" } else { "✗" }
    $color = if ($Success) { "Green" } else { "Red" }
    $msg   = if ($Detail)  { "$icon  $Step — $Detail" } else { "$icon  $Step" }
    Write-Host $msg -ForegroundColor $color
}

# ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       Azure DevOps Security Hardening                    ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host "  Organisation : $Organization" -ForegroundColor White
Write-Host "  Project      : $Project" -ForegroundColor White
if ($ReportOnly) {
    Write-Host "  Mode         : REPORT ONLY — no changes will be made" -ForegroundColor Yellow
} else {
    Write-Host "  Mode         : APPLY — changes will be made" -ForegroundColor Green
}
Write-Host ""
Write-Host "  Note: This script covers project-level hardening only." -ForegroundColor DarkGray
Write-Host "  Run Set-AzureDevOpsOrgSettings.ps1 separately for organisation-level settings." -ForegroundColor DarkGray
Write-Host ""

# ─────────────────────────────────────────────────────────────
# Confirm before applying
# ─────────────────────────────────────────────────────────────
if (-not $ReportOnly -and -not $Force -and -not $WhatIfPreference) {
    Write-Host "⚠️  This will apply security hardening to: $Organization/$Project" -ForegroundColor Yellow
    $confirmation = Read-Host "Continue? (yes/no)"
    if ($confirmation -ne "yes") {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        exit 0
    }
}

# ─────────────────────────────────────────────────────────────
# Resolve repositories for branch policies
# ─────────────────────────────────────────────────────────────
$skipBranchPoliciesNow = $SkipBranchPolicies.IsPresent

if (-not $skipBranchPoliciesNow) {
    if ($RepositoryNames.Count -eq 0) {
        Write-Host "[Pre-flight] Enumerating repositories in $Project..." -ForegroundColor Yellow
        try {
            . "$scriptRoot\_Helpers.ps1"
            $authHeader  = Get-AzureDevOpsAuthHeader
            $reposUrl    = "https://dev.azure.com/$Organization/$Project/_apis/git/repositories?api-version=7.1"
            $repos       = (Invoke-AzureDevOpsApi -Uri $reposUrl -AuthHeader $authHeader).value
            $RepositoryNames = $repos.name
            Write-Host "✓ Found $($RepositoryNames.Count) repositories: $($RepositoryNames -join ', ')" -ForegroundColor Green
        }
        catch {
            Write-Warning "Could not enumerate repositories: $_"
            Write-Warning "Use -RepositoryNames to specify repositories explicitly, or -SkipBranchPolicies to skip this step."
            $skipBranchPoliciesNow = $true
        }
    }
}

# ─────────────────────────────────────────────────────────────
# Step 1 — Branch Policies
# ─────────────────────────────────────────────────────────────
Write-StepHeader "Step 1 of 8 — Branch Policies"

if ($skipBranchPoliciesNow) {
    Write-Host "  Skipped." -ForegroundColor Gray
    $results["Branch Policies"] = "Skipped"
} else {
    $branchScript  = Join-Path $scriptRoot "Set-AzureDevOpsBranchPolicies.ps1"
    $branchSuccess = $true
    $branchErrors  = @()

    foreach ($repo in $RepositoryNames) {
        Write-Host "  Applying to: $repo" -ForegroundColor White
        try {
            $branchParams = @{
                Organization            = $Organization
                Project                 = $Project
                RepositoryName          = $repo
                Branch                  = $Branch
                MinimumReviewerCount    = $MinimumReviewerCount
                ProhibitSelfApproval    = $true
                ResetVotesOnPush        = $true
                RequireResolvedComments = $true
                AllowSquash             = $true
                AllowRebase             = $false
                AllowNoFastForward      = $false
                Force                   = (-not $ReportOnly)
            }
            if ($RequiredReviewerEmails.Count -gt 0) {
                $branchParams.RequiredReviewerEmails = $RequiredReviewerEmails
            }

            if ($ReportOnly) {
                & $branchScript @branchParams -WhatIf
            } else {
                & $branchScript @branchParams
            }
        }
        catch {
            $branchSuccess = $false
            $branchErrors += "$repo`: $_"
            Write-Warning "  Failed for $repo`: $_"
        }
    }

    if ($branchSuccess) {
        $results["Branch Policies"] = "Applied to $($RepositoryNames.Count) repo(s)"
    } else {
        $results["Branch Policies"] = "Completed with errors: $($branchErrors -join '; ')"
    }
}

# ─────────────────────────────────────────────────────────────
# Step 2 — Admin Audit
# ─────────────────────────────────────────────────────────────
Write-StepHeader "Step 2 of 8 — Project Administrator Audit"

if ($SkipAdminAudit) {
    Write-Host "  Skipped." -ForegroundColor Gray
    $results["Admin Audit"] = "Skipped"
} else {
    $auditScript = Join-Path $scriptRoot "Get-AzureDevOpsAudit.ps1"
    try {
        $auditParams = @{
            Organization = $Organization
            Project      = $Project
            Group        = "Project Administrators"
        }
        if ($ExpectedAdmins.Count -gt 0) {
            $auditParams.ExpectedAdmins = $ExpectedAdmins
        }
        if ($AdminAuditCsvPath) {
            $auditParams.ExportCsvPath = $AdminAuditCsvPath
        }

        & $auditScript @auditParams
        $results["Admin Audit"] = "Completed$(if ($AdminAuditCsvPath) { " — exported to $AdminAuditCsvPath" })"
    }
    catch {
        Write-Warning "Admin audit failed: $_"
        $results["Admin Audit"] = "Failed: $_"
    }
}

# ─────────────────────────────────────────────────────────────
# Step 3 — Service Connection Security
# ─────────────────────────────────────────────────────────────
Write-StepHeader "Step 3 of 8 — Service Connection Security"

if ($SkipServiceConnectionSecurity) {
    Write-Host "  Skipped." -ForegroundColor Gray
    $results["Service Connection Security"] = "Skipped"
} else {
    $svcScript = Join-Path $scriptRoot "Set-AzureDevOpsServiceConnectionSecurity.ps1"
    try {
        $svcParams = @{
            Organization = $Organization
            Project      = $Project
            ReportOnly   = $ReportOnly
            Force        = (-not $ReportOnly)
        }

        & $svcScript @svcParams
        $results["Service Connection Security"] = if ($ReportOnly) { "Reported (no changes)" } else { "Applied" }
    }
    catch {
        Write-Warning "Service connection security failed: $_"
        $results["Service Connection Security"] = "Failed: $_"
    }
}

# ─────────────────────────────────────────────────────────────
# Step 4 — Pipeline Security Settings
# ─────────────────────────────────────────────────────────────
Write-StepHeader "Step 4 of 8 — Pipeline Security Settings"

if ($SkipPipelineSecurity) {
    Write-Host "  Skipped." -ForegroundColor Gray
    $results["Pipeline Security"] = "Skipped"
} else {
    $pipelineScript = Join-Path $scriptRoot "Set-AzureDevOpsPipelineSecurity.ps1"
    try {
        $pipelineParams = @{
            Organization = $Organization
            Project      = $Project
            ReportOnly   = $ReportOnly
            Force        = (-not $ReportOnly)
        }

        & $pipelineScript @pipelineParams
        $results["Pipeline Security"] = if ($ReportOnly) { "Reported (no changes)" } else { "Applied" }
    }
    catch {
        Write-Warning "Pipeline security settings failed: $_"
        $results["Pipeline Security"] = "Failed: $_"
    }
}

# ─────────────────────────────────────────────────────────────
# Step 5 — Project-level Repository Policies
# ─────────────────────────────────────────────────────────────
Write-StepHeader "Step 5 of 8 — Project-level Repository Policies"

if ($SkipProjectPolicies) {
    Write-Host "  Skipped." -ForegroundColor Gray
    $results["Project Policies"] = "Skipped"
} else {
    try {
        . "$scriptRoot\_Helpers.ps1"
        $authHeader = Get-AzureDevOpsAuthHeader

        $typesUrl    = "https://dev.azure.com/$Organization/$Project/_apis/policy/types?api-version=7.1"
        $policyTypes = Invoke-AzureDevOpsApi -Uri $typesUrl -AuthHeader $authHeader
        $typeMap     = @{}
        foreach ($pt in $policyTypes.value) { $typeMap[$pt.displayName] = $pt.id }

        $policiesUrl      = "https://dev.azure.com/$Organization/$Project/_apis/policy/configurations?api-version=7.1"
        $existingPolicies = (Invoke-AzureDevOpsApi -Uri $policiesUrl -AuthHeader $authHeader).value
        $baseUrl          = "https://dev.azure.com/$Organization/$Project/_apis/policy/configurations"

        # These policy types require a real repositoryId — enumerate all repos and apply to each
        $reposUrl = "https://dev.azure.com/$Organization/$Project/_apis/git/repositories?api-version=7.1"
        $allRepos = (Invoke-AzureDevOpsApi -Uri $reposUrl -AuthHeader $authHeader).value

        if (-not $allRepos -or $allRepos.Count -eq 0) {
            Write-Host "  No repositories found — skipping." -ForegroundColor Yellow
            $results["Project Policies"] = "Skipped — no repositories"
            return
        }

        Write-Host "  Applying to $($allRepos.Count) repository/repositories..." -ForegroundColor White

        $applied = 0
        foreach ($repo in $allRepos) {
            $repoScope = @(@{ repositoryId = $repo.id })

            $repoPolicies = @(
                @{
                    TypeName = "Commit author email validation"
                    Label    = "Commit author email validation ($($repo.name), pattern: $AuthorEmailPattern)"
                    Config   = @{
                        isEnabled  = $true
                        isBlocking = $true
                        type       = $null
                        settings   = @{
                            authorEmailPatterns = @($AuthorEmailPattern)
                            scope               = $repoScope
                        }
                    }
                },
                @{
                    TypeName = "Work item linking"
                    Label    = "Work item linking ($($repo.name))"
                    Config   = @{
                        isEnabled  = $true
                        isBlocking = $true
                        type       = $null
                        settings   = @{ scope = $repoScope }
                    }
                }
            )

            foreach ($entry in $repoPolicies) {
                $typeId = $typeMap[$entry.TypeName]
                if (-not $typeId) {
                    Write-Warning "  Could not find policy type '$($entry.TypeName)' — skipping"
                    continue
                }

                $entry.Config.type = @{ id = $typeId }

                $existing = $existingPolicies | Where-Object {
                    $_.type.id -eq $typeId -and
                    $_.settings.scope -and
                    ($_.settings.scope | Where-Object { $_.repositoryId -eq $repo.id })
                } | Select-Object -First 1

                if ($existing) {
                    if (-not $ReportOnly -and $PSCmdlet.ShouldProcess($entry.Label, "Update policy")) {
                        $entry.Config | Add-Member -NotePropertyName "id" -NotePropertyValue $existing.id -Force
                        $url = "$baseUrl/$($existing.id)?api-version=7.1"
                        Invoke-AzureDevOpsApi -Uri $url -Method Put -Body $entry.Config -AuthHeader $authHeader | Out-Null
                        Write-Host "  ✓ Updated: $($entry.Label)" -ForegroundColor Green
                    } else {
                        Write-Host "  ℹ  Already configured: $($entry.Label)" -ForegroundColor Gray
                    }
                } else {
                    if (-not $ReportOnly -and $PSCmdlet.ShouldProcess($entry.Label, "Create policy")) {
                        $url = "$baseUrl`?api-version=7.1"
                        Invoke-AzureDevOpsApi -Uri $url -Method Post -Body $entry.Config -AuthHeader $authHeader | Out-Null
                        Write-Host "  ✓ Created: $($entry.Label)" -ForegroundColor Green
                        $applied++
                    } else {
                        Write-Host "  ℹ  Not configured: $($entry.Label)" -ForegroundColor Yellow
                    }
                }
            }
        }

        $results["Project Policies"] = if ($ReportOnly) { "Reported (no changes)" } else { "Applied ($applied created/updated)" }
    }
    catch {
        Write-Warning "Project-level policy step failed: $_"
        $results["Project Policies"] = "Failed: $_"
    }
}

# ─────────────────────────────────────────────────────────────
# Step 6 — Variable Group Library Security
# ─────────────────────────────────────────────────────────────
Write-StepHeader "Step 6 of 8 — Variable Group Library Security"

if ($SkipLibrarySecurity) {
    Write-Host "  Skipped." -ForegroundColor Gray
    $results["Library Security"] = "Skipped"
} else {
    try {
        . "$scriptRoot\_Helpers.ps1"
        $authHeader = Get-AzureDevOpsAuthHeader

        # Library security namespace
        $libraryNamespaceId = "b7e84409-6553-448a-bbb2-af228e07cbeb"
        # Permission bits: ViewLibraryItem=1, AdministerLibraryItem=2, CreateLibraryItem=4,
        #                  DeleteLibraryItem=8, ManageLibraryPermissions=16, UseLibraryItem=32
        $allowViewOnly = 1    # View(1) only — broader groups must not Use, Create, or Administer
        $denyElevated  = 62   # Administer(2) + Create(4) + Delete(8) + ManagePermissions(16) + Use(32)

        # Get project ID
        $projectUrl     = "https://dev.azure.com/$Organization/_apis/projects/$Project`?api-version=7.1"
        $projectDetails = Invoke-AzureDevOpsApi -Uri $projectUrl -AuthHeader $authHeader
        $projectId      = $projectDetails.id
        $libraryToken   = "Library/$projectId"   # Forward slash — ADO Library namespace token format

        # Resolve identity descriptors for the two groups
        $groupsToRestrict = @(
            "[$Project]\Contributors",
            "[$Project]\Build Administrators"
        )

        $aces = @()
        foreach ($groupName in $groupsToRestrict) {
            $identityUrl = "https://vssps.dev.azure.com/$Organization/_apis/identities?searchFilter=General&filterValue=$([Uri]::EscapeDataString($groupName))&queryMembership=None&api-version=7.1-preview.1"
            $identityResult = Invoke-AzureDevOpsApi -Uri $identityUrl -AuthHeader $authHeader
            $identity = $identityResult.value | Select-Object -First 1
            if (-not $identity) {
                Write-Warning "  Could not resolve identity for '$groupName' — skipping"
                continue
            }
            Write-Host "  ℹ  $groupName → $($identity.subjectDescriptor)" -ForegroundColor Gray
            $aces += @{
                descriptor = $identity.descriptor
                allow      = $allowViewOnly
                deny       = $denyElevated
            }
        }

        if ($aces.Count -gt 0) {
            $aclBody = @{
                token                = $libraryToken
                merge                = $false
                accessControlEntries = $aces
            }

            if (-not $ReportOnly -and $PSCmdlet.ShouldProcess("Library security — $Project", "Restrict Contributors and Build Administrators")) {
                $aclUrl = "https://dev.azure.com/$Organization/_apis/accesscontrolentries/$libraryNamespaceId`?api-version=7.1"
                Invoke-AzureDevOpsApi -Uri $aclUrl -Method Post -Body $aclBody -AuthHeader $authHeader | Out-Null
                Write-Host "  ✓ Contributors and Build Administrators restricted to View only on Library" -ForegroundColor Green
                $results["Library Security"] = "Applied"
            } else {
                Write-Host "  ℹ  Would restrict Contributors and Build Administrators to View only on Library" -ForegroundColor Yellow
                $results["Library Security"] = if ($ReportOnly) { "Reported (no changes)" } else { "Skipped (WhatIf)" }
            }
        } else {
            Write-Host "  ℹ  No groups to restrict." -ForegroundColor Gray
            $results["Library Security"] = "No action needed"
        }
    }
    catch {
        Write-Warning "Library security step failed: $_"
        $results["Library Security"] = "Failed: $_"
    }
}

# ─────────────────────────────────────────────────────────────
# Step 7 — Agent Pool Auto-Provisioning
# ─────────────────────────────────────────────────────────────
Write-StepHeader "Step 7 of 8 — Agent Pool Auto-Provisioning"

if ($SkipPoolAutoProvision) {
    Write-Host "  Skipped." -ForegroundColor Gray
    $results["Pool Auto-Provision"] = "Skipped"
} else {
    try {
        . "$scriptRoot\_Helpers.ps1"
        $authHeader = Get-AzureDevOpsAuthHeader

        # List agent queues visible to this project
        $queuesUrl = "https://dev.azure.com/$Organization/$Project/_apis/distributedtask/queues?api-version=7.1"
        $queues    = (Invoke-AzureDevOpsApi -Uri $queuesUrl -AuthHeader $authHeader).value

        if (-not $queues -or $queues.Count -eq 0) {
            Write-Host "  No agent queues found in this project." -ForegroundColor Gray
            $results["Pool Auto-Provision"] = "No queues found"
        } else {
            $flagged = 0
            $disabled = 0

            foreach ($queue in $queues) {
                # Skip Microsoft-hosted pools (isHosted = true)
                if ($queue.pool.isHosted) { continue }

                $poolUrl     = "https://dev.azure.com/$Organization/_apis/distributedtask/pools/$($queue.pool.id)?api-version=7.1"
                $poolDetails = Invoke-AzureDevOpsApi -Uri $poolUrl -AuthHeader $authHeader

                if ($poolDetails.autoProvision -eq $true) {
                    $flagged++
                    Write-Host "  ⚠️  Pool '$($poolDetails.name)' has autoProvision enabled" -ForegroundColor Yellow

                    if (-not $ReportOnly -and $PSCmdlet.ShouldProcess("Pool '$($poolDetails.name)'", "Disable autoProvision")) {
                        try {
                            $patchUrl  = "https://dev.azure.com/$Organization/_apis/distributedtask/pools/$($poolDetails.id)?api-version=7.1"
                            $patchBody = @{ autoProvision = $false }
                            Invoke-AzureDevOpsApi -Uri $patchUrl -Method Patch -Body $patchBody -AuthHeader $authHeader | Out-Null
                            Write-Host "  ✓ Disabled autoProvision on pool '$($poolDetails.name)'" -ForegroundColor Green
                            $disabled++
                        }
                        catch {
                            Write-Warning "  Could not disable autoProvision on '$($poolDetails.name)' (requires Manage pool at org level): $_"
                        }
                    } else {
                        Write-Host "  ℹ  Would disable autoProvision on '$($poolDetails.name)'" -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "  ✓ Pool '$($poolDetails.name)' — autoProvision already disabled" -ForegroundColor Green
                }
            }

            if ($flagged -eq 0) {
                Write-Host "  ✓ No self-hosted pools with autoProvision enabled." -ForegroundColor Green
            }

            $results["Pool Auto-Provision"] = if ($ReportOnly) {
                "Reported ($flagged pool(s) with autoProvision enabled)"
            } else {
                "Applied ($disabled of $flagged pool(s) updated)"
            }
        }
    }
    catch {
        Write-Warning "Pool auto-provision step failed: $_"
        $results["Pool Auto-Provision"] = "Failed: $_"
    }
}

# ─────────────────────────────────────────────────────────────
# Step 8 — Build Pipeline Security
# ─────────────────────────────────────────────────────────────
Write-StepHeader "Step 8 of 10 — Build Pipeline Security"

if ($SkipBuildSecurity) {
    Write-Host "  Skipped." -ForegroundColor Gray
    $results["Build Pipeline Security"] = "Skipped"
} else {
    try {
        . "$scriptRoot\_Helpers.ps1"
        $authHeader = Get-AzureDevOpsAuthHeader

        # Build security namespace
        $buildNamespaceId = "33344d9c-fc72-4d6f-aba5-fa317101a7e9"
        # Permission bits: ViewBuilds=1, EditBuildQuality=2, RetainIndefinitely=4, DeleteBuilds=8,
        #                  ManageBuildQualities=16, DestroyBuilds=32, UpdateBuildInformation=64,
        #                  QueueBuilds=128, ManageBuildQueue=256, StopBuilds=512,
        #                  ViewBuildDefinition=1024, EditBuildDefinition=2048,
        #                  DeleteBuildDefinition=4096, OverrideBuildCheckInValidation=8192,
        #                  AdministerBuildPermissions=16384
        $allowViewOnly   = 1025   # ViewBuilds(1) + ViewBuildDefinition(1024)
        $denyElevated    = 31742  # All non-view bits: 2+4+8+16+32+64+128+256+512+2048+4096+8192+16384

        # Get project ID (reuse from earlier if available, else re-fetch)
        $projectUrl     = "https://dev.azure.com/$Organization/_apis/projects/$Project`?api-version=7.1"
        $projectDetails = Invoke-AzureDevOpsApi -Uri $projectUrl -AuthHeader $authHeader
        $projectId      = $projectDetails.id
        $buildToken     = $projectId   # Build namespace token is just the project ID

        # Resolve identity descriptors for the two groups
        $groupsToRestrict = @(
            "[$Project]\Contributors",
            "[$Project]\Build Administrators"
        )

        $aces = @()
        foreach ($groupName in $groupsToRestrict) {
            $identityUrl = "https://vssps.dev.azure.com/$Organization/_apis/identities?searchFilter=General&filterValue=$([Uri]::EscapeDataString($groupName))&queryMembership=None&api-version=7.1-preview.1"
            $identityResult = Invoke-AzureDevOpsApi -Uri $identityUrl -AuthHeader $authHeader
            $identity = $identityResult.value | Select-Object -First 1
            if (-not $identity) {
                Write-Warning "  Could not resolve identity for '$groupName' — skipping"
                continue
            }
            Write-Host "  ℹ  $groupName → $($identity.subjectDescriptor)" -ForegroundColor Gray
            $aces += @{
                descriptor = $identity.descriptor
                allow      = $allowViewOnly
                deny       = $denyElevated
            }
        }

        if ($aces.Count -gt 0) {
            $aclBody = @{
                token                = $buildToken
                merge                = $false
                accessControlEntries = $aces
            }

            if (-not $ReportOnly -and $PSCmdlet.ShouldProcess("Build pipeline security — $Project", "Restrict Contributors and Build Administrators")) {
                $aclUrl = "https://dev.azure.com/$Organization/_apis/accesscontrolentries/$buildNamespaceId`?api-version=7.1"
                Invoke-AzureDevOpsApi -Uri $aclUrl -Method Post -Body $aclBody -AuthHeader $authHeader | Out-Null
                Write-Host "  ✓ Contributors and Build Administrators restricted to View only on Build pipelines" -ForegroundColor Green
                $results["Build Pipeline Security"] = "Applied"
            } else {
                Write-Host "  ℹ  Would restrict Contributors and Build Administrators to View only on Build pipelines" -ForegroundColor Yellow
                $results["Build Pipeline Security"] = if ($ReportOnly) { "Reported (no changes)" } else { "Skipped (WhatIf)" }
            }
        } else {
            Write-Host "  ℹ  No groups to restrict." -ForegroundColor Gray
            $results["Build Pipeline Security"] = "No action needed"
        }
    }
    catch {
        Write-Warning "Build pipeline security step failed: $_"
        $results["Build Pipeline Security"] = "Failed: $_"
    }
}

# ─────────────────────────────────────────────────────────────
# Step 9 — Repository ACL Security
# ─────────────────────────────────────────────────────────────
Write-StepHeader "Step 9 of 10 — Repository ACL Security"

if ($SkipRepositoryAcl) {
    Write-Host "  Skipped." -ForegroundColor Gray
    $results["Repository ACL Security"] = "Skipped"
} else {
    try {
        . "$scriptRoot\_Helpers.ps1"
        $authHeader = Get-AzureDevOpsAuthHeader

        # Git Repositories security namespace
        $repoNamespaceId = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87"
        # Permission bits: GenericRead(Read)=2, GenericContribute=4, ForcePush=8,
        #   CreateBranch=16, CreateTag=32, ManageNote=64, PolicyExempt(bypass push)=128,
        #   RemoveOthersLocks=4096, PullRequestContribute=16384, PullRequestBypassPolicy=32768
        $allowRead    = 2      # Read only
        $denyElevated = 20604  # GenericContribute(4)+ForcePush(8)+CreateBranch(16)+CreateTag(32)+
                               # ManageNote(64)+RemoveOthersLocks(4096)+PullRequestContribute(16384)
                               # NOTE: PolicyExempt(128) and PullRequestBypassPolicy(32768) are
                               # intentionally excluded — denying them blocks Project Administrators
                               # who are also in the Contributors group from bypassing policies.

        # Get project ID
        $projectUrl     = "https://dev.azure.com/$Organization/_apis/projects/$Project`?api-version=7.1"
        $projectDetails = Invoke-AzureDevOpsApi -Uri $projectUrl -AuthHeader $authHeader
        $projectId      = $projectDetails.id
        $repoToken      = "repoV2/$projectId"   # Project-level Git Repositories token

        $groupsToRestrict = @(
            "[$Project]\Contributors",
            "[$Project]\Build Administrators"
        )

        $aces = @()
        foreach ($groupName in $groupsToRestrict) {
            $identityUrl = "https://vssps.dev.azure.com/$Organization/_apis/identities?searchFilter=General&filterValue=$([Uri]::EscapeDataString($groupName))&queryMembership=None&api-version=7.1-preview.1"
            $identityResult = Invoke-AzureDevOpsApi -Uri $identityUrl -AuthHeader $authHeader
            $identity = $identityResult.value | Select-Object -First 1
            if (-not $identity) {
                Write-Warning "  Could not resolve identity for '$groupName' — skipping"
                continue
            }
            Write-Host "  ℹ  $groupName → $($identity.subjectDescriptor)" -ForegroundColor Gray
            $aces += @{
                descriptor = $identity.descriptor
                allow      = $allowRead
                deny       = $denyElevated
            }
        }

        if ($aces.Count -gt 0) {
            $aclBody = @{
                token                = $repoToken
                merge                = $false
                accessControlEntries = $aces
            }

            if (-not $ReportOnly -and $PSCmdlet.ShouldProcess("Repository ACL — $Project", "Restrict Contributors and Build Administrators to Read only")) {
                $aclUrl = "https://dev.azure.com/$Organization/_apis/accesscontrolentries/$repoNamespaceId`?api-version=7.1"
                Invoke-AzureDevOpsApi -Uri $aclUrl -Method Post -Body $aclBody -AuthHeader $authHeader | Out-Null
                Write-Host "  ✓ Contributors and Build Administrators restricted to Read only on Repositories" -ForegroundColor Green
                $results["Repository ACL Security"] = "Applied"
            } else {
                Write-Host "  ℹ  Would restrict Contributors and Build Administrators to Read only on Repositories" -ForegroundColor Yellow
                $results["Repository ACL Security"] = if ($ReportOnly) { "Reported (no changes)" } else { "Skipped (WhatIf)" }
            }
        } else {
            Write-Host "  ℹ  No groups to restrict." -ForegroundColor Gray
            $results["Repository ACL Security"] = "No action needed"
        }
    }
    catch {
        Write-Warning "Repository ACL security step failed: $_"
        $results["Repository ACL Security"] = "Failed: $_"
    }
}

# ─────────────────────────────────────────────────────────────
# Step 10 — Release Pipeline Security
# ─────────────────────────────────────────────────────────────
Write-StepHeader "Step 10 of 10 — Release Pipeline Security"

if ($SkipReleasePipelineSecurity) {
    Write-Host "  Skipped." -ForegroundColor Gray
    $results["Release Pipeline Security"] = "Skipped"
} else {
    try {
        . "$scriptRoot\_Helpers.ps1"
        $authHeader = Get-AzureDevOpsAuthHeader

        # Release Management security namespace
        $releaseNamespaceId = "c788c23e-1b46-4162-8f5e-d7585343b5de"
        # Permission bits: ViewReleases=1, EditReleaseDefinition=2, DeleteReleaseDefinition=4,
        #   ManageReleaseApprovals=8, CreateReleases=64, EditReleaseEnvironment=128,
        #   DeleteReleaseEnvironment=256, AdministerDeployments=512, ViewReleaseDefinition=1024,
        #   DeleteReleases=2048, ManageDeployments=4096
        $allowView    = 1025   # ViewReleases(1) + ViewReleaseDefinition(1024)
        $denyElevated = 64510  # All 16 permission bits except ViewReleases(1) and ViewReleaseDefinition(1024)
                               # Broad mask avoids relying on undocumented bit positions for individual actions

        # Get project ID
        $projectUrl     = "https://dev.azure.com/$Organization/_apis/projects/$Project`?api-version=7.1"
        $projectDetails = Invoke-AzureDevOpsApi -Uri $projectUrl -AuthHeader $authHeader
        $projectId      = $projectDetails.id
        $releaseToken   = $projectId   # Project-level Release Management token

        $groupsToRestrict = @(
            "[$Project]\Contributors"
        )

        $aces = @()
        foreach ($groupName in $groupsToRestrict) {
            $identityUrl = "https://vssps.dev.azure.com/$Organization/_apis/identities?searchFilter=General&filterValue=$([Uri]::EscapeDataString($groupName))&queryMembership=None&api-version=7.1-preview.1"
            $identityResult = Invoke-AzureDevOpsApi -Uri $identityUrl -AuthHeader $authHeader
            $identity = $identityResult.value | Select-Object -First 1
            if (-not $identity) {
                Write-Warning "  Could not resolve identity for '$groupName' — skipping"
                continue
            }
            Write-Host "  ℹ  $groupName → $($identity.subjectDescriptor)" -ForegroundColor Gray
            $aces += @{
                descriptor = $identity.descriptor
                allow      = $allowView
                deny       = $denyElevated
            }
        }

        if ($aces.Count -gt 0) {
            $aclBody = @{
                token                = $releaseToken
                merge                = $false
                accessControlEntries = $aces
            }

            if (-not $ReportOnly -and $PSCmdlet.ShouldProcess("Release pipeline security — $Project", "Restrict Contributors to View only")) {
                $aclUrl = "https://dev.azure.com/$Organization/_apis/accesscontrolentries/$releaseNamespaceId`?api-version=7.1"
                Invoke-AzureDevOpsApi -Uri $aclUrl -Method Post -Body $aclBody -AuthHeader $authHeader | Out-Null
                Write-Host "  ✓ Contributors restricted to View only on Release pipelines" -ForegroundColor Green
                $results["Release Pipeline Security"] = "Applied"
            } else {
                Write-Host "  ℹ  Would restrict Contributors to View only on Release pipelines" -ForegroundColor Yellow
                $results["Release Pipeline Security"] = if ($ReportOnly) { "Reported (no changes)" } else { "Skipped (WhatIf)" }
            }
        } else {
            Write-Host "  ℹ  No groups to restrict." -ForegroundColor Gray
            $results["Release Pipeline Security"] = "No action needed"
        }
    }
    catch {
        Write-Warning "Release pipeline security step failed: $_"
        $results["Release Pipeline Security"] = "Failed: $_"
    }
}

# ─────────────────────────────────────────────────────────────
# Final Summary
# ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host "  Hardening Summary — $Organization/$Project" -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host ""

foreach ($step in $results.Keys) {
    $value   = $results[$step]
    $failed  = $value -like "Failed*"
    $skipped = $value -eq "Skipped"
    $color   = if ($failed) { "Red" } elseif ($skipped) { "Gray" } else { "Green" }
    $icon    = if ($failed) { "✗" } elseif ($skipped) { "–" } else { "✓" }
    Write-Host "  $icon  $step" -ForegroundColor $color
    Write-Host "     $value" -ForegroundColor $color
    Write-Host ""
}

if ($ReportOnly) {
    Write-Host "Report-only run complete. Re-run without -ReportOnly to apply changes." -ForegroundColor Yellow
} else {
    Write-Host "Hardening complete." -ForegroundColor Green
}
Write-Host ""
