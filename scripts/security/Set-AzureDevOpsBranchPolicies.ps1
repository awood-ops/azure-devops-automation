<#
.SYNOPSIS
    Configures branch protection policies on an Azure DevOps repository branch.

.DESCRIPTION
    This script applies the recommended security policies to a branch, including:
    - Minimum number of reviewers (with optional self-approval prohibition)
    - Require all comments to be resolved before merge
    - Merge strategy restrictions (squash / rebase only, block basic merge commits)
    - Build validation (require a pipeline to pass before merge)
    - Required reviewers (auto-include specific team members on every PR)

    Key Features:
    - Fetches policy type IDs dynamically — no hardcoded GUIDs
    - Idempotent — updates existing policies rather than creating duplicates
    - Each policy type is individually enabled/disabled via parameters
    - Supports ShouldProcess (-WhatIf)

.PARAMETER Organization
    Azure DevOps organization name (e.g. "myorg" from dev.azure.com/myorg)

.PARAMETER Project
    Azure DevOps project name

.PARAMETER RepositoryName
    Name of the repository to protect

.PARAMETER Branch
    Branch to apply policies to. Default: "main"

.PARAMETER MinimumReviewerCount
    Minimum number of reviewers required to approve a PR. Default: 2

.PARAMETER ProhibitSelfApproval
    Prevent the PR creator from approving their own changes. Default: $true

.PARAMETER ResetVotesOnPush
    Reset all approval votes when new commits are pushed. Default: $true

.PARAMETER RequireResolvedComments
    Block merge until all PR comments are resolved. Default: $true

.PARAMETER AllowSquash
    Allow squash merge. Default: $true

.PARAMETER AllowRebase
    Allow rebase merge. Default: $false

.PARAMETER AllowNoFastForward
    Allow basic (no fast-forward) merge commits. Default: $false
    Recommended: leave as $false to enforce a clean linear or squash-only history.

.PARAMETER BuildPipelineId
    Pipeline definition ID to use for build validation. Optional.
    The PR must pass this pipeline before merge is allowed.

.PARAMETER BuildDisplayName
    Display label for the build validation policy. Default: "PR Validation"

.PARAMETER RequiredReviewerEmails
    One or more email addresses (UPNs) to automatically add as required reviewers
    on every PR targeting this branch. Optional.

.PARAMETER Force
    Skips confirmation prompts

.EXAMPLE
    # Apply recommended baseline policies to main
    .\Set-AzureDevOpsBranchPolicies.ps1 `
        -Organization "myorg" `
        -Project "MyProject" `
        -RepositoryName "MyRepo"

.EXAMPLE
    # Best practice — all security controls enabled
    # MinimumReviewerCount 2  : one reviewer can be pressured; two is a meaningful check
    # ProhibitSelfApproval    : prevents "approve my own hotfix" bypass
    # ResetVotesOnPush        : forces re-review after new commits — approvals don't carry over
    # RequireResolvedComments : security feedback can't be dismissed by merging anyway
    # AllowSquash only        : clean linear history, easier to audit and revert
    # AllowRebase $false      : rebase rewrites history, making audit trails unreliable
    # AllowNoFastForward $false: blocks direct merge commits that bypass the review record
    # RequiredReviewerEmails  : guarantees the right eyes on every PR — cannot be skipped
    # Note: add -BuildPipelineId <id> if you have a CI pipeline — strongly recommended
    .\Set-AzureDevOpsBranchPolicies.ps1 `
        -Organization "myorg" `
        -Project "MyProject" `
        -RepositoryName "MyRepo" `
        -Branch "main" `
        -MinimumReviewerCount 2 `
        -ProhibitSelfApproval $true `
        -ResetVotesOnPush $true `
        -RequireResolvedComments $true `
        -AllowSquash $true `
        -AllowRebase $false `
        -AllowNoFastForward $false `
        -RequiredReviewerEmails "tech.lead@company.com","security@company.com" `
        -Force

.EXAMPLE
    # Preview what would change without applying
    .\Set-AzureDevOpsBranchPolicies.ps1 `
        -Organization "myorg" `
        -Project "MyProject" `
        -RepositoryName "MyRepo" `
        -WhatIf

.NOTES
    Author: Andrew Wood
    Version: 1.0

    Prerequisites:
    - Azure DevOps login: Connect-AzAccount, AZURE_DEVOPS_EXT_PAT, or az devops login
    - Permissions: Project Administrator or higher on the target project

    API References:
    - Policy Configurations: https://learn.microsoft.com/en-us/rest/api/azure/devops/policy/configurations
    - Policy Types: https://learn.microsoft.com/en-us/rest/api/azure/devops/policy/types

.LINK
    https://learn.microsoft.com/en-us/azure/devops/repos/git/branch-policies
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string]$Organization,

    [Parameter(Mandatory = $true)]
    [string]$Project,

    [Parameter(Mandatory = $true)]
    [string]$RepositoryName,

    [Parameter(Mandatory = $false)]
    [string]$Branch = "main",

    [Parameter(Mandatory = $false)]
    [int]$MinimumReviewerCount = 2,

    [Parameter(Mandatory = $false)]
    [bool]$ProhibitSelfApproval = $true,

    [Parameter(Mandatory = $false)]
    [bool]$ResetVotesOnPush = $true,

    [Parameter(Mandatory = $false)]
    [bool]$RequireResolvedComments = $true,

    [Parameter(Mandatory = $false)]
    [bool]$AllowSquash = $true,

    [Parameter(Mandatory = $false)]
    [bool]$AllowRebase = $false,

    [Parameter(Mandatory = $false)]
    [bool]$AllowNoFastForward = $false,

    [Parameter(Mandatory = $false)]
    [int]$BuildPipelineId = 0,

    [Parameter(Mandatory = $false)]
    [string]$BuildDisplayName = "PR Validation",

    [Parameter(Mandatory = $false)]
    [string[]]$RequiredReviewerEmails = @(),

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "=== Azure DevOps Branch Policy Configuration ===" -ForegroundColor Cyan
Write-Host ""

. "$PSScriptRoot\_Helpers.ps1"

function Set-PolicyConfiguration {
    <#
    .SYNOPSIS
        Creates or updates a single policy configuration, avoiding duplicates.
    #>
    param(
        [string]$Organization,
        [string]$Project,
        [string]$AuthHeader,
        [object]$PolicyConfig,
        [object[]]$ExistingPolicies,
        [string]$PolicyLabel
    )

    $typeId = $PolicyConfig.type.id
    $repoId = $PolicyConfig.settings.scope[0].repositoryId
    $refName = $PolicyConfig.settings.scope[0].refName

    # Find an existing policy of this type targeting the same repo and branch
    $existing = $ExistingPolicies | Where-Object {
        $_.type.id -eq $typeId -and
        $_.settings.scope -and
        ($_.settings.scope | Where-Object { $_.repositoryId -eq $repoId -and $_.refName -eq $refName })
    } | Select-Object -First 1

    $baseUrl = "https://dev.azure.com/$Organization/$Project/_apis/policy/configurations"

    if ($existing) {
        $PolicyConfig | Add-Member -NotePropertyName "id" -NotePropertyValue $existing.id -Force
        $url = "$baseUrl/$($existing.id)?api-version=7.1"
        if ($PSCmdlet.ShouldProcess("$PolicyLabel (id: $($existing.id))", "Update branch policy")) {
            Invoke-AzureDevOpsApi -Uri $url -Method Put -Body $PolicyConfig -AuthHeader $AuthHeader | Out-Null
            Write-Host "  ✓ Updated: $PolicyLabel" -ForegroundColor Green
        }
    }
    else {
        $url = "$baseUrl`?api-version=7.1"
        if ($PSCmdlet.ShouldProcess($PolicyLabel, "Create branch policy")) {
            Invoke-AzureDevOpsApi -Uri $url -Method Post -Body $PolicyConfig -AuthHeader $AuthHeader | Out-Null
            Write-Host "  ✓ Created: $PolicyLabel" -ForegroundColor Green
        }
    }
}

#endregion

# Confirm operation
if (-not $Force -and -not $WhatIfPreference) {
    Write-Host "`n⚠️  This will apply branch policies with the following settings:" -ForegroundColor Yellow
    Write-Host "   - Organization:           $Organization" -ForegroundColor Gray
    Write-Host "   - Project:                $Project" -ForegroundColor Gray
    Write-Host "   - Repository:             $RepositoryName" -ForegroundColor Gray
    Write-Host "   - Branch:                 $Branch" -ForegroundColor Gray
    Write-Host "   - Min. reviewers:         $MinimumReviewerCount" -ForegroundColor Gray
    Write-Host "   - Prohibit self-approval: $ProhibitSelfApproval" -ForegroundColor Gray
    Write-Host "   - Reset votes on push:    $ResetVotesOnPush" -ForegroundColor Gray
    Write-Host "   - Require resolved comments: $RequireResolvedComments" -ForegroundColor Gray
    Write-Host "   - Allow squash:           $AllowSquash" -ForegroundColor Gray
    Write-Host "   - Allow rebase:           $AllowRebase" -ForegroundColor Gray
    Write-Host "   - Allow no-fast-forward:  $AllowNoFastForward" -ForegroundColor Gray
    if ($BuildPipelineId -gt 0) {
        Write-Host "   - Build validation:       Pipeline $BuildPipelineId ($BuildDisplayName)" -ForegroundColor Gray
    }
    if ($RequiredReviewerEmails.Count -gt 0) {
        Write-Host "   - Required reviewers:     $($RequiredReviewerEmails -join ', ')" -ForegroundColor Gray
    }
    $confirmation = Read-Host "`nContinue? (yes/no)"
    if ($confirmation -ne "yes") {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        exit 0
    }
}

# Authenticate
Write-Host "[1/5] Authenticating to Azure DevOps..." -ForegroundColor Yellow
try {
    $authHeader = Get-AzureDevOpsAuthHeader
    Write-Host "✓ Successfully authenticated" -ForegroundColor Green
}
catch {
    Write-Error "Failed to authenticate: $_"
    exit 1
}

# Resolve repository ID
Write-Host "`n[2/5] Resolving repository..." -ForegroundColor Yellow
try {
    $repoUrl = "https://dev.azure.com/$Organization/$Project/_apis/git/repositories/$RepositoryName`?api-version=7.1"
    $repo = Invoke-AzureDevOpsApi -Uri $repoUrl -AuthHeader $authHeader
    $repoId = $repo.id
    Write-Host "✓ Repository found: $RepositoryName (id: $repoId)" -ForegroundColor Green
}
catch {
    Write-Error "Repository '$RepositoryName' not found in project '$Project': $_"
    exit 1
}

# Fetch policy types dynamically to avoid hardcoded GUIDs
Write-Host "`n[3/5] Fetching policy types..." -ForegroundColor Yellow
try {
    $typesUrl = "https://dev.azure.com/$Organization/$Project/_apis/policy/types?api-version=7.1"
    $policyTypes = Invoke-AzureDevOpsApi -Uri $typesUrl -AuthHeader $authHeader

    $typeMap = @{}
    foreach ($pt in $policyTypes.value) {
        $typeMap[$pt.displayName] = $pt.id
    }

    $typeMinReviewers       = $typeMap["Minimum number of reviewers"]
    $typeCommentRequirements = $typeMap["Comment requirements"]
    $typeMergeStrategy      = $typeMap["Require a merge strategy"]
    $typeBuildValidation    = $typeMap["Build"]
    $typeRequiredReviewers  = $typeMap["Required reviewers"]

    Write-Host "✓ Policy types loaded ($($policyTypes.value.Count) types available)" -ForegroundColor Green
    Write-Host "  Min. reviewers type ID:  $typeMinReviewers" -ForegroundColor Gray
    Write-Host "  Comment requirements ID: $typeCommentRequirements" -ForegroundColor Gray
    Write-Host "  Merge strategy ID:       $typeMergeStrategy" -ForegroundColor Gray
}
catch {
    Write-Error "Failed to fetch policy types: $_"
    exit 1
}

# Load existing policy configurations for this project
Write-Host "`n[4/5] Loading existing policies..." -ForegroundColor Yellow
try {
    $policiesUrl = "https://dev.azure.com/$Organization/$Project/_apis/policy/configurations?api-version=7.1"
    $existingPolicies = (Invoke-AzureDevOpsApi -Uri $policiesUrl -AuthHeader $authHeader).value
    Write-Host "✓ Found $($existingPolicies.Count) existing policy configurations" -ForegroundColor Green
}
catch {
    Write-Error "Failed to load existing policies: $_"
    exit 1
}

# Build the branch scope object used in every policy
$branchScope = @(
    @{
        repositoryId = $repoId
        refName      = "refs/heads/$Branch"
        matchKind    = "Exact"
    }
)

# Apply policies
Write-Host "`n[5/5] Applying branch policies..." -ForegroundColor Yellow

# --- Minimum reviewers ---
if ($typeMinReviewers) {
    $minReviewersPolicy = @{
        isEnabled  = $true
        isBlocking = $true
        type       = @{ id = $typeMinReviewers }
        settings   = @{
            minimumApproverCount         = $MinimumReviewerCount
            creatorVoteCounts            = (-not $ProhibitSelfApproval)  # false = creator cannot self-approve
            allowDownvotes               = $false
            resetOnSourcePush            = $ResetVotesOnPush
            requireVoteOnLastIteration   = $false
            resetRejectionsOnSourceUpdate = $false
            scope                        = $branchScope
        }
    }
    Set-PolicyConfiguration -Organization $Organization -Project $Project -AuthHeader $authHeader `
        -PolicyConfig $minReviewersPolicy -ExistingPolicies $existingPolicies `
        -PolicyLabel "Minimum reviewers ($MinimumReviewerCount)"
}
else {
    Write-Warning "Could not find 'Minimum number of reviewers' policy type — skipping"
}

# --- Comment requirements ---
if ($RequireResolvedComments -and $typeCommentRequirements) {
    $commentPolicy = @{
        isEnabled  = $true
        isBlocking = $true
        type       = @{ id = $typeCommentRequirements }
        settings   = @{ scope = $branchScope }
    }
    Set-PolicyConfiguration -Organization $Organization -Project $Project -AuthHeader $authHeader `
        -PolicyConfig $commentPolicy -ExistingPolicies $existingPolicies `
        -PolicyLabel "Comment requirements"
}
elseif ($RequireResolvedComments) {
    Write-Warning "Could not find 'Comment requirements' policy type — skipping"
}

# --- Merge strategy ---
if ($typeMergeStrategy) {
    $mergePolicy = @{
        isEnabled  = $true
        isBlocking = $true
        type       = @{ id = $typeMergeStrategy }
        settings   = @{
            allowSquash        = $AllowSquash
            allowNoFastForward = $AllowNoFastForward
            allowRebase        = $AllowRebase
            allowRebaseMerge   = $false  # rebase + merge commit — always blocked for clean history
            scope              = $branchScope
        }
    }
    Set-PolicyConfiguration -Organization $Organization -Project $Project -AuthHeader $authHeader `
        -PolicyConfig $mergePolicy -ExistingPolicies $existingPolicies `
        -PolicyLabel "Merge strategy (squash: $AllowSquash, rebase: $AllowRebase, no-ff: $AllowNoFastForward)"
}
else {
    Write-Warning "Could not find 'Require a merge strategy' policy type — skipping"
}

# --- Build validation ---
if ($BuildPipelineId -gt 0) {
    if ($typeBuildValidation) {
        $buildPolicy = @{
            isEnabled  = $true
            isBlocking = $true
            type       = @{ id = $typeBuildValidation }
            settings   = @{
                buildDefinitionId      = $BuildPipelineId
                queueOnSourceUpdateOnly = $true
                manualQueueOnly        = $false
                displayName            = $BuildDisplayName
                validDuration          = 720  # 12 hours in minutes
                scope                  = $branchScope
            }
        }
        Set-PolicyConfiguration -Organization $Organization -Project $Project -AuthHeader $authHeader `
            -PolicyConfig $buildPolicy -ExistingPolicies $existingPolicies `
            -PolicyLabel "Build validation (pipeline: $BuildPipelineId)"
    }
    else {
        Write-Warning "Could not find 'Build' policy type — skipping build validation"
    }
}

# --- Required reviewers ---
if ($RequiredReviewerEmails.Count -gt 0) {
    if ($typeRequiredReviewers) {
        # Resolve each email to an Azure DevOps identity ID
        $reviewerIds = @()
        foreach ($email in $RequiredReviewerEmails) {
            try {
                $identityUrl = "https://vssps.dev.azure.com/$Organization/_apis/identities?searchFilter=MailAddress&filterValue=$email&api-version=7.1-preview.1"
                $identityResult = Invoke-AzureDevOpsApi -Uri $identityUrl -AuthHeader $authHeader
                $identity = $identityResult.value | Select-Object -First 1
                if ($identity) {
                    $reviewerIds += $identity.id
                    Write-Host "  ✓ Resolved reviewer: $email → $($identity.id)" -ForegroundColor Gray
                }
                else {
                    Write-Warning "Could not resolve identity for '$email' — skipping this reviewer"
                }
            }
            catch {
                Write-Warning "Failed to resolve identity for '$email': $_"
            }
        }

        if ($reviewerIds.Count -gt 0) {
            $requiredReviewersPolicy = @{
                isEnabled  = $true
                isBlocking = $true
                type       = @{ id = $typeRequiredReviewers }
                settings   = @{
                    requiredReviewerIds = $reviewerIds
                    message             = ""
                    scope               = $branchScope
                }
            }
            Set-PolicyConfiguration -Organization $Organization -Project $Project -AuthHeader $authHeader `
                -PolicyConfig $requiredReviewersPolicy -ExistingPolicies $existingPolicies `
                -PolicyLabel "Required reviewers ($($reviewerIds.Count) reviewer(s))"
        }
    }
    else {
        Write-Warning "Could not find 'Required reviewers' policy type — skipping"
    }
}

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Green
Write-Host "Branch policies applied to: $Organization/$Project — $RepositoryName/$Branch" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Verify policies in Azure DevOps: Repos → Branches → ... → Branch policies" -ForegroundColor Gray
Write-Host "  2. Ensure 'Bypass policies when pushing' is denied for Contributors in repo security" -ForegroundColor Gray
Write-Host "  3. Add build validation pipeline ID if not already specified (-BuildPipelineId)" -ForegroundColor Gray
Write-Host ""
