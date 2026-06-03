<#
.SYNOPSIS
    Adds or removes a member from any security group across one or more Azure DevOps projects.

.DESCRIPTION
    Complements Get-AzureDevOpsAudit.ps1 by providing a safe, scriptable way to
    modify security group membership. Supports both users (by email address) and groups
    (by display name, including Entra ID groups), and targets any named security group
    (defaults to Project Administrators for backward compatibility).

    Key Features:
    - Add or remove a user or group from any project security group
    - Remove from every group in a project at once with -AllGroups (ideal for offboarding)
    - Targets a single project or every project in the organisation
    - Skips projects where the member is already in (Add) or already absent (Remove)
    - Confirmation prompt before making changes — bypass with -Force or preview with -WhatIf
    - Safe — validates the member exists before attempting any changes

.PARAMETER Organization
    Azure DevOps organization name (e.g. "myorg" from dev.azure.com/myorg).

.PARAMETER Project
    One or more projects to modify. If omitted, the change is applied to ALL projects in
    the organisation. Pass multiple names as a comma-separated list or array.

.PARAMETER Group
    The security group to modify. Defaults to "Project Administrators".
    Use the group's display name exactly as it appears in Azure DevOps
    (e.g. "Contributors", "Readers", "Build Administrators").

.PARAMETER AllGroups
    When specified, removes the member from every group they belong to in the
    target project(s). Cannot be combined with -Group; requires -Action Remove.

.PARAMETER Action
    Whether to "Add" or "Remove" the member.

.PARAMETER Member
    The member to add or remove.
    - Supply an email address (UPN) for a user, e.g. "alice@example.com"
    - Supply a display name for a group, e.g. "Platform Engineers" or "[myorg]\Release Managers"

.PARAMETER Force
    Skips the confirmation prompt.

.EXAMPLE
    # Add a user to Project Administrators in one project (default group)
    .\Set-AzureDevOpsGroupMember.ps1 `
        -Organization "myorg" `
        -Project "MyProject" `
        -Action Add `
        -Member "alice@example.com"

.EXAMPLE
    # Remove a user from Project Administrators across ALL projects (no prompt)
    .\Set-AzureDevOpsGroupMember.ps1 `
        -Organization "myorg" `
        -Action Remove `
        -Member "bob@example.com" `
        -Force

.EXAMPLE
    # Add a user to Contributors in one project
    .\Set-AzureDevOpsGroupMember.ps1 `
        -Organization "myorg" `
        -Project "MyProject" `
        -Group "Contributors" `
        -Action Add `
        -Member "alice@example.com"

.EXAMPLE
    # Remove a user from Readers across multiple projects
    .\Set-AzureDevOpsGroupMember.ps1 `
        -Organization "myorg" `
        -Project "ProjectA","ProjectB" `
        -Group "Readers" `
        -Action Remove `
        -Member "bob@example.com" `
        -Force

.EXAMPLE
    # Remove a user from Contributors across ALL projects (offboarding)
    .\Set-AzureDevOpsGroupMember.ps1 `
        -Organization "myorg" `
        -Group "Contributors" `
        -Action Remove `
        -Member "bob@example.com" `
        -Force

.EXAMPLE
    # Preview adding an Entra ID group to Build Administrators
    .\Set-AzureDevOpsGroupMember.ps1 `
        -Organization "myorg" `
        -Project "MyProject" `
        -Group "Build Administrators" `
        -Action Add `
        -Member "Platform Engineers" `
        -WhatIf

.EXAMPLE
    # Add an Entra ID group to Project Administrators across multiple projects
    .\Set-AzureDevOpsGroupMember.ps1 `
        -Organization "myorg" `
        -Project "ProjectA","ProjectB","ProjectC" `
        -Action Add `
        -Member "Platform Engineers"

.EXAMPLE
    # Remove a user from ALL groups across ALL projects (full offboarding)
    .\Set-AzureDevOpsGroupMember.ps1 `
        -Organization "myorg" `
        -AllGroups `
        -Action Remove `
        -Member "jane.doe@example.com" `
        -Force

.NOTES
    Author: Andrew Wood
    Version: 1.0

    Prerequisites:
    - Azure DevOps login: Connect-AzAccount, AZURE_DEVOPS_EXT_PAT, or az devops login
    - Permissions: Project Administrator or Organisation Administrator

    API References:
    - Graph Memberships API: https://learn.microsoft.com/en-us/rest/api/azure/devops/graph/memberships
    - Identities API:        https://learn.microsoft.com/en-us/rest/api/azure/devops/ims/identities

.LINK
    https://learn.microsoft.com/en-us/azure/devops/organizations/security/permissions
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string]$Organization,

    [Parameter(Mandatory = $false)]
    [string[]]$Project,

    [Parameter(Mandatory = $false)]
    [string]$Group = "Project Administrators",

    [Parameter(Mandatory = $false)]
    [switch]$AllGroups,

    [Parameter(Mandatory = $true)]
    [ValidateSet("Add", "Remove")]
    [string]$Action,

    [Parameter(Mandatory = $true)]
    [string]$Member,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$ErrorActionPreference = "Stop"

if ($AllGroups -and $Action -ne "Remove") {
    Write-Error "-AllGroups can only be used with -Action Remove."
    exit 1
}

Write-Host "=== Azure DevOps Group Member Manager ===" -ForegroundColor Cyan
Write-Host ""

. "$PSScriptRoot\_Helpers.ps1"

function Test-IsMember {
    <#
    .SYNOPSIS
        Returns $true if SubjectDescriptor is a direct member of GroupDescriptor.
    #>
    param(
        [string]$Organization,
        [string]$SubjectDescriptor,
        [string]$GroupDescriptor,
        [string]$AuthHeader
    )

    try {
        $url = "https://vssps.dev.azure.com/$Organization/_apis/graph/memberships/$SubjectDescriptor" +
               "?direction=Up&api-version=7.1-preview.1"
        $memberships = Invoke-AzureDevOpsApi -Uri $url -AuthHeader $AuthHeader
        return ($memberships.value | Where-Object { $_.containerDescriptor -eq $GroupDescriptor }).Count -gt 0
    }
    catch {
        return $false
    }
}

# ─── [1/4] Authenticate ───────────────────────────────────────────────────────
Write-Host "[1/4] Authenticating to Azure DevOps..." -ForegroundColor Yellow
try {
    $authHeader = Get-AzureDevOpsAuthHeader
    Write-Host "✓ Authenticated" -ForegroundColor Green
}
catch {
    Write-Error "Failed to authenticate: $_"
    exit 1
}

# ─── [2/4] Resolve projects ───────────────────────────────────────────────────
Write-Host "`n[2/4] Resolving projects to modify..." -ForegroundColor Yellow
$projectsToModify = @()
try {
    if ($Project) {
        foreach ($proj in $Project) {
            $projectUrl = "https://dev.azure.com/$Organization/_apis/projects/$proj`?api-version=7.1"
            $projectsToModify += Invoke-AzureDevOpsApi -Uri $projectUrl -AuthHeader $authHeader
        }
        Write-Host "✓ Targeting $($projectsToModify.Count) project(s): $($Project -join ', ')" -ForegroundColor Green
    }
    else {
        $projectsUrl = "https://dev.azure.com/$Organization/_apis/projects?`$top=500&api-version=7.1"
        $projectsToModify = (Invoke-AzureDevOpsApi -Uri $projectsUrl -AuthHeader $authHeader).value
        Write-Host "✓ Targeting all $($projectsToModify.Count) projects in organisation" -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to resolve projects: $_"
    exit 1
}

# ─── [3/4] Resolve member ────────────────────────────────────────────────────
Write-Host "`n[3/4] Resolving member '$Member'..." -ForegroundColor Yellow

# Obtain a project scope descriptor to narrow group searches (uses first project)
$projectScopeDescriptor = $null
if ($projectsToModify.Count -gt 0) {
    try {
        $scopeUrl = "https://vssps.dev.azure.com/$Organization/_apis/graph/descriptors/$($projectsToModify[0].id)?api-version=7.1-preview.1"
        $projectScopeDescriptor = (Invoke-AzureDevOpsApi -Uri $scopeUrl -AuthHeader $authHeader).value
    }
    catch {
        Write-Verbose "Could not resolve project scope descriptor for group search narrowing: $_"
    }
}

try {
    $resolvedMember = Resolve-MemberDescriptor `
        -Organization          $Organization `
        -Member                $Member `
        -AuthHeader            $authHeader `
        -ProjectScopeDescriptor $projectScopeDescriptor

    Write-Host "✓ Resolved: $($resolvedMember.DisplayName) [$($resolvedMember.SubjectKind)]" -ForegroundColor Green
    Write-Verbose "  Descriptor: $($resolvedMember.Descriptor)"
}
catch {
    Write-Error "Could not resolve member: $_"
    exit 1
}

# ─── Confirm ──────────────────────────────────────────────────────────────────
$scope      = if ($Project) { if ($Project.Count -eq 1) { "project '$($Project[0])'" } else { "$($Project.Count) projects ($($Project -join ', '))" } } else { "ALL $($projectsToModify.Count) projects" }
$actionVerb = if ($Action -eq "Add") { "added to" } else { "removed from" }

Write-Host ""
Write-Host "  Action  : $Action" -ForegroundColor White
Write-Host "  Member  : $($resolvedMember.DisplayName) ($Member)" -ForegroundColor White
Write-Host "  Scope   : $scope" -ForegroundColor White
    Write-Host "  Group   : $(if ($AllGroups) { 'ALL groups' } else { $Group })" -ForegroundColor White
Write-Host ""

if (-not $Force -and -not $WhatIfPreference) {
    $confirm = Read-Host "Proceed? [y/N]"
    if ($confirm -notmatch '^[yY]') {
        Write-Host "Cancelled." -ForegroundColor Yellow
        exit 0
    }
    Write-Host ""
}

# ─── [4/4] Apply changes ──────────────────────────────────────────────────────
Write-Host "[4/4] Applying changes..." -ForegroundColor Yellow
Write-Host ""

$results      = @()
$successCount = 0
$skipCount    = 0
$failCount    = 0

foreach ($proj in $projectsToModify) {
    Write-Host "Project: $($proj.name)" -ForegroundColor Cyan

    try {
        # Get project scope descriptor
        $scopeDescUrl    = "https://vssps.dev.azure.com/$Organization/_apis/graph/descriptors/$($proj.id)?api-version=7.1-preview.1"
        $scopeDescriptor = (Invoke-AzureDevOpsApi -Uri $scopeDescUrl -AuthHeader $authHeader).value

        # Find target group(s) and apply change
        $groupsUrl = "https://vssps.dev.azure.com/$Organization/_apis/graph/groups" +
                     "?scopeDescriptor=$scopeDescriptor&api-version=7.1-preview.1"
        $groups    = Invoke-AzureDevOpsApi -Uri $groupsUrl -AuthHeader $authHeader

        if ($AllGroups) {
            # Get all groups this user currently belongs to (org-wide, one call)
            $membershipsUrl = "https://vssps.dev.azure.com/$Organization/_apis/graph/memberships" +
                              "/$($resolvedMember.Descriptor)?direction=Up&api-version=7.1-preview.1"
            $memberships       = Invoke-AzureDevOpsApi -Uri $membershipsUrl -AuthHeader $authHeader
            $memberDescriptors = $memberships.value | ForEach-Object { $_.containerDescriptor }

            # Intersect: only remove from groups that belong to this project
            $groupsToRemove = $groups.value | Where-Object { $memberDescriptors -contains $_.descriptor }

            if ($groupsToRemove.Count -eq 0) {
                Write-Host "  ℹ️  Not a member of any group in this project — skipping" -ForegroundColor Gray
                $skipCount++
                $results += [PSCustomObject]@{ Project = $proj.name; Group = "(all)"; Status = "Skipped"; Reason = "No memberships found" }
                continue
            }

            foreach ($grp in $groupsToRemove) {
                $removeUrl = "https://vssps.dev.azure.com/$Organization/_apis/graph/memberships" +
                             "/$($resolvedMember.Descriptor)/$($grp.descriptor)?api-version=7.1-preview.1"
                if ($PSCmdlet.ShouldProcess("$($proj.name) / $($grp.displayName)", "Remove '$($resolvedMember.DisplayName)'")) {
                    Invoke-AzureDevOpsApi -Uri $removeUrl -Method Delete -AuthHeader $authHeader | Out-Null
                    Write-Host "  ✓  Removed from $($grp.displayName)" -ForegroundColor Green
                    $successCount++
                    $results += [PSCustomObject]@{ Project = $proj.name; Group = $grp.displayName; Status = "Success"; Reason = "" }
                }
            }
        }
        else {
            $adminGroup = $groups.value | Where-Object {
                $_.principalName -like "*\$Group" -or $_.displayName -eq $Group
            } | Select-Object -First 1

            if (-not $adminGroup) {
                Write-Host "  ⚠️  Group '$Group' not found — skipping" -ForegroundColor Yellow
                $skipCount++
                $results += [PSCustomObject]@{ Project = $proj.name; Group = $Group; Status = "Skipped"; Reason = "Group '$Group' not found" }
                continue
            }

            # Check current membership to avoid redundant API calls and give friendly output
            $alreadyMember = Test-IsMember `
                -Organization      $Organization `
                -SubjectDescriptor $resolvedMember.Descriptor `
                -GroupDescriptor   $adminGroup.descriptor `
                -AuthHeader        $authHeader

            if ($Action -eq "Add" -and $alreadyMember) {
                Write-Host "  ℹ️  Already a member — no change needed" -ForegroundColor Gray
                $skipCount++
                $results += [PSCustomObject]@{ Project = $proj.name; Group = $Group; Status = "Skipped"; Reason = "Already a member" }
                continue
            }

            if ($Action -eq "Remove" -and -not $alreadyMember) {
                Write-Host "  ℹ️  Not currently a member — no change needed" -ForegroundColor Gray
                $skipCount++
                $results += [PSCustomObject]@{ Project = $proj.name; Group = $Group; Status = "Skipped"; Reason = "Not a member" }
                continue
            }

            $membershipUrl = "https://vssps.dev.azure.com/$Organization/_apis/graph/memberships" +
                             "/$($resolvedMember.Descriptor)/$($adminGroup.descriptor)" +
                             "?api-version=7.1-preview.1"
            $httpMethod    = if ($Action -eq "Add") { "Put" } else { "Delete" }

            if ($PSCmdlet.ShouldProcess("$($proj.name) / $Group", "$Action '$($resolvedMember.DisplayName)'")) {
                Invoke-AzureDevOpsApi -Uri $membershipUrl -Method $httpMethod -AuthHeader $authHeader | Out-Null
                Write-Host "  ✓  $($resolvedMember.DisplayName) $actionVerb $Group" -ForegroundColor Green
                $successCount++
                $results += [PSCustomObject]@{ Project = $proj.name; Group = $Group; Status = "Success"; Reason = "" }
            }
        }
    }
    catch {
        Write-Host "  ✗  Failed: $_" -ForegroundColor Red
        $failCount++
        $results += [PSCustomObject]@{ Project = $proj.name; Status = "Failed"; Reason = $_.Exception.Message }
    }

    Write-Host ""
}

# ─── Summary ──────────────────────────────────────────────────────────────────
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host "  ✓ Succeeded : $successCount" -ForegroundColor $(if ($successCount -gt 0) { "Green" } else { "White" })
Write-Host "  ℹ Skipped   : $skipCount"    -ForegroundColor Gray
Write-Host "  ✗ Failed    : $failCount"    -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "White" })
Write-Host ""

if ($skipCount -gt 0 -or $failCount -gt 0) {
    $results | Where-Object { $_.Status -ne "Success" } | Format-Table Project, Group, Status, Reason -AutoSize
}
