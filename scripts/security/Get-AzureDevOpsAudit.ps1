<#
.SYNOPSIS
    Audits security group membership across one or more Azure DevOps projects.

.DESCRIPTION
    Security group membership is a significant attack surface — over-privileged members can
    bypass controls, access sensitive repositories, and escalate privileges. This script
    enumerates membership across all security groups in each project (or a specific group)
    and highlights unexpected members based on an optional allowlist.

    Key Features:
    - Reports members of every security group per project
    - Filter to a single group with -Group (e.g. "Project Administrators", "Contributors")
    - Highlights accounts not on the expected allowlist
    - Supports auditing a single project or all projects in the organisation
    - Outputs a summary table and optionally exports to CSV
    - Read-only — makes no changes

.PARAMETER Organization
    Azure DevOps organization name (e.g. "myorg" from dev.azure.com/myorg)

.PARAMETER Project
    Specific project to audit. If omitted, all projects in the organisation are audited.

.PARAMETER Group
    Optional group display name to filter the audit to a single security group
    (e.g. "Project Administrators", "Contributors"). If omitted, all groups are audited.

.PARAMETER ExpectedAdmins
    Optional list of expected member email addresses (UPNs). Members not on this list will
    be flagged as unexpected across all audited groups. If not provided, all members are
    listed without flagging.

.PARAMETER ExportCsvPath
    Optional path to export the audit results as a CSV file.

.PARAMETER Force
    Skips confirmation prompts

.EXAMPLE
    # Audit ALL groups across all projects (full membership report)
    .\Get-AzureDevOpsAudit.ps1 `
        -Organization "myorg" `
        -ExportCsvPath "C:\Reports\full-audit.csv"

.EXAMPLE
    # Audit only Project Administrators across all projects (original behaviour)
    .\Get-AzureDevOpsAudit.ps1 `
        -Organization "myorg" `
        -Group "Project Administrators" `
        -ExportCsvPath "C:\Reports\admins.csv"

.EXAMPLE
    # Audit a specific project and group with an allowlist
    .\Get-AzureDevOpsAudit.ps1 `
        -Organization "myorg" `
        -Project "MyProject" `
        -Group "Project Administrators" `
        -ExpectedAdmins "alice@example.com","bob@example.com"

.EXAMPLE
    # Audit Contributors across all projects
    .\Get-AzureDevOpsAudit.ps1 `
        -Organization "myorg" `
        -Group "Contributors"

.NOTES
    Author: Andrew Wood
    Version: 1.0

    Prerequisites:
    - Azure DevOps login: Connect-AzAccount, AZURE_DEVOPS_EXT_PAT, or az devops login
    - Permissions: Project Administrator or Organisation Administrator

    API References:
    - Graph Groups API: https://learn.microsoft.com/en-us/rest/api/azure/devops/graph/groups
    - Graph Memberships API: https://learn.microsoft.com/en-us/rest/api/azure/devops/graph/memberships

.LINK
    https://learn.microsoft.com/en-us/azure/devops/organizations/security/permissions
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Organization,

    [Parameter(Mandatory = $false)]
    [string]$Project,

    [Parameter(Mandatory = $false)]
    [string]$Group,

    [Parameter(Mandatory = $false)]
    [string[]]$ExpectedAdmins = @(),

    [Parameter(Mandatory = $false)]
    [string]$ExportCsvPath,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "=== Azure DevOps Security Group Membership Audit ===" -ForegroundColor Cyan
Write-Host ""

. "$PSScriptRoot\_Helpers.ps1"

function Get-GroupMembers {
    <#
    .SYNOPSIS
        Returns direct members of a group given its descriptor.
        Uses typed endpoints (/users/ or /groups/) based on descriptor prefix,
        which is more reliable than the /subjects/ unified endpoint.
    #>
    param(
        [string]$Organization,
        [string]$GroupDescriptor,
        [string]$AuthHeader
    )

    $members = @()
    try {
        $membershipsUrl = "https://vssps.dev.azure.com/$Organization/_apis/graph/memberships/$GroupDescriptor`?direction=Down&api-version=7.1-preview.1"
        $memberships = Invoke-AzureDevOpsApi -Uri $membershipsUrl -AuthHeader $AuthHeader

        foreach ($membership in $memberships.value) {
            $memberDescriptor = $membership.memberDescriptor

            # Determine endpoint from descriptor prefix:
            #   vssgp./aadgp. = group, vssea./msa./aad. = user/service account
            $isGroup = $memberDescriptor -like "vssgp.*" -or $memberDescriptor -like "aadgp.*"
            $typedEndpoint = if ($isGroup) { "groups" } else { "users" }

            try {
                $subjectUrl = "https://vssps.dev.azure.com/$Organization/_apis/graph/$typedEndpoint/$memberDescriptor`?api-version=7.1-preview.1"
                $subject = Invoke-AzureDevOpsApi -Uri $subjectUrl -AuthHeader $AuthHeader
                $members += $subject
            }
            catch {
                # Primary endpoint failed — try the alternate in case the descriptor
                # prefix doesn't match the actual subject kind (e.g. a group whose
                # descriptor wasn't caught by the prefix check above).
                $fallbackEndpoint = if ($isGroup) { "users" } else { "groups" }
                try {
                    Write-Verbose "Primary lookup failed for $memberDescriptor, retrying as $fallbackEndpoint"
                    $subjectUrl = "https://vssps.dev.azure.com/$Organization/_apis/graph/$fallbackEndpoint/$memberDescriptor`?api-version=7.1-preview.1"
                    $subject = Invoke-AzureDevOpsApi -Uri $subjectUrl -AuthHeader $AuthHeader
                    $members += $subject
                }
                catch {
                    Write-Verbose "Subject lookup failed for $memberDescriptor`: $_"
                    $members += [PSCustomObject]@{
                        descriptor   = $memberDescriptor
                        displayName  = "(lookup failed)"
                        mailAddress  = "(lookup failed)"
                        subjectKind  = if ($isGroup) { "group" } else { "user" }
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Failed to get members for group $GroupDescriptor`: $_"
    }

    return $members
}

#endregion

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

# Build project list
Write-Host "`n[2/3] Resolving projects to audit..." -ForegroundColor Yellow
$projectsToAudit = @()
try {
    if ($Project) {
        $projectUrl = "https://dev.azure.com/$Organization/_apis/projects/$Project`?api-version=7.1"
        $singleProject = Invoke-AzureDevOpsApi -Uri $projectUrl -AuthHeader $authHeader
        $projectsToAudit += $singleProject
        Write-Host "✓ Auditing project: $Project" -ForegroundColor Green
    }
    else {
        $projectsUrl = "https://dev.azure.com/$Organization/_apis/projects?api-version=7.1"
        $allProjects = Invoke-AzureDevOpsApi -Uri $projectsUrl -AuthHeader $authHeader
        $projectsToAudit = $allProjects.value
        Write-Host "✓ Auditing all $($projectsToAudit.Count) projects in organisation" -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to resolve projects: $_"
    exit 1
}

# Audit each project
$groupScope = if ($Group) { "group '$Group'" } else { "all groups" }
Write-Host "`n[3/3] Auditing security group memberships ($groupScope)..." -ForegroundColor Yellow
Write-Host ""

$auditResults = @()
$unexpectedCount = 0

foreach ($proj in $projectsToAudit) {
    Write-Host "Project: $($proj.name)" -ForegroundColor Cyan

    try {
        # Get the project-scoped group descriptor
        $scopeDescriptorUrl = "https://vssps.dev.azure.com/$Organization/_apis/graph/descriptors/$($proj.id)?api-version=7.1-preview.1"
        $scopeDescriptor = (Invoke-AzureDevOpsApi -Uri $scopeDescriptorUrl -AuthHeader $authHeader).value

        # List all groups in this project scope (paginated)
        $allGroups = @()
        $baseGroupsUrl = "https://vssps.dev.azure.com/$Organization/_apis/graph/groups?scopeDescriptor=$scopeDescriptor&api-version=7.1-preview.1"
        $groupsContinuationToken = $null
        do {
            $groupsPageUrl = if ($groupsContinuationToken) { "$baseGroupsUrl&continuationToken=$groupsContinuationToken" } else { $baseGroupsUrl }
            $groupTokenRef = [ref]$null
            $groupsPage = Invoke-AzureDevOpsApi -Uri $groupsPageUrl -AuthHeader $authHeader -OutContinuationToken $groupTokenRef
            $allGroups += $groupsPage.value
            $groupsContinuationToken = $groupTokenRef.Value
        } while ($groupsContinuationToken)

        # Filter to a specific group if -Group was supplied, otherwise audit all
        $groupsToAudit = if ($Group) {
            $allGroups | Where-Object { $_.displayName -eq $Group -or $_.principalName -like "*\$Group" }
        } else {
            $allGroups
        }

        if ($groupsToAudit.Count -eq 0) {
            $msg = if ($Group) { "No group matching '$Group' found" } else { "No groups found" }
            Write-Host "  ⚠️  $msg — skipping" -ForegroundColor Yellow
            continue
        }

        Write-Host "  Groups to audit: $($groupsToAudit.Count)" -ForegroundColor Gray

        foreach ($securityGroup in ($groupsToAudit | Sort-Object displayName)) {
            $members = Get-GroupMembers -Organization $Organization -GroupDescriptor $securityGroup.descriptor -AuthHeader $authHeader

            if ($members.Count -eq 0) {
                Write-Verbose "  [$($securityGroup.displayName)] — no direct members"
                continue
            }

            Write-Host "  [$($securityGroup.displayName)]" -ForegroundColor White

            foreach ($member in $members) {
                $email = $member.mailAddress
                $name  = $member.displayName
                $kind  = $member.subjectKind

                $isExpected = $ExpectedAdmins.Count -eq 0 -or
                    ($email -and $ExpectedAdmins -contains $email) -or
                    ($name  -and $ExpectedAdmins -contains $name)
                $flag = if ($isExpected) { "" } else { "⚠️  UNEXPECTED" }

                if (-not $isExpected) {
                    $unexpectedCount++
                    Write-Host "    ⚠️  $name ($email) [$kind] — NOT on expected list" -ForegroundColor Red
                }
                else {
                    Write-Host "    ✓  $name ($email) [$kind]" -ForegroundColor Green
                }

                $auditResults += [PSCustomObject]@{
                    Project      = $proj.name
                    Group        = $securityGroup.displayName
                    DisplayName  = $name
                    Email        = $email
                    SubjectKind  = $kind
                    Descriptor   = $member.descriptor
                    IsExpected   = $isExpected
                    Flag         = $flag
                }
            }
        }
    }
    catch {
        Write-Warning "Failed to audit project '$($proj.name)': $_"
    }

    Write-Host ""
}

# Summary
Write-Host "=== Audit Summary ===" -ForegroundColor Cyan
Write-Host "Projects audited:         $($projectsToAudit.Count)" -ForegroundColor White
Write-Host "Total entries:            $($auditResults.Count)" -ForegroundColor White

if ($ExpectedAdmins.Count -gt 0) {
    $color = if ($unexpectedCount -gt 0) { "Red" } else { "Green" }
    Write-Host "Unexpected members found: $unexpectedCount" -ForegroundColor $color
}
else {
    Write-Host "Note: No -ExpectedAdmins list provided — all members listed without flagging" -ForegroundColor Yellow
}

Write-Host ""

# Display table
if ($auditResults.Count -gt 0) {
    $auditResults | Format-Table Project, Group, DisplayName, Email, SubjectKind, Flag -AutoSize
}

# Export CSV if requested
if ($ExportCsvPath) {
    try {
        $auditResults | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "✓ Results exported to: $ExportCsvPath" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to export CSV: $_"
    }
}

Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Review any ⚠️  UNEXPECTED entries above" -ForegroundColor Gray
Write-Host "  2. Manage group membership via Set-AzureDevOpsGroupMember.ps1" -ForegroundColor Gray
Write-Host "  3. Most developers should be in Contributors only" -ForegroundColor Gray
Write-Host "  4. Consider creating a 'Tech Leads' group with Contribute + Create branches, not full admin" -ForegroundColor Gray
Write-Host "  5. Use -Group 'Project Administrators' to focus on the highest-risk group only" -ForegroundColor Gray
Write-Host ""
