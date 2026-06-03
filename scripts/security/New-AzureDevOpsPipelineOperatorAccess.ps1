<#
.SYNOPSIS
    Creates an ADO operator group for a pipeline and grants minimum required permissions:
    queue the pipeline and manage Library Secure Files.

.DESCRIPTION
    One-time, idempotent setup. For each run it will:

      1. Find or create an ADO security group in the target project
      2. Add an Entra group (by display name) as a member of that ADO group
      3. Add the ADO group to project Readers (minimum to navigate the project)
      4. Grant Library Administrator at project level (covers Secure Files upload/replace)
      5. Grant ViewBuildDefinition + QueueBuilds on the specified pipeline

    Safe to re-run — existing group/membership/permissions are skipped without error.

    PREREQUISITE — Entra group must already be present in the ADO organisation:
    The Entra group needs to have been added to the ADO organisation at least once
    (Organisation Settings → Users, or by being added to any project group). The script
    will warn and skip the membership step if it cannot find the group, allowing all other
    steps to complete. Re-run once the group is visible.

.PARAMETER Organization
    Azure DevOps organization name (e.g. "myorg" from dev.azure.com/myorg).

.PARAMETER Project
    Azure DevOps project name.

.PARAMETER PipelineName
    The pipeline definition name to grant Queue permission on.

.PARAMETER EntraGroupName
    Display name of the Entra/ADO group to add as a member of the operator group.

.PARAMETER OperatorGroupName
    Display name of the ADO security group to create or reuse as the operator group.

.PARAMETER Force
    Skips the confirmation prompt.

.EXAMPLE
    .\New-AzureDevOpsPipelineOperatorAccess.ps1 `
        -Organization "myorg" `
        -Project "My Project" `
        -PipelineName "My Import Pipeline" `
        -EntraGroupName "SG_PFG_ADO_MyProject_Operators" `
        -OperatorGroupName "My Project - Operators" `
        -Force

.NOTES
    Author: Andrew Wood
    Version: 1.0

    Permission bits granted on the pipeline (Build namespace 33344d9c-fc72-4d6f-aba5-fa317101a7e8):
      1024 = ViewBuildDefinition  (see the pipeline)
       128 = QueueBuilds          (trigger a run)
      ────
      1152 = combined allow mask
#>

#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string]$Organization,

    [Parameter(Mandatory = $true)]
    [string]$Project,

    [Parameter(Mandatory = $true)]
    [string]$PipelineName,

    [Parameter(Mandatory = $true)]
    [string]$EntraGroupName,

    [Parameter(Mandatory = $true)]
    [string]$OperatorGroupName,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# Build security namespace — permission bits
$BuildNamespaceId = "33344d9c-fc72-4d6f-aba5-fa317101a7e8"
$OperatorAllow    = 1152   # ViewBuildDefinition (1024) + QueueBuilds (128)

Write-Host "=== ADO Pipeline Operator Access Setup ===" -ForegroundColor Cyan
Write-Host ""

. "$PSScriptRoot\_Helpers.ps1"

# ─── Confirm ──────────────────────────────────────────────────────────────────
if (-not $Force -and -not $WhatIfPreference) {
    Write-Host "This will configure operator access in $Organization/${Project}:" -ForegroundColor Yellow
    Write-Host "  ADO group  : $OperatorGroupName"
    Write-Host "  Entra group: $EntraGroupName"
    Write-Host "  Pipeline   : $PipelineName"
    Write-Host "  Grants     : Project Readers · Library Administrator · Queue builds"
    Write-Host ""
    $confirm = Read-Host "Proceed? [y/N]"
    if ($confirm -notmatch '^[yY]') {
        Write-Host "Cancelled." -ForegroundColor Yellow
        exit 0
    }
    Write-Host ""
}

# ─── [1/6] Authenticate ───────────────────────────────────────────────────────
Write-Host "[1/6] Authenticating to Azure DevOps..." -ForegroundColor Yellow
$authHeader = Get-AzureDevOpsAuthHeader
Write-Host "✓ Authenticated" -ForegroundColor Green

# ─── [2/6] Resolve project ────────────────────────────────────────────────────
Write-Host "`n[2/6] Resolving project '$Project'..." -ForegroundColor Yellow

$projectUrl  = "https://dev.azure.com/$Organization/_apis/projects/$([Uri]::EscapeDataString($Project))?api-version=7.1"
$projectInfo = Invoke-AzureDevOpsApi -Uri $projectUrl -AuthHeader $authHeader
$projectId   = [string]$projectInfo.id

if (-not $projectId) {
    Write-Error "Could not resolve project ID for '$Project'. Check the project name and organisation."
    exit 1
}
Write-Host "✓ Project: $($projectInfo.name) (ID: $projectId)" -ForegroundColor Green
Write-Verbose "  Scope descriptor URL: https://vssps.dev.azure.com/$Organization/_apis/graph/descriptors/${projectId}?api-version=7.1-preview.1"

$scopeUrl        = "https://vssps.dev.azure.com/$Organization/_apis/graph/descriptors/${projectId}?api-version=7.1-preview.1"
$scopeDescriptor = (Invoke-AzureDevOpsApi -Uri $scopeUrl -AuthHeader $authHeader).value

# ─── [3/6] Find or create operator ADO group ──────────────────────────────────
Write-Host "`n[3/6] Finding or creating ADO group '$OperatorGroupName'..." -ForegroundColor Yellow

$groupsUrl      = "https://vssps.dev.azure.com/$Organization/_apis/graph/groups?scopeDescriptor=$scopeDescriptor&api-version=7.1-preview.1"
$existingGroups = Invoke-AzureDevOpsApi -Uri $groupsUrl -AuthHeader $authHeader
$operatorGroup  = $existingGroups.value | Where-Object { $_.displayName -eq $OperatorGroupName } | Select-Object -First 1

if ($operatorGroup) {
    Write-Host "✓ Group already exists — reusing (descriptor: $($operatorGroup.descriptor))" -ForegroundColor Yellow
} else {
    if ($PSCmdlet.ShouldProcess($Organization, "Create ADO group '$OperatorGroupName'")) {
        $operatorGroup = Invoke-AzureDevOpsApi -Uri $groupsUrl -Method Post -Body @{
            displayName = $OperatorGroupName
            description = "Pipeline operator access. Add Entra group $EntraGroupName (via PIM) as a member. Grants: Library Administrator + Queue builds on $PipelineName."
        } -AuthHeader $authHeader
        Write-Host "✓ Created '$OperatorGroupName'" -ForegroundColor Green
    }
}

# ─── Add operator group to project Readers ────────────────────────────────────
Write-Host "  Adding '$OperatorGroupName' to project Readers..." -ForegroundColor Cyan
$readersGroup = $existingGroups.value | Where-Object { $_.principalName -like "*\Readers" } | Select-Object -First 1

if (-not $readersGroup) {
    Write-Warning "  Could not find Readers group — skipping."
} else {
    if ($PSCmdlet.ShouldProcess("Readers", "Add '$OperatorGroupName'")) {
        $url = "https://vssps.dev.azure.com/$Organization/_apis/graph/memberships/$($operatorGroup.descriptor)/$($readersGroup.descriptor)?api-version=7.1-preview.1"
        try {
            Invoke-AzureDevOpsApi -Uri $url -Method Put -AuthHeader $authHeader | Out-Null
            Write-Host "  ✓ Added to Readers" -ForegroundColor Green
        } catch {
            if ($_ -match '409|already|Conflict') {
                Write-Host "  ✓ Already in Readers — no change needed" -ForegroundColor Yellow
            } else { throw }
        }
    }
}

# ─── [4/6] Add Entra group to operator group ──────────────────────────────────
Write-Host "`n[4/6] Adding Entra group '$EntraGroupName' to '$OperatorGroupName'..." -ForegroundColor Yellow

$identityUrl    = "https://vssps.dev.azure.com/$Organization/_apis/identities?searchFilter=General&filterValue=$([Uri]::EscapeDataString($EntraGroupName))&queryMembership=None&api-version=7.1"
$identityResult = Invoke-AzureDevOpsApi -Uri $identityUrl -AuthHeader $authHeader
$entraIdentity  = $identityResult.value | Where-Object { $_.providerDisplayName -eq $EntraGroupName } | Select-Object -First 1

if (-not $entraIdentity) {
    # Group not yet materialised in ADO — attempt via Microsoft Graph
    Write-Host "  Not found in ADO identity store — attempting to add via Microsoft Graph..." -ForegroundColor Yellow
    try {
        $graphTokenResult = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction Stop
        if ($graphTokenResult.Token -is [SecureString]) {
            $BSTR        = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($graphTokenResult.Token)
            $graphBearer = "Bearer $([System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR))"
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        } else {
            $graphBearer = "Bearer $($graphTokenResult.Token)"
        }
        $graphHeaders = @{ Authorization = $graphBearer; Accept = "application/json" }
        $filter       = [Uri]::EscapeDataString("displayName eq '$EntraGroupName'")
        $graphGroup   = (Invoke-WebRequest "https://graph.microsoft.com/v1.0/groups?`$filter=$filter&`$select=id,displayName" -Headers $graphHeaders | ConvertFrom-Json).value | Select-Object -First 1

        if (-not $graphGroup) {
            Write-Warning "  '$EntraGroupName' not found in Entra — check the display name is exact."
            Write-Warning "  All other permissions have been set — only this membership step is skipped."
        } else {
            Write-Host "  Found in Entra: $($graphGroup.displayName) (OID: $($graphGroup.id))" -ForegroundColor Green
            if ($PSCmdlet.ShouldProcess($Organization, "Materialise '$EntraGroupName' in ADO organisation")) {
                $addGroupUrl  = "https://vssps.dev.azure.com/$Organization/_apis/graph/groups?api-version=7.1-preview.1"
                $addGroupBody = ConvertTo-Json -InputObject @{ originId = $graphGroup.id } -Compress
                try {
                    Invoke-AzureDevOpsApi -Uri $addGroupUrl -Method Post -Body $addGroupBody -AuthHeader $authHeader | Out-Null
                } catch {
                    if ($_ -notmatch '409|already|Conflict') { throw }
                }
                Write-Host "  ✓ Group added to ADO organisation" -ForegroundColor Green
                # Re-fetch identity now it is materialised
                $identityResult = Invoke-AzureDevOpsApi -Uri $identityUrl -AuthHeader $authHeader
                $entraIdentity  = $identityResult.value | Where-Object { $_.providerDisplayName -eq $EntraGroupName } | Select-Object -First 1
            }
        }
    } catch {
        Write-Warning "  Could not add group via Graph API: $_"
        Write-Warning "  Add '$EntraGroupName' manually via Organisation Settings → Users, then re-run."
    }
}

if ($entraIdentity) {
    # Resolve graph descriptor (needed for membership API)
    $entraDescriptor = $entraIdentity.subjectDescriptor
    if (-not $entraDescriptor) {
        $storageKeyUrl   = "https://vssps.dev.azure.com/$Organization/_apis/graph/descriptors/$($entraIdentity.id)?api-version=7.1-preview.1"
        $entraDescriptor = (Invoke-AzureDevOpsApi -Uri $storageKeyUrl -AuthHeader $authHeader).value
    }

    if ($PSCmdlet.ShouldProcess($OperatorGroupName, "Add '$EntraGroupName'")) {
        $url = "https://vssps.dev.azure.com/$Organization/_apis/graph/memberships/$entraDescriptor/$($operatorGroup.descriptor)?api-version=7.1-preview.1"
        try {
            Invoke-AzureDevOpsApi -Uri $url -Method Put -AuthHeader $authHeader | Out-Null
            Write-Host "✓ '$EntraGroupName' added to '$OperatorGroupName'" -ForegroundColor Green
        } catch {
            if ($_ -match '409|already|Conflict') {
                Write-Host "✓ Already a member — no change needed" -ForegroundColor Yellow
            } else { throw }
        }
    }
}

# ─── [5/6] Grant Library Administrator ────────────────────────────────────────
Write-Host "`n[5/6] Granting Library Administrator at project level..." -ForegroundColor Yellow

# Library roles API requires the identity GUID (not graph descriptor)
$identityLookupUrl = "https://vssps.dev.azure.com/$Organization/_apis/identities?subjectDescriptors=$($operatorGroup.descriptor)&api-version=7.1"
$operatorIdentity  = (Invoke-AzureDevOpsApi -Uri $identityLookupUrl -AuthHeader $authHeader).value | Select-Object -First 1

if (-not $operatorIdentity) {
    Write-Warning "Could not resolve identity for '$OperatorGroupName' — Library role assignment skipped."
} else {
    if ($PSCmdlet.ShouldProcess("Library (project level)", "Grant Administrator to '$OperatorGroupName'")) {
        # The security roles API requires a real resource ID — there is no project-wide wildcard.
        # Enumerate every variable group and secure file and grant Administrator on each.
        $libraryRoleBody = ConvertTo-Json -InputObject @(@{ roleName = "Administrator"; userId = $operatorIdentity.id }) -Compress

        $varGroupsUrl = "https://dev.azure.com/$Organization/$([Uri]::EscapeDataString($Project))/_apis/distributedtask/variablegroups?api-version=7.1"
        $varGroups    = (Invoke-AzureDevOpsApi -Uri $varGroupsUrl -AuthHeader $authHeader).value
        # securityroles endpoint is org-scoped; resource ID must be {projectId}%24{resourceId}
        if ($varGroups) {
            foreach ($vg in $varGroups) {
                $roleUrl = "https://dev.azure.com/$Organization/_apis/securityroles/scopes/distributedtask.variablegroup/roleassignments/resources/$projectId%24$($vg.id)?api-version=7.1-preview.1"
                Invoke-AzureDevOpsApi -Uri $roleUrl -Method Put -Body $libraryRoleBody -AuthHeader $authHeader | Out-Null
                Write-Host "  ✓ Administrator on variable group: $($vg.name)" -ForegroundColor Green
            }
        } else {
            Write-Host "  (no variable groups found)" -ForegroundColor DarkGray
        }

        $secureFilesUrl = "https://dev.azure.com/$Organization/$([Uri]::EscapeDataString($Project))/_apis/distributedtask/securefiles?api-version=7.1-preview.1"
        $secureFiles    = (Invoke-AzureDevOpsApi -Uri $secureFilesUrl -AuthHeader $authHeader).value
        if ($secureFiles) {
            foreach ($sf in $secureFiles) {
                $roleUrl = "https://dev.azure.com/$Organization/_apis/securityroles/scopes/distributedtask.securefile/roleassignments/resources/$projectId%24$($sf.id)?api-version=7.1-preview.1"
                Invoke-AzureDevOpsApi -Uri $roleUrl -Method Put -Body $libraryRoleBody -AuthHeader $authHeader | Out-Null
                Write-Host "  ✓ Administrator on secure file: $($sf.name)" -ForegroundColor Green
            }
        } else {
            Write-Host "  (no secure files found)" -ForegroundColor DarkGray
        }

        Write-Host "✓ Library Administrator granted (all Secure Files + Variable Groups)" -ForegroundColor Green
    }
}

# ─── [6/6] Grant Queue builds on pipeline ─────────────────────────────────────
Write-Host "`n[6/6] Granting Queue builds on pipeline '$PipelineName'..." -ForegroundColor Yellow

$pipelineSearchUrl = "https://dev.azure.com/$Organization/$([Uri]::EscapeDataString($Project))/_apis/build/definitions?name=$([Uri]::EscapeDataString($PipelineName))&api-version=7.1"
$pipeline          = (Invoke-AzureDevOpsApi -Uri $pipelineSearchUrl -AuthHeader $authHeader).value |
                     Where-Object { $_.name -eq $PipelineName } | Select-Object -First 1

if (-not $pipeline) {
    Write-Warning "Pipeline '$PipelineName' not found — Queue builds permission skipped. Re-run once the pipeline exists."
} elseif (-not $operatorIdentity) {
    Write-Warning "Identity not resolved — Queue builds permission skipped."
} else {
    Write-Host "  Pipeline ID: $($pipeline.id)" -ForegroundColor DarkGray

    if ($PSCmdlet.ShouldProcess("Pipeline '$PipelineName'", "Grant Queue builds to '$OperatorGroupName'")) {
        $aclUrl  = "https://dev.azure.com/$Organization/_apis/accesscontrolentries/$BuildNamespaceId`?api-version=7.1"
        $aclBody = ConvertTo-Json -Depth 10 -Compress -InputObject @{
            token                = "$projectId/$($pipeline.id)"
            merge                = $true
            accessControlEntries = @(
                @{
                    descriptor   = $operatorIdentity.descriptor
                    allow        = $OperatorAllow
                    deny         = 0
                    extendedInfo = @{}
                }
            )
        }
        Invoke-AzureDevOpsApi -Uri $aclUrl -Method Post -Body $aclBody -AuthHeader $authHeader | Out-Null
        Write-Host "✓ ViewBuildDefinition + QueueBuilds ($OperatorAllow) granted on '$PipelineName'" -ForegroundColor Green
    }
}

# ─── Summary ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Setup Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "ADO group '$OperatorGroupName' is configured in $Organization / $Project" -ForegroundColor Cyan
Write-Host ""
Write-Host "Verify at:" -ForegroundColor Yellow
Write-Host "  Library   : https://dev.azure.com/$Organization/$([Uri]::EscapeDataString($Project))/_library?itemType=SecureFiles"
Write-Host "  Pipeline  : https://dev.azure.com/$Organization/$([Uri]::EscapeDataString($Project))/_build?definitionId=$($pipeline.id)"
Write-Host ""
