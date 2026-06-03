<#
.SYNOPSIS
    Locks Azure DevOps service connections so only explicitly authorised pipelines can use them.

.DESCRIPTION
    Service connections are high-value credentials — anyone who can queue a pipeline that
    has access to a service connection can deploy to the associated Azure environment.
    By default, Azure DevOps grants ALL pipelines access to new service connections, which
    is a significant security risk, especially for connections targeting production.

    This script sets each service connection (or a specified subset) to:
    - Deny access to all pipelines by default
    - Optionally grant access to a specified list of pipeline IDs

    Key Features:
    - Lists current pipeline permissions for all service connections
    - Reports which connections are open to all pipelines
    - Locks down all or specified connections with a single run
    - Optionally grants access to specific authorised pipelines
    - Idempotent — safe to run multiple times

.PARAMETER Organization
    Azure DevOps organization name (e.g. "myorg" from dev.azure.com/myorg)

.PARAMETER Project
    Azure DevOps project name

.PARAMETER ServiceConnectionNames
    One or more service connection names to target. If omitted, all service connections
    in the project are processed.

.PARAMETER AuthorisedPipelineIds
    List of pipeline definition IDs to explicitly grant access after locking down.
    These are the only pipelines that will be allowed to use the connection.

.PARAMETER ReportOnly
    Report current permission state without making any changes.

.PARAMETER Force
    Skips confirmation prompts

.EXAMPLE
    # Report current state of all service connections
    .\Set-AzureDevOpsServiceConnectionSecurity.ps1 `
        -Organization "myorg" `
        -Project "MyProject" `
        -ReportOnly

.EXAMPLE
    # Lock all service connections (no pipelines authorised yet)
    .\Set-AzureDevOpsServiceConnectionSecurity.ps1 `
        -Organization "myorg" `
        -Project "MyProject" `
        -Force

.EXAMPLE
    # Lock a specific connection and authorise two pipelines
    .\Set-AzureDevOpsServiceConnectionSecurity.ps1 `
        -Organization "myorg" `
        -Project "MyProject" `
        -ServiceConnectionNames "Azure-Production" `
        -AuthorisedPipelineIds 10,23 `
        -Force

.NOTES
    Author: Andrew Wood
    Version: 1.0

    Prerequisites:
    - Azure DevOps login: Connect-AzAccount, AZURE_DEVOPS_EXT_PAT, or az devops login
    - Permissions: Project Administrator or service connection Administrator

    API References:
    - Service Endpoints: https://learn.microsoft.com/en-us/rest/api/azure/devops/serviceendpoint/endpoints
    - Pipeline Permissions: https://learn.microsoft.com/en-us/rest/api/azure/devops/approvalsandchecks/pipeline-permissions

.LINK
    https://learn.microsoft.com/en-us/azure/devops/pipelines/library/service-endpoints
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string]$Organization,

    [Parameter(Mandatory = $true)]
    [string]$Project,

    [Parameter(Mandatory = $false)]
    [string[]]$ServiceConnectionNames = @(),

    [Parameter(Mandatory = $false)]
    [int[]]$AuthorisedPipelineIds = @(),

    [Parameter(Mandatory = $false)]
    [switch]$ReportOnly,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "=== Azure DevOps Service Connection Security ===" -ForegroundColor Cyan
Write-Host ""

. "$PSScriptRoot\_Helpers.ps1"

# Confirm (for non-report mode)
if (-not $ReportOnly -and -not $Force -and -not $WhatIfPreference) {
    $scope = if ($ServiceConnectionNames.Count -gt 0) {
        $ServiceConnectionNames -join ", "
    } else { "ALL service connections" }

    Write-Host "`n⚠️  This will restrict pipeline access on: $scope" -ForegroundColor Yellow
    Write-Host "   Organization: $Organization" -ForegroundColor Gray
    Write-Host "   Project:      $Project" -ForegroundColor Gray
    if ($AuthorisedPipelineIds.Count -gt 0) {
        Write-Host "   Authorised pipeline IDs: $($AuthorisedPipelineIds -join ', ')" -ForegroundColor Gray
    }
    else {
        Write-Host "   ⚠️  No authorised pipeline IDs specified — connections will be locked to zero pipelines" -ForegroundColor Yellow
        Write-Host "      Pipelines will need to be manually authorised per connection afterwards" -ForegroundColor Yellow
    }
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

# List service connections
Write-Host "`n[2/3] Fetching service connections..." -ForegroundColor Yellow
try {
    $endpointsUrl = "https://dev.azure.com/$Organization/$Project/_apis/serviceendpoint/endpoints?api-version=7.2-preview.4"
    $allConnections = (Invoke-AzureDevOpsApi -Uri $endpointsUrl -AuthHeader $authHeader).value

    if ($ServiceConnectionNames.Count -gt 0) {
        $connections = $allConnections | Where-Object { $ServiceConnectionNames -contains $_.name }
        $missing = $ServiceConnectionNames | Where-Object { $allConnections.name -notcontains $_ }
        if ($missing) {
            Write-Warning "The following service connections were not found: $($missing -join ', ')"
        }
    }
    else {
        $connections = $allConnections
    }

    Write-Host "✓ Found $($connections.Count) service connection(s) to process" -ForegroundColor Green
}
catch {
    Write-Error "Failed to fetch service connections: $_"
    exit 1
}

# Process each connection
Write-Host "`n[3/3] Processing service connection permissions..." -ForegroundColor Yellow
Write-Host ""

$report = @()

foreach ($conn in $connections) {
    Write-Host "Service Connection: $($conn.name)" -ForegroundColor Cyan
    Write-Host "  Type: $($conn.type)   ID: $($conn.id)" -ForegroundColor Gray

    try {
        # Get current pipeline permissions
        $permUrl = "https://dev.azure.com/$Organization/$Project/_apis/pipelines/pipelinePermissions/endpoint/$($conn.id)?api-version=7.1-preview.1"
        $currentPerms = Invoke-AzureDevOpsApi -Uri $permUrl -AuthHeader $authHeader

        $allAuthorised = $currentPerms.allPipelines.authorized
        $specificPipelines = $currentPerms.pipelines

        if ($allAuthorised) {
            Write-Host "  ⚠️  Status: OPEN — all pipelines can use this connection" -ForegroundColor Red
        }
        else {
            $authorisedCount = ($specificPipelines | Where-Object { $_.authorized }).Count
            Write-Host "  ✓  Status: RESTRICTED — $authorisedCount specific pipeline(s) authorised" -ForegroundColor Green
        }

        if ($specificPipelines -and $specificPipelines.Count -gt 0) {
            foreach ($pipeline in $specificPipelines) {
                $pStatus = if ($pipeline.authorized) { "✓ authorised" } else { "✗ not authorised" }
                Write-Host "    Pipeline ID $($pipeline.id): $pStatus" -ForegroundColor Gray
            }
        }

        $report += [PSCustomObject]@{
            Name               = $conn.name
            Type               = $conn.type
            Id                 = $conn.id
            AllPipelinesOpen   = $allAuthorised
            AuthorisedPipelines = ($specificPipelines | Where-Object { $_.authorized }).id -join ","
        }

        # Apply change if not in report-only mode
        if (-not $ReportOnly) {
            $pipelinesPayload = @()
            foreach ($pipelineId in $AuthorisedPipelineIds) {
                $pipelinesPayload += @{ id = $pipelineId; authorized = $true }
            }

            $permissionsBody = @{
                allPipelines = @{ authorized = $false }
                pipelines    = $pipelinesPayload
            }

            if ($PSCmdlet.ShouldProcess($conn.name, "Restrict service connection pipeline access")) {
                Invoke-AzureDevOpsApi -Uri $permUrl -Method Patch -Body $permissionsBody -AuthHeader $authHeader | Out-Null
                $msg = if ($AuthorisedPipelineIds.Count -gt 0) {
                    "Locked — authorised pipelines: $($AuthorisedPipelineIds -join ', ')"
                } else {
                    "Locked — no pipelines authorised (grant manually via UI or -AuthorisedPipelineIds)"
                }
                Write-Host "  ✓ $msg" -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Warning "Failed to process '$($conn.name)': $_"
    }

    Write-Host ""
}

# Summary
Write-Host "=== Summary ===" -ForegroundColor Cyan
$openCount = ($report | Where-Object { $_.AllPipelinesOpen }).Count
$restrictedCount = ($report | Where-Object { -not $_.AllPipelinesOpen }).Count

if ($ReportOnly) {
    Write-Host "Report mode — no changes made" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Open to all pipelines: $openCount" -ForegroundColor $(if ($openCount -gt 0) { "Red" } else { "Green" })
    Write-Host "Already restricted:    $restrictedCount" -ForegroundColor Green
    Write-Host ""
    if ($openCount -gt 0) {
        Write-Host "Re-run without -ReportOnly to lock down the open connections." -ForegroundColor Yellow
    }
}
else {
    Write-Host "Connections processed: $($report.Count)" -ForegroundColor White
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. Verify permissions: Project Settings → Service connections → [connection] → Security" -ForegroundColor Gray
    Write-Host "  2. For each connection, confirm only intended pipelines appear under Pipeline permissions" -ForegroundColor Gray
    Write-Host "  3. Repeat for dev vs prod service connections — keep them separate with separate authorisations" -ForegroundColor Gray
}
Write-Host ""
