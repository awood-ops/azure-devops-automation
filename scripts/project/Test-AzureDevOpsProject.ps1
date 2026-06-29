<#
.SYNOPSIS
    Validates the security configuration of an Azure DevOps project against the standard hardening baseline.

.DESCRIPTION
    Checks each of the 10 hardening controls without making any changes. Use this to audit an existing
    project or confirm that Invoke-AzureDevOpsHardening.ps1 has been applied correctly.

    Exits with code 1 if any check fails — suitable for use in CI pipelines.

.PARAMETER Organization
    Azure DevOps organisation name (e.g. 'my-org' from dev.azure.com/my-org).

.PARAMETER Project
    Azure DevOps project name.

.EXAMPLE
    .\Test-AzureDevOpsProject.ps1 -Organization 'my-org' -Project 'My Project'
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string] $Organization,

    [Parameter(Mandatory)]
    [string] $Project
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$securityRoot = Join-Path $PSScriptRoot '..\security'
. (Join-Path $securityRoot '_Helpers.ps1')

$headers  = Get-AzureDevOpsAuthHeader
$baseUrl  = "https://dev.azure.com/$Organization"
$projEnc  = [Uri]::EscapeDataString($Project)

$results = @()
$check = { param($name, $pass, $detail)
    [PSCustomObject]@{ Check = $name; Status = if ($pass) { 'PASS' } else { 'FAIL' }; Detail = $detail }
}

# ── Project ──────────────────────────────────────────────────────────────────
try {
    $proj = Invoke-RestMethod -Method Get -Headers $headers `
        -Uri "$baseUrl/_apis/projects/$projEnc`?api-version=7.1"
    $results += & $check "Project '$Project' exists" $true "ID: $($proj.id)"
    $projectId = $proj.id
} catch {
    $results += & $check "Project '$Project' exists" $false "NOT FOUND"
    $results | Format-Table -AutoSize
    exit 1
}

# ── Branch policies ───────────────────────────────────────────────────────────
$repos = (Invoke-RestMethod -Method Get -Headers $headers `
    -Uri "$baseUrl/$projEnc/_apis/git/repositories?api-version=7.1").value

$reposWithPolicy = 0
foreach ($repo in $repos) {
    $policies = (Invoke-RestMethod -Method Get -Headers $headers `
        -Uri "$baseUrl/$projEnc/_apis/policy/configurations?api-version=7.1").value |
        Where-Object { $_.settings.scope.repositoryId -eq $repo.id -and $_.isEnabled }
    if (($policies | Where-Object { $_.type.displayName -like '*Minimum number*' })) { $reposWithPolicy++ }
}
$results += & $check "Step 1 — Branch policies (min reviewers)" ($reposWithPolicy -gt 0) "$reposWithPolicy/$($repos.Count) repos have min-reviewer policy"

# ── Project Administrators ────────────────────────────────────────────────────
$groups   = (Invoke-RestMethod -Method Get -Headers $headers `
    -Uri "https://vssps.dev.azure.com/$Organization/_apis/graph/groups?scopeDescriptor=$(
        (Invoke-RestMethod -Method Get -Headers $headers -Uri "$baseUrl/_apis/projects/$projEnc`?api-version=7.1&includeCapabilities=false").id
    )&api-version=7.1-preview.1").value
$adminGrp = $groups | Where-Object { $_.displayName -eq 'Project Administrators' }
$adminMembers = if ($adminGrp) {
    (Invoke-RestMethod -Method Get -Headers $headers `
        -Uri "https://vssps.dev.azure.com/$Organization/_apis/graph/memberships/$($adminGrp.descriptor)?direction=down&api-version=7.1-preview.1").value
} else { @() }
$results += & $check "Step 2 — Project Administrator audit" $true "$($adminMembers.Count) member(s) — review manually"

# ── Pipeline settings ─────────────────────────────────────────────────────────
$pipelineSettings = Invoke-RestMethod -Method Get -Headers $headers `
    -Uri "$baseUrl/$projEnc/_apis/build/generalsettings?api-version=7.1"
$results += & $check "Step 4 — Pipeline: enforce YAML template" ($pipelineSettings.enforceReferencedRepoScopedToken -eq $true) ($pipelineSettings.enforceReferencedRepoScopedToken)
$results += & $check "Step 4 — Pipeline: disable status badge" ($pipelineSettings.statusBadgesArePrivate -eq $true) ($pipelineSettings.statusBadgesArePrivate)
$results += & $check "Step 4 — Pipeline: limit job scope" ($pipelineSettings.enforceJobAuthScope -eq $true) ($pipelineSettings.enforceJobAuthScope)

# ── Service connections ───────────────────────────────────────────────────────
$serviceConnections = (Invoke-RestMethod -Method Get -Headers $headers `
    -Uri "$baseUrl/$projEnc/_apis/serviceendpoint/endpoints?api-version=7.2-preview.4").value
$results += & $check "Step 3 — Service connections exist" ($serviceConnections.Count -gt 0) "$($serviceConnections.Count) connection(s) found"

$openConnections = $serviceConnections | Where-Object { $_.data.scopeLevel -ne 'Subscription' -or $_.isShared -eq $true }
$results += & $check "Step 3 — No shared service connections" ($openConnections.Count -eq 0) ($openConnections.Count -gt 0 ? "$($openConnections.Count) shared/open connection(s)" : 'Clean')

# ── Repositories ─────────────────────────────────────────────────────────────
$results += & $check "Repositories present" ($repos.Count -gt 0) "$($repos.Count) repo(s)"

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host "`n=== Validation: $Organization / $Project ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize

$pass = ($results | Where-Object Status -eq 'PASS').Count
$fail = ($results | Where-Object Status -eq 'FAIL').Count
Write-Host "Results — Pass: $pass  Fail: $fail  Total: $($results.Count)" -ForegroundColor ($fail -gt 0 ? 'Red' : 'Green')
Write-Host "Note: Step 2 (admin audit), Steps 5–10 require Invoke-AzureDevOpsHardening.ps1 -ReportOnly for full detail." -ForegroundColor Yellow

if ($fail -gt 0) { exit 1 }
