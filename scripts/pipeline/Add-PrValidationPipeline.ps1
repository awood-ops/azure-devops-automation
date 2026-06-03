<#
.SYNOPSIS
    Adds a PR validation pipeline to a repository and applies the build validation branch policy.

.DESCRIPTION
    Three steps:
      1. Checks whether the PR validation YAML already exists in the repository. If not,
         commits the appropriate template from the local pipelines/ folder.
      2. Creates a "PR Validation" pipeline definition in Azure DevOps pointing to the YAML.
      3. Applies the "Build validation" branch policy on the default branch, wiring it to
         the created pipeline. This satisfies the BRANCH-02 audit control.

    For new projects forked from Infrastructure and Security after the YAML has been added
    to the source repo, step 1 is a no-op (file already present). For existing projects or
    the first run on a source repo, step 1 commits the template.

.PARAMETER Organization
    Azure DevOps organization name (e.g. "my-org" from dev.azure.com/my-org)

.PARAMETER Project
    Azure DevOps project name

.PARAMETER RepositoryName
    Name of the repository to configure

.PARAMETER ProjectType
    Template to use if the YAML does not already exist in the repository.
    Valid values: DataPlatform, FabricAccelerator
    Required when the YAML is not already present.

.PARAMETER YamlPath
    Path for the PR validation YAML within the repository.
    Default: "pipelines/pr-validation.yml"

.PARAMETER Branch
    Branch to protect with the build validation policy. Default: "main"

.PARAMETER PipelineName
    Display name for the pipeline definition. Default: "PR Validation"

.PARAMETER Force
    Skip confirmation prompts

.EXAMPLE
    # New project — YAML not yet in repo, commit template and wire up pipeline
    .\Add-PrValidationPipeline.ps1 `
        -Organization   "my-org" `
        -Project        "Acme Corp" `
        -RepositoryName "DataLandingZone_bicepavm" `
        -ProjectType    "DataPlatform" `
        -Force

.EXAMPLE
    # Existing project with YAML already in repo — skip commit, just create pipeline + policy
    .\Add-PrValidationPipeline.ps1 `
        -Organization   "my-org" `
        -Project        "Acme Corp" `
        -RepositoryName "DataLandingZone_bicepavm" `
        -Force

.NOTES
    Author: Andrew Wood
    Version: 1.0

    Prerequisites:
    - Connect-AzAccount (recommended) or AZURE_DEVOPS_EXT_PAT
    - Project Administrator permissions on the target project

    After running:
    - Set the 'ServiceConnection' pipeline variable once a service connection exists
      to enable the Bicep what-if validation stage.
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
    [ValidateSet("DataPlatform", "FabricAccelerator")]
    [string]$ProjectType,

    [Parameter(Mandatory = $false)]
    [string]$YamlPath = "pipelines/pr-validation.yml",

    [Parameter(Mandatory = $false)]
    [string]$Branch = "main",

    [Parameter(Mandatory = $false)]
    [string]$PipelineName = "PR Validation",

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$scriptRoot = $PSScriptRoot

. "$scriptRoot\..\security\_Helpers.ps1"

$yamlTemplateMap = @{
    DataPlatform      = "pr-validation-data-platform.yml"
    FabricAccelerator = "pr-validation-fabric-accelerator.yml"
}

Write-Host ""
Write-Host "=== PR Validation Pipeline Setup ===" -ForegroundColor Cyan
Write-Host "  Organisation : $Organization" -ForegroundColor White
Write-Host "  Project      : $Project" -ForegroundColor White
Write-Host "  Repository   : $RepositoryName" -ForegroundColor White
Write-Host "  YAML path    : $YamlPath" -ForegroundColor White
Write-Host "  Branch       : $Branch" -ForegroundColor White
Write-Host "  Pipeline     : $PipelineName" -ForegroundColor White
Write-Host ""

if (-not $Force -and -not $WhatIfPreference) {
    $confirmation = Read-Host "Continue? (yes/no)"
    if ($confirmation -ne "yes") {
        Write-Host "Cancelled." -ForegroundColor Yellow
        exit 0
    }
}

$authHeader = Get-AzureDevOpsAuthHeader
$base       = "https://dev.azure.com/$Organization/$([Uri]::EscapeDataString($Project))"

# Resolve project ID (needed for repo-level ACL token)
$projectDetails = Invoke-AzureDevOpsApi -Uri "https://dev.azure.com/$Organization/_apis/projects/$([Uri]::EscapeDataString($Project))?api-version=7.1" -AuthHeader $authHeader
$projectId      = $projectDetails.id

# ── Step 1: Commit YAML if not already in the repo ─────────────────────────────
Write-Host "[1/3] Checking for $YamlPath in $RepositoryName..." -ForegroundColor Yellow

$repoUrl = "$base/_apis/git/repositories/$([Uri]::EscapeDataString($RepositoryName))?api-version=7.1"
$repo    = Invoke-AzureDevOpsApi -Uri $repoUrl -AuthHeader $authHeader
$repoId  = $repo.id

$fileExists = $false
try {
    $encodedPath = [Uri]::EscapeDataString("/$YamlPath")
    Invoke-AzureDevOpsApi -Uri "$base/_apis/git/repositories/$repoId/items?path=$encodedPath&api-version=7.1" -AuthHeader $authHeader | Out-Null
    $fileExists = $true
}
catch { }

if ($fileExists) {
    Write-Host "  ✓ $YamlPath already present — skipping commit" -ForegroundColor Green
}
else {
    if (-not $ProjectType) {
        Write-Error "$YamlPath does not exist in $RepositoryName and -ProjectType was not specified. " +
                    "Provide -ProjectType DataPlatform or FabricAccelerator to commit the template."
        exit 1
    }

    $templateFile = $yamlTemplateMap[$ProjectType]
    $templatePath = Resolve-Path "$scriptRoot\..\..\pipelines\$templateFile"

    if (-not (Test-Path $templatePath)) {
        Write-Error "YAML template not found at: $templatePath"
        exit 1
    }

    Write-Host "  ℹ  Not found — committing template from $templateFile" -ForegroundColor Yellow

    # Get current HEAD SHA of the branch
    $refs    = Invoke-AzureDevOpsApi -Uri "$base/_apis/git/repositories/$repoId/refs?filter=heads/$Branch&api-version=7.1" -AuthHeader $authHeader
    $headSha = ($refs.value | Where-Object { $_.name -eq "refs/heads/$Branch" }).objectId

    if (-not $headSha) {
        Write-Error "Could not find branch '$Branch' in repository '$RepositoryName'"
        exit 1
    }

    $yamlContent = Get-Content -Raw -Path $templatePath
    $yamlBase64  = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($yamlContent))

    $commitBody = @{
        comment = "Add PR validation pipeline [skip ci]"
        changes = @(@{
            changeType = "add"
            item       = @{ path = "/$YamlPath" }
            newContent = @{ content = $yamlBase64; contentType = "base64Encoded" }
        })
    }

    if ($PSCmdlet.ShouldProcess("$RepositoryName/$YamlPath", "Commit PR validation YAML directly to $Branch")) {
        # Explicitly grant PolicyExempt + PullRequestBypassPolicy to Project Administrators at the
        # repo-level token. This overrides the project-level deny inherited from the Contributors
        # group, ensuring admins can push directly to main bypassing branch policies.
        Write-Host "  Granting bypass permissions to Project Administrators at repo level..." -ForegroundColor Gray
        $repoNamespaceId = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87"
        $repoToken       = "repoV2/$projectId/$repoId"
        $paIdentityUrl   = "https://vssps.dev.azure.com/$Organization/_apis/identities?searchFilter=General&filterValue=$([Uri]::EscapeDataString("[$Project]\Project Administrators"))&queryMembership=None&api-version=7.1-preview.1"
        $paIdentity      = (Invoke-AzureDevOpsApi -Uri $paIdentityUrl -AuthHeader $authHeader).value | Select-Object -First 1
        if ($paIdentity) {
            $bypassAclBody = @{
                token                = $repoToken
                merge                = $true
                accessControlEntries = @(@{ descriptor = $paIdentity.descriptor; allow = 32896; deny = 0 })
            }
            Invoke-AzureDevOpsApi -Uri "https://dev.azure.com/$Organization/_apis/accesscontrolentries/$repoNamespaceId`?api-version=7.1" `
                -Method Post -Body $bypassAclBody -AuthHeader $authHeader | Out-Null
            Write-Host "  ✓ PolicyExempt(128) + PullRequestBypassPolicy(32768) granted to Project Administrators" -ForegroundColor Green
        } else {
            Write-Warning "  Could not resolve Project Administrators group — push may still be blocked by branch policy"
        }

        # Push directly to main using git — Project Administrators now have PolicyExempt at repo level.
        $tempDir      = Join-Path ([System.IO.Path]::GetTempPath()) "pr-yaml-$([System.Guid]::NewGuid().ToString().Substring(0,8))"
        $token        = (az account get-access-token --resource "499b84ac-1321-427f-aa17-267ca6975798" --query accessToken -o tsv)
        $repoCloneUrl = "https://x:$token@dev.azure.com/$Organization/$([Uri]::EscapeDataString($Project))/_git/$([Uri]::EscapeDataString($RepositoryName))"

        try {
            Write-Host "  Cloning $RepositoryName..." -ForegroundColor Gray
            git -c credential.helper="" clone --depth 1 --branch $Branch $repoCloneUrl $tempDir
            if ($LASTEXITCODE -ne 0) { throw "git clone failed (exit $LASTEXITCODE)" }

            $destFile = Join-Path $tempDir ($YamlPath -replace '/', '\')
            New-Item -ItemType Directory -Force -Path (Split-Path $destFile) | Out-Null
            Copy-Item $templatePath $destFile

            Push-Location $tempDir
            git add ($YamlPath -replace '/', '\')
            git commit -m "Add PR validation pipeline [skip ci]"
            if ($LASTEXITCODE -ne 0) { throw "git commit failed (exit $LASTEXITCODE)" }

            git -c credential.helper="" push origin $Branch
            if ($LASTEXITCODE -ne 0) { throw "git push failed (exit $LASTEXITCODE) — ensure you have Project Administrator rights on this project" }

            Pop-Location
            Write-Host "  ✓ Committed directly to $Branch`: $YamlPath" -ForegroundColor Green
        }
        finally {
            if ((Get-Location).Path -eq $tempDir) { Pop-Location }
            Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
        }
    }
}

# ── Step 2: Create the pipeline definition ─────────────────────────────────────
Write-Host ""
Write-Host "[2/3] Creating pipeline definition '$PipelineName'..." -ForegroundColor Yellow

$pipelineScript = Join-Path $scriptRoot "New-AzureDevOpsPipeline.ps1"

if ($PSCmdlet.ShouldProcess("$Project/$PipelineName", "Create pipeline definition")) {
    & $pipelineScript `
        -Organization   $Organization `
        -Project        $Project `
        -PipelineName   $PipelineName `
        -RepositoryName $RepositoryName `
        -YamlPath       $YamlPath `
        -Branch         $Branch `
        -EnableCI       $false `
        -EnablePR       $true `
        -Force
}

# Resolve pipeline ID by name (New-AzureDevOpsPipeline writes it to host but does not return it)
$pipelines  = Invoke-AzureDevOpsApi -Uri "$base/_apis/pipelines?api-version=7.1" -AuthHeader $authHeader
$pipelineId = ($pipelines.value | Where-Object { $_.name -eq $PipelineName } | Select-Object -First 1).id

if (-not $pipelineId) {
    Write-Warning "Could not resolve pipeline ID for '$PipelineName'."
    Write-Warning "Apply the branch policy manually once the pipeline exists:"
    Write-Warning "  Set-AzureDevOpsBranchPolicies.ps1 -BuildPipelineId <id> ..."
    exit 1
}

Write-Host "  ✓ Pipeline ID: $pipelineId" -ForegroundColor Green

# ── Step 3: Apply build validation branch policy ───────────────────────────────
Write-Host ""
Write-Host "[3/3] Applying build validation branch policy on $RepositoryName/$Branch..." -ForegroundColor Yellow

$policyScript = Join-Path $scriptRoot "..\security\Set-AzureDevOpsBranchPolicies.ps1"

if ($PSCmdlet.ShouldProcess("$RepositoryName/$Branch", "Apply build validation branch policy")) {
    & $policyScript `
        -Organization     $Organization `
        -Project          $Project `
        -RepositoryName   $RepositoryName `
        -Branch           $Branch `
        -BuildPipelineId  $pipelineId `
        -BuildDisplayName $PipelineName `
        -Force
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Green
Write-Host "  Build validation policy applied: $PipelineName (ID: $pipelineId)" -ForegroundColor White
Write-Host ""
Write-Host "  Next: set the 'ServiceConnection' pipeline variable in Azure DevOps" -ForegroundColor Yellow
Write-Host "  once a service connection exists to enable the Bicep what-if stage." -ForegroundColor Yellow
Write-Host ""
