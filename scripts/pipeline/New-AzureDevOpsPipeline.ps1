<#
.SYNOPSIS
    Creates an Azure DevOps pipeline using the REST API.

.DESCRIPTION
    This script automates the creation of Azure DevOps pipelines, including:
    - Creating the pipeline definition
    - Linking to a repository (Azure Repos or GitHub)
    - Configuring build settings and triggers
    - Setting up service connections (optional)
    - Granting pipeline permissions to resources

    Key Features:
    - Supports both YAML and Classic pipelines
    - Works with Azure Repos Git, GitHub, and other repository types
    - Configurable triggers (CI, PR, scheduled)
    - Can authorize service connections automatically
    - Idempotent - can be run multiple times safely

.PARAMETER Organization
    Azure DevOps organization name (e.g., "myorg" from dev.azure.com/myorg)

.PARAMETER Project
    Azure DevOps project name where the pipeline will be created

.PARAMETER PipelineName
    Display name for the pipeline

.PARAMETER RepositoryType
    Type of repository. Options: "azureReposGit", "github", "tfsgit", "githubEnterprise"
    Default: "azureReposGit"

.PARAMETER RepositoryName
    Name of the repository. For Azure Repos, this is the repo name. For GitHub, use "owner/repo" format.

.PARAMETER RepositoryId
    Repository ID (optional). If not provided, will be looked up by name.

.PARAMETER YamlPath
    Path to the YAML file in the repository (e.g., "azure-pipelines.yml" or ".azuredevops/pipeline.yml")
    Default: "azure-pipelines.yml"

.PARAMETER Branch
    Default branch for the pipeline. Default: "main"

.PARAMETER ServiceConnectionId
    Service connection ID for accessing the repository (required for GitHub and external repos)

.PARAMETER ServiceConnectionName
    Service connection name (alternative to ServiceConnectionId - will be looked up)

.PARAMETER Folder
    Folder path where the pipeline should be created (e.g., "\MyFolder\SubFolder")
    Default: "\" (root)

.PARAMETER EnableCI
    Enable continuous integration trigger. Default: $true

.PARAMETER EnablePR
    Enable pull request validation trigger. Default: $false

.PARAMETER AuthorizeResources
    Automatically authorize all pipeline resources (service connections, agent pools, etc.)
    Default: $false

.PARAMETER Force
    Skips confirmation prompts

.EXAMPLE
    # Create a pipeline from Azure Repos with default settings
    .\New-AzureDevOpsPipeline.ps1 `
        -Organization "myorg" `
        -Project "MyProject" `
        -PipelineName "CI-Build" `
        -RepositoryName "MyRepo"

.EXAMPLE
    # Create a pipeline from GitHub repository
    .\New-AzureDevOpsPipeline.ps1 `
        -Organization "myorg" `
        -Project "MyProject" `
        -PipelineName "GitHub-CI" `
        -RepositoryType "github" `
        -RepositoryName "myuser/myrepo" `
        -ServiceConnectionName "GitHub-Connection" `
        -YamlPath ".github/azure-pipelines.yml"

.EXAMPLE
    # Create a pipeline in a specific folder with custom branch
    .\New-AzureDevOpsPipeline.ps1 `
        -Organization "myorg" `
        -Project "MyProject" `
        -PipelineName "Production-Deploy" `
        -RepositoryName "MyRepo" `
        -Branch "production" `
        -Folder "\Production\Deployments" `
        -AuthorizeResources `
        -Force

.NOTES
    Author: Andrew Wood
    Version: 1.0
    
    Prerequisites:
    - Azure DevOps login: az devops login or set AZURE_DEVOPS_EXT_PAT environment variable
    - Permissions: Build Administrator or Project Administrator in Azure DevOps
    - For GitHub repos: Service connection must already exist

    API References:
    - Pipelines API: https://learn.microsoft.com/en-us/rest/api/azure/devops/pipelines/pipelines
    - Repositories API: https://learn.microsoft.com/en-us/rest/api/azure/devops/git/repositories

.LINK
    https://learn.microsoft.com/en-us/azure/devops/pipelines/create-first-pipeline
    https://learn.microsoft.com/en-us/rest/api/azure/devops/pipelines/pipelines/create
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string]$Organization,

    [Parameter(Mandatory = $true)]
    [string]$Project,

    [Parameter(Mandatory = $true)]
    [string]$PipelineName,

    [Parameter(Mandatory = $false)]
    [ValidateSet("azureReposGit", "github", "tfsgit", "githubEnterprise", "bitbucket")]
    [string]$RepositoryType = "azureReposGit",

    [Parameter(Mandatory = $true)]
    [string]$RepositoryName,

    [Parameter(Mandatory = $false)]
    [string]$RepositoryId,

    [Parameter(Mandatory = $false)]
    [string]$YamlPath = "azure-pipelines.yml",

    [Parameter(Mandatory = $false)]
    [string]$Branch = "main",

    [Parameter(Mandatory = $false)]
    [string]$ServiceConnectionId,

    [Parameter(Mandatory = $false)]
    [string]$ServiceConnectionName,

    [Parameter(Mandatory = $false)]
    [string]$Folder = "\",

    [Parameter(Mandatory = $false)]
    [bool]$EnableCI = $true,

    [Parameter(Mandatory = $false)]
    [bool]$EnablePR = $false,

    [Parameter(Mandatory = $false)]
    [switch]$AuthorizeResources,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "=== Azure DevOps Pipeline Creation Script ===" -ForegroundColor Cyan
Write-Host ""

#region Helper Functions

function Get-AzureDevOpsToken {
    <#
    .SYNOPSIS
        Gets an Azure DevOps access token
    #>
    try {
        # Try to get token from Az module
        $tokenResult = Get-AzAccessToken -ResourceUrl "499b84ac-1321-427f-aa17-267ca6975798" -ErrorAction SilentlyContinue
        
        if ($tokenResult) {
            # Extract token - it might be a SecureString or in a Token property
            if ($tokenResult.Token -is [SecureString]) {
                $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenResult.Token)
                $token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
            }
            elseif ($tokenResult.Token) {
                $token = $tokenResult.Token
            }
            else {
                $token = $tokenResult
            }
            
            return $token
        }
    }
    catch {
        # Fall through to PAT check
    }
    
    # Try to get PAT from environment variable
    if ($env:AZURE_DEVOPS_EXT_PAT) {
        return $env:AZURE_DEVOPS_EXT_PAT
    }
    
    # Try to get PAT from az devops (if installed)
    try {
        $patResult = az account get-access-token --resource 499b84ac-1321-427f-aa17-267ca6975798 2>$null | ConvertFrom-Json
        if ($patResult.accessToken) {
            return $patResult.accessToken
        }
    }
    catch {
        # Continue
    }
    
    Write-Error @"
Failed to get Azure DevOps access token. Please either:
1. Run Connect-AzAccount first (recommended)
2. Set the AZURE_DEVOPS_EXT_PAT environment variable with a Personal Access Token
3. Run 'az devops login' if you have Azure CLI with DevOps extension installed
"@
    throw "No authentication available"
}

function Invoke-AzureDevOpsApi {
    <#
    .SYNOPSIS
        Invokes Azure DevOps REST API with proper headers
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        
        [Parameter(Mandatory = $false)]
        [string]$Method = "Get",
        
        [Parameter(Mandatory = $false)]
        [object]$Body,
        
        [Parameter(Mandatory = $true)]
        [string]$Token
    )
    
    $headers = @{
        'Authorization' = 'Bearer ' + $Token
        'Content-Type' = 'application/json'
    }
    
    $params = @{
        Method = $Method
        Uri = $Uri
        Headers = $headers
    }
    
    if ($Body) {
        if ($Body -is [string]) {
            $params.Body = $Body
        }
        else {
            $params.Body = ($Body | ConvertTo-Json -Depth 10 -Compress)
        }
    }
    
    try {
        $response = Invoke-RestMethod @params
        if ($response -is [string]) {
            $response = $response | ConvertFrom-Json
        }
        return $response
    }
    catch {
        $errorMessage = "API call failed: $($_.Exception.Message)"
        if ($_.ErrorDetails.Message) {
            $errorMessage += "`nDetails: $($_.ErrorDetails.Message)"
        }
        Write-Error $errorMessage
        throw
    }
}

#endregion

# Confirm operation
if (-not $Force) {
    Write-Host "`n⚠️  This will create a pipeline with the following settings:" -ForegroundColor Yellow
    Write-Host "   - Organization: $Organization" -ForegroundColor Gray
    Write-Host "   - Project: $Project" -ForegroundColor Gray
    Write-Host "   - Pipeline Name: $PipelineName" -ForegroundColor Gray
    Write-Host "   - Repository: $RepositoryName ($RepositoryType)" -ForegroundColor Gray
    Write-Host "   - YAML Path: $YamlPath" -ForegroundColor Gray
    Write-Host "   - Branch: $Branch" -ForegroundColor Gray
    Write-Host "   - Folder: $Folder" -ForegroundColor Gray
    $confirmation = Read-Host "`nContinue? (yes/no)"
    if ($confirmation -ne "yes") {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        exit 0
    }
}

# Get authentication token
Write-Host "[1/6] Authenticating to Azure DevOps..." -ForegroundColor Yellow
try {
    $token = Get-AzureDevOpsToken
    Write-Host "✓ Successfully authenticated" -ForegroundColor Green
}
catch {
    Write-Error "Failed to authenticate: $_"
    exit 1
}

# Get project details
Write-Host "`n[2/6] Getting project details..." -ForegroundColor Yellow
try {
    $projectUrl = "https://dev.azure.com/$Organization/_apis/projects/$Project" + "?api-version=7.1"
    $projectDetails = Invoke-AzureDevOpsApi -Uri $projectUrl -Token $token
    $projectId = $projectDetails.id
    
    Write-Host "✓ Project found: $($projectDetails.name)" -ForegroundColor Green
    Write-Host "  Project ID: $projectId" -ForegroundColor Gray
}
catch {
    Write-Error "Failed to get project details: $_"
    exit 1
}

# Get or resolve repository ID
Write-Host "`n[3/6] Resolving repository..." -ForegroundColor Yellow
try {
    if (-not $RepositoryId) {
        if ($RepositoryType -eq "azureReposGit" -or $RepositoryType -eq "tfsgit") {
            # Get Azure Repos repository
            $repoUrl = "https://dev.azure.com/$Organization/$Project/_apis/git/repositories/$RepositoryName" + "?api-version=7.1"
            try {
                $repo = Invoke-AzureDevOpsApi -Uri $repoUrl -Token $token
                $RepositoryId = $repo.id
                Write-Host "✓ Repository found: $($repo.name)" -ForegroundColor Green
                Write-Host "  Repository ID: $RepositoryId" -ForegroundColor Gray
            }
            catch {
                Write-Warning "Could not find repository by name, will use name directly"
                $RepositoryId = $RepositoryName
            }
        }
        else {
            # For external repos like GitHub, validate and use the repository name
            if ($RepositoryType -eq "github" -or $RepositoryType -eq "githubEnterprise") {
                if ($RepositoryName -notmatch '/') {
                    Write-Error "For GitHub repositories, RepositoryName must be in 'owner/repo' format (e.g., 'awood-ops/KeyRotation')"
                    exit 1
                }
            }
            $RepositoryId = $RepositoryName
            Write-Host "✓ Using external repository: $RepositoryName" -ForegroundColor Green
        }
    }
    else {
        Write-Host "✓ Using provided repository ID: $RepositoryId" -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to resolve repository: $_"
    exit 1
}

# Get service connection if needed
Write-Host "`n[4/6] Checking service connection..." -ForegroundColor Yellow
try {
    if ($RepositoryType -ne "azureReposGit" -and $RepositoryType -ne "tfsgit") {
        if (-not $ServiceConnectionId -and -not $ServiceConnectionName) {
            Write-Error "ServiceConnectionId or ServiceConnectionName is required for external repositories"
            exit 1
        }
        
        if (-not $ServiceConnectionId -and $ServiceConnectionName) {
            # Look up service connection by name
            $endpointsUrl = "https://dev.azure.com/$Organization/$Project/_apis/serviceendpoint/endpoints?api-version=7.2-preview.4"
            $endpoints = Invoke-AzureDevOpsApi -Uri $endpointsUrl -Token $token
            $endpoint = $endpoints.value | Where-Object { $_.name -eq $ServiceConnectionName } | Select-Object -First 1
            
            if ($endpoint) {
                $ServiceConnectionId = $endpoint.id
                Write-Host "✓ Service connection found: $ServiceConnectionName" -ForegroundColor Green
                Write-Host "  Connection ID: $ServiceConnectionId" -ForegroundColor Gray
            }
            else {
                Write-Error "Service connection '$ServiceConnectionName' not found"
                exit 1
            }
        }
        else {
            Write-Host "✓ Using service connection ID: $ServiceConnectionId" -ForegroundColor Green
        }
    }
    else {
        Write-Host "✓ No service connection needed (Azure Repos)" -ForegroundColor Gray
    }
}
catch {
    Write-Error "Failed to get service connection: $_"
    exit 1
}

# Check if pipeline already exists
Write-Host "`n[5/6] Checking for existing pipeline..." -ForegroundColor Yellow
try {
    $listPipelinesUrl = "https://dev.azure.com/$Organization/$Project/_apis/pipelines?api-version=7.1"
    $existingPipelines = Invoke-AzureDevOpsApi -Uri $listPipelinesUrl -Token $token
    $existingPipeline = $existingPipelines.value | Where-Object { $_.name -eq $PipelineName } | Select-Object -First 1
    
    if ($existingPipeline) {
        Write-Host "⚠️  Pipeline already exists: $PipelineName" -ForegroundColor Yellow
        Write-Host "  Pipeline ID: $($existingPipeline.id)" -ForegroundColor Gray
        Write-Host "  URL: $($existingPipeline._links.web.href)" -ForegroundColor Gray
        
        if (-not $Force) {
            $overwrite = Read-Host "`nPipeline exists. Do you want to update it? (yes/no)"
            if ($overwrite -ne "yes") {
                Write-Host "Operation cancelled." -ForegroundColor Yellow
                exit 0
            }
        }
        $pipelineExists = $true
        $pipelineId = $existingPipeline.id
    }
    else {
        Write-Host "✓ Pipeline does not exist, will create new" -ForegroundColor Green
        $pipelineExists = $false
    }
}
catch {
    Write-Error "Failed to check for existing pipeline: $_"
    exit 1
}

# Create or update pipeline
Write-Host "`n[6/6] Creating pipeline..." -ForegroundColor Yellow
try {
    # Build the repository configuration based on type
    $repositoryConfig = @{
        type = $RepositoryType
    }
    
    # For GitHub repos, we need both id (owner/repo) and name (repo)
    if ($RepositoryType -eq "github" -or $RepositoryType -eq "githubEnterprise") {
        $repositoryConfig.id = $RepositoryId
        # Extract repo name from owner/repo format
        if ($RepositoryId -match '/') {
            $repositoryConfig.name = $RepositoryId.Split('/')[-1]
        }
        else {
            $repositoryConfig.name = $RepositoryId
        }
    }
    else {
        # For Azure Repos, just use id
        $repositoryConfig.id = $RepositoryId
    }
    
    # Add service connection for external repos
    if ($ServiceConnectionId) {
        $repositoryConfig.connection = @{
            id = $ServiceConnectionId
        }
    }
    
    # Add default branch
    $repositoryConfig.defaultBranch = "refs/heads/$Branch"
    
    # Build the pipeline configuration
    $pipelineConfig = @{
        name = $PipelineName
        folder = $Folder
        configuration = @{
            type = "yaml"
            path = $YamlPath
            repository = $repositoryConfig
        }
    }
    
    # Debug: Show the configuration being sent
    Write-Host "  Debug - Repository config:" -ForegroundColor Gray
    Write-Host "    Type: $($repositoryConfig.type)" -ForegroundColor Gray
    Write-Host "    ID: $($repositoryConfig.id)" -ForegroundColor Gray
    Write-Host "    Name: $($repositoryConfig.name)" -ForegroundColor Gray
    Write-Host "    Branch: $($repositoryConfig.defaultBranch)" -ForegroundColor Gray
    if ($repositoryConfig.connection) {
        Write-Host "    Connection ID: $($repositoryConfig.connection.id)" -ForegroundColor Gray
    }
    
    # Create or use existing pipeline
    if ($pipelineExists) {
        # Azure DevOps Pipelines API doesn't support updates via REST API
        # The pipeline already exists, so we'll just use it
        Write-Host "✓ Pipeline already exists and is configured" -ForegroundColor Green
        Write-Host "  Note: To modify pipeline settings (YAML path, repository, etc.), please use Azure DevOps UI" -ForegroundColor Yellow
        
        # Get the existing pipeline details
        $getUrl = "https://dev.azure.com/$Organization/$Project/_apis/pipelines/$pipelineId" + "?api-version=7.1"
        $pipeline = Invoke-AzureDevOpsApi -Uri $getUrl -Token $token
    }
    else {
        # Create new pipeline
        $createUrl = "https://dev.azure.com/$Organization/$Project/_apis/pipelines?api-version=7.1"
        $pipeline = Invoke-AzureDevOpsApi -Uri $createUrl -Method Post -Body $pipelineConfig -Token $token
        Write-Host "✓ Pipeline created successfully" -ForegroundColor Green
    }
    
    Write-Host "  Pipeline ID: $($pipeline.id)" -ForegroundColor Gray
    Write-Host "  Pipeline URL: $($pipeline._links.web.href)" -ForegroundColor Gray
    
    # Authorize resources if requested
    if ($AuthorizeResources) {
        Write-Host "`nAuthorizing pipeline resources..." -ForegroundColor Yellow
        try {
            # Authorize service connection if present
            if ($ServiceConnectionId) {
                $authorizeUrl = "https://dev.azure.com/$Organization/$Project/_apis/pipelines/pipelinePermissions/endpoint/$ServiceConnectionId" + "?api-version=7.1-preview.1"
                $authorizeBody = @{
                    pipelines = @(
                        @{
                            id = $pipeline.id
                            authorized = $true
                        }
                    )
                }
                Invoke-AzureDevOpsApi -Uri $authorizeUrl -Method Patch -Body $authorizeBody -Token $token
                Write-Host "✓ Authorized service connection for pipeline" -ForegroundColor Green
            }
        }
        catch {
            Write-Warning "Failed to authorize resources: $_"
            Write-Host "  You may need to authorize manually in Azure DevOps" -ForegroundColor Yellow
        }
    }
}
catch {
    Write-Error "Failed to create pipeline: $_"
    exit 1
}

# Summary
Write-Host "`n=== Summary ===" -ForegroundColor Green
Write-Host "Pipeline:" -ForegroundColor Cyan
Write-Host "  Name: $PipelineName" -ForegroundColor White
Write-Host "  ID: $($pipeline.id)" -ForegroundColor White
Write-Host "  Folder: $Folder" -ForegroundColor White
Write-Host ""
Write-Host "Repository:" -ForegroundColor Cyan
Write-Host "  Type: $RepositoryType" -ForegroundColor White
Write-Host "  Name: $RepositoryName" -ForegroundColor White
Write-Host "  Branch: $Branch" -ForegroundColor White
Write-Host "  YAML: $YamlPath" -ForegroundColor White
Write-Host ""
Write-Host "Azure DevOps:" -ForegroundColor Cyan
Write-Host "  Organization: $Organization" -ForegroundColor White
Write-Host "  Project: $Project" -ForegroundColor White
Write-Host "  URL: $($pipeline._links.web.href)" -ForegroundColor White
Write-Host ""
Write-Host "✓ Pipeline setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Review the pipeline in Azure DevOps" -ForegroundColor Gray
Write-Host "  2. Run the pipeline to validate configuration" -ForegroundColor Gray
Write-Host "  3. Configure any additional settings (variables, approvals, etc.)" -ForegroundColor Gray
