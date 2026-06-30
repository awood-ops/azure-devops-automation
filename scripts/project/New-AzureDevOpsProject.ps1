<#
.SYNOPSIS
    Creates an Azure DevOps project using the REST API.

.DESCRIPTION
    This script automates the creation of Azure DevOps projects, including:
    - Creating the project with specified process template
    - Configuring version control (Git or TFVC)
    - Setting visibility (public or private)
    - Configuring project description and capabilities

    Key Features:
    - Supports Agile, Scrum, CMMI, and Basic process templates
    - Configures Git or TFVC version control
    - Sets project visibility (public/private)
    - Idempotent - can be run multiple times safely
    - Waits for project creation to complete
    - Enables GitHub Advanced Security for Azure DevOps (GHAzDO) push protection by default

.PARAMETER Organization
    Azure DevOps organization name (e.g., "myorg" from dev.azure.com/myorg)

.PARAMETER ProjectName
    Name for the new project

.PARAMETER Description
    Description of the project (optional)

.PARAMETER ProcessTemplate
    Process template to use. Options: "Agile", "Scrum", "CMMI", "Basic"
    Default: "Agile"

.PARAMETER VersionControl
    Version control system. Options: "Git", "Tfvc"
    Default: "Git"

.PARAMETER Visibility
    Project visibility. Options: "private", "public"
    Default: "private"

.PARAMETER WaitForCompletion
    Wait for project creation to complete before returning
    Default: $true

.PARAMETER TimeoutSeconds
    Maximum time to wait for project creation (in seconds)
    Default: 300 (5 minutes)

.PARAMETER EnableAdvancedSecurity
    Enable GitHub Advanced Security for Azure DevOps (GHAzDO) with push protection (credential scanning)
    Default: $true

.PARAMETER Force
    Skips confirmation prompts

.EXAMPLE
    # Create a basic project with default settings
    .\New-AzureDevOpsProject.ps1 `
        -Organization "myorg" `
        -ProjectName "MyNewProject"

.EXAMPLE
    # Create a Scrum project with description
    .\New-AzureDevOpsProject.ps1 `
        -Organization "myorg" `
        -ProjectName "MyProject" `
        -Description "My awesome project" `
        -ProcessTemplate "Scrum" `
        -Force

.EXAMPLE
    # Create a public project with TFVC
    .\New-AzureDevOpsProject.ps1 `
        -Organization "myorg" `
        -ProjectName "PublicProject" `
        -Description "Open source project" `
        -ProcessTemplate "Agile" `
        -VersionControl "Tfvc" `
        -Visibility "public"

.NOTES
    Author: Andrew Wood
    Version: 1.0
    
    Prerequisites:
    - Azure DevOps login: az devops login or set AZURE_DEVOPS_EXT_PAT environment variable
    - Permissions: Project Collection Administrator or Organization Owner
    
    API References:
    - Projects API: https://learn.microsoft.com/en-us/rest/api/azure/devops/core/projects
    - Processes API: https://learn.microsoft.com/en-us/rest/api/azure/devops/processes/processes

.LINK
    https://learn.microsoft.com/en-us/azure/devops/organizations/projects/create-project
    https://learn.microsoft.com/en-us/rest/api/azure/devops/core/projects/create
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string]$Organization,

    [Parameter(Mandatory = $true)]
    [string]$ProjectName,

    [Parameter(Mandatory = $false)]
    [string]$Description = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Agile", "Scrum", "CMMI", "Basic")]
    [string]$ProcessTemplate = "Agile",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Git", "Tfvc")]
    [string]$VersionControl = "Git",

    [Parameter(Mandatory = $false)]
    [ValidateSet("private", "public")]
    [string]$Visibility = "private",

    [Parameter(Mandatory = $false)]
    [bool]$WaitForCompletion = $true,

    [Parameter(Mandatory = $false)]
    [int]$TimeoutSeconds = 300,

    [Parameter(Mandatory = $false)]
    [bool]$EnableAdvancedSecurity = $true,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "=== Azure DevOps Project Creation Script ===" -ForegroundColor Cyan
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
        Write-Verbose "Az module token unavailable: $_"
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
        Write-Verbose "az CLI token unavailable: $_"
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
    Write-Host "`n⚠️  This will create a project with the following settings:" -ForegroundColor Yellow
    Write-Host "   - Organization: $Organization" -ForegroundColor Gray
    Write-Host "   - Project Name: $ProjectName" -ForegroundColor Gray
    Write-Host "   - Process Template: $ProcessTemplate" -ForegroundColor Gray
    Write-Host "   - Version Control: $VersionControl" -ForegroundColor Gray
    Write-Host "   - Visibility: $Visibility" -ForegroundColor Gray
    Write-Host "   - Advanced Security (GHAzDO): $(if ($EnableAdvancedSecurity) { 'Enabled' } else { 'Skipped' })" -ForegroundColor Gray
    if ($Description) {
        Write-Host "   - Description: $Description" -ForegroundColor Gray
    }
    $confirmation = Read-Host "`nContinue? (yes/no)"
    if ($confirmation -ne "yes") {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        exit 0
    }
}

# Get authentication token
Write-Host "[1/5] Authenticating to Azure DevOps..." -ForegroundColor Yellow
try {
    $token = Get-AzureDevOpsToken
    Write-Host "✓ Successfully authenticated" -ForegroundColor Green
}
catch {
    Write-Error "Failed to authenticate: $_"
    exit 1
}

# Check if project already exists
Write-Host "`n[2/5] Checking for existing project..." -ForegroundColor Yellow
try {
    $checkUrl = "https://dev.azure.com/$Organization/_apis/projects/$ProjectName" + "?api-version=7.1"
    try {
        $existingProject = Invoke-AzureDevOpsApi -Uri $checkUrl -Token $token
        
        Write-Host "⚠️  Project already exists: $ProjectName" -ForegroundColor Yellow
        Write-Host "  Project ID: $($existingProject.id)" -ForegroundColor Gray
        Write-Host "  State: $($existingProject.state)" -ForegroundColor Gray
        Write-Host "  URL: $($existingProject.url)" -ForegroundColor Gray
        
        Write-Host "`n✓ Project is already available" -ForegroundColor Green
        exit 0
    }
    catch {
        # Project doesn't exist - this is expected, continue
        Write-Host "✓ Project does not exist, will create new" -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to check for existing project: $_"
    exit 1
}

# Get process template ID
Write-Host "`n[3/5] Getting process template..." -ForegroundColor Yellow
try {
    $processesUrl = "https://dev.azure.com/$Organization/_apis/process/processes?api-version=7.1"
    $processes = Invoke-AzureDevOpsApi -Uri $processesUrl -Token $token
    
    $process = $processes.value | Where-Object { $_.name -eq $ProcessTemplate } | Select-Object -First 1
    
    if (-not $process) {
        Write-Error "Process template '$ProcessTemplate' not found"
        exit 1
    }
    
    $processId = $process.id
    Write-Host "✓ Process template found: $ProcessTemplate" -ForegroundColor Green
    Write-Host "  Process ID: $processId" -ForegroundColor Gray
}
catch {
    Write-Error "Failed to get process template: $_"
    exit 1
}

# Create project
Write-Host "`n[4/5] Creating project..." -ForegroundColor Yellow
try {
    $createUrl = "https://dev.azure.com/$Organization/_apis/projects?api-version=7.1"
    
    $projectConfig = @{
        name = $ProjectName
        description = $Description
        visibility = $Visibility
        capabilities = @{
            versioncontrol = @{
                sourceControlType = $VersionControl
            }
            processTemplate = @{
                templateTypeId = $processId
            }
        }
    }
    
    # Create the project
    $operation = Invoke-AzureDevOpsApi -Uri $createUrl -Method Post -Body $projectConfig -Token $token
    
    Write-Host "✓ Project creation initiated" -ForegroundColor Green
    Write-Host "  Operation ID: $($operation.id)" -ForegroundColor Gray
    Write-Host "  Status: $($operation.status)" -ForegroundColor Gray
    
    # Wait for project creation to complete
    if ($WaitForCompletion) {
        Write-Host "`nWaiting for project creation to complete..." -ForegroundColor Yellow
        
        $operationUrl = $operation.url
        $startTime = Get-Date
        $completed = $false
        
        while (-not $completed) {
            # Check if timeout exceeded
            $elapsed = (Get-Date) - $startTime
            if ($elapsed.TotalSeconds -gt $TimeoutSeconds) {
                Write-Warning "Project creation timeout exceeded ($TimeoutSeconds seconds)"
                Write-Host "  Operation may still be in progress. Check Azure DevOps portal." -ForegroundColor Yellow
                break
            }
            
            # Check operation status
            $operationStatus = Invoke-AzureDevOpsApi -Uri $operationUrl -Token $token
            
            if ($operationStatus.status -eq "succeeded") {
                $completed = $true
                Write-Host "✓ Project created successfully" -ForegroundColor Green
                
                # Get project details
                $projectUrl = "https://dev.azure.com/$Organization/_apis/projects/$ProjectName" + "?api-version=7.1"
                $project = Invoke-AzureDevOpsApi -Uri $projectUrl -Token $token
                
                # Summary
                Write-Host "`n=== Summary ===" -ForegroundColor Green
                Write-Host "Project:" -ForegroundColor Cyan
                Write-Host "  Name: $($project.name)" -ForegroundColor White
                Write-Host "  ID: $($project.id)" -ForegroundColor White
                Write-Host "  State: $($project.state)" -ForegroundColor White
                Write-Host "  Visibility: $($project.visibility)" -ForegroundColor White
                if ($project.description) {
                    Write-Host "  Description: $($project.description)" -ForegroundColor White
                }
                Write-Host ""
                Write-Host "Configuration:" -ForegroundColor Cyan
                Write-Host "  Process Template: $ProcessTemplate" -ForegroundColor White
                Write-Host "  Version Control: $VersionControl" -ForegroundColor White
                Write-Host ""
                Write-Host "Azure DevOps:" -ForegroundColor Cyan
                Write-Host "  Organization: $Organization" -ForegroundColor White
                Write-Host "  URL: https://dev.azure.com/$Organization/$ProjectName" -ForegroundColor White
                Write-Host ""
                Write-Host "✓ Project setup complete!" -ForegroundColor Green
                Write-Host ""
                Write-Host "Next steps:" -ForegroundColor Yellow
                Write-Host "  1. Visit the project: https://dev.azure.com/$Organization/$ProjectName" -ForegroundColor Gray
                Write-Host "  2. Create repositories and pipelines" -ForegroundColor Gray
                Write-Host "  3. Add team members and configure permissions" -ForegroundColor Gray
                Write-Host "  4. Set up work items and boards" -ForegroundColor Gray
                if (-not $EnableAdvancedSecurity) {
                    Write-Host "  5. Enable GHAzDO push protection: Project Settings > Repos > Repositories > Settings" -ForegroundColor Yellow
                }
            }
            elseif ($operationStatus.status -eq "failed" -or $operationStatus.status -eq "cancelled") {
                Write-Error "Project creation failed: $($operationStatus.status)"
                if ($operationStatus.resultMessage) {
                    Write-Host "  Error: $($operationStatus.resultMessage)" -ForegroundColor Red
                }
                exit 1
            }
            else {
                Write-Host "  Status: $($operationStatus.status)..." -ForegroundColor Gray
                Start-Sleep -Seconds 2
            }
        }
    }
    else {
        Write-Host "`nProject creation initiated but not waiting for completion." -ForegroundColor Yellow
        Write-Host "Check the Azure DevOps portal to verify project creation." -ForegroundColor Yellow
        Write-Host "URL: https://dev.azure.com/$Organization/$ProjectName" -ForegroundColor Gray
    }
}
catch {
    Write-Error "Failed to create project: $_"
    exit 1
}

# Enable GitHub Advanced Security (GHAzDO) push protection
if ($EnableAdvancedSecurity) {
    Write-Host "`n[5/5] Enabling Advanced Security (GHAzDO) push protection..." -ForegroundColor Yellow
    try {
        $advSecUrl = "https://advsec.dev.azure.com/$Organization/$ProjectName/_apis/management/enablement?api-version=7.2-preview.1"
        $advSecConfig = @{
            advSecEnabled  = $true
            blockPushes    = $true
            enableOnCreate = $true
        }
        Invoke-AzureDevOpsApi -Uri $advSecUrl -Method Patch -Body $advSecConfig -Token $token | Out-Null
        Write-Host "✓ Advanced Security push protection enabled (credential scanning active, new repos inherit automatically)" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to enable Advanced Security: $_"
        Write-Host "  Enable manually: Project Settings > Repos > Repositories > [repo] > Settings > Push protection" -ForegroundColor Yellow
        Write-Host "  Docs: https://learn.microsoft.com/en-us/azure/devops/repos/security/github-advanced-security-push-protection" -ForegroundColor Gray
    }
}
