<#
.SYNOPSIS
    Creates an Azure DevOps service connection with workload identity federation.

.DESCRIPTION
    This script automates the creation of Azure DevOps service connections using workload identity federation.
    It can either use an existing service principal or create a new one by calling New-WorkloadIdentity.ps1.
    
    Key Features:
    - Creates or uses existing service principal with workload identity
    - Creates Azure DevOps service connection with federated credentials
    - Supports subscription, resource group, and management group scopes
    - Can create the service principal automatically
    - Retrieves issuer/subject from Azure DevOps for federated credentials
    - Idempotent - can be run multiple times safely

.PARAMETER Organization
    Azure DevOps organization name (e.g., "myorg" from dev.azure.com/myorg)

.PARAMETER Project
    Azure DevOps project name where the service connection will be created

.PARAMETER ServiceConnectionName
    Name for the Azure DevOps service connection

.PARAMETER SubscriptionId
    Azure Subscription ID for the service connection

.PARAMETER SubscriptionName
    Azure Subscription Name (optional - will be looked up if not provided)

.PARAMETER ServicePrincipalId
    Application (client) ID of existing service principal. If not provided, a new one will be created.

.PARAMETER ServicePrincipalName
    Display name for the service principal. Used when creating a new service principal.
    If not provided, uses the service connection name.

.PARAMETER TenantId
    Azure AD Tenant ID (optional - will be detected from current context)

.PARAMETER RoleDefinitionName
    Azure RBAC role to assign to the service principal. Default: "Contributor"
    Only used when creating a new service principal.

.PARAMETER Scope
    Scope for role assignment. Default: subscription level
    Only used when creating a new service principal.

.PARAMETER ManagementGroupId
    Management Group ID for role assignment at management group scope
    Only used when creating a new service principal.

.PARAMETER CreateServicePrincipal
    If specified, creates a new service principal using New-WorkloadIdentity.ps1

.PARAMETER WorkloadIdentityScriptPath
    Path to New-WorkloadIdentity.ps1 script
    Default: Looks in common locations

.PARAMETER Force
    Skips confirmation prompts

.EXAMPLE
    # Create service connection using existing service principal
    .\New-AzureDevOpsServiceConnection.ps1 `
        -Organization "myorg" `
        -Project "MyProject" `
        -ServiceConnectionName "Azure-Production" `
        -SubscriptionId "11111111-1111-1111-1111-111111111111" `
        -ServicePrincipalId "22222222-2222-2222-2222-222222222222"

.EXAMPLE
    # Create service connection and service principal together
    .\New-AzureDevOpsServiceConnection.ps1 `
        -Organization "myorg" `
        -Project "MyProject" `
        -ServiceConnectionName "Azure-Dev" `
        -SubscriptionId "11111111-1111-1111-1111-111111111111" `
        -CreateServicePrincipal `
        -RoleDefinitionName "Contributor"

.EXAMPLE
    # Create service connection with custom service principal name
    .\New-AzureDevOpsServiceConnection.ps1 `
        -Organization "myorg" `
        -Project "MyProject" `
        -ServiceConnectionName "Azure-Prod" `
        -SubscriptionId "11111111-1111-1111-1111-111111111111" `
        -CreateServicePrincipal `
        -ServicePrincipalName "sp-prod-deployment" `
        -RoleDefinitionName "Contributor" `
        -Force

.EXAMPLE
    # Create service connection with management group scope
    .\New-AzureDevOpsServiceConnection.ps1 `
        -Organization "myorg" `
        -Project "MyProject" `
        -ServiceConnectionName "Azure-MG" `
        -SubscriptionId "11111111-1111-1111-1111-111111111111" `
        -CreateServicePrincipal `
        -ManagementGroupId "mg-corporate" `
        -RoleDefinitionName "Reader"

.NOTES
    Author: Andrew Wood
    Version: 1.0
    
    Prerequisites:
    - Azure login: Connect-AzAccount
    - Permissions: 
      * Build Administrator or Project Administrator in Azure DevOps
      * User Access Administrator or Owner on Azure subscription (if creating service principal)
    
    Dependencies:
    - New-WorkloadIdentity.ps1 (if using -CreateServicePrincipal)

.LINK
    https://learn.microsoft.com/en-us/azure/devops/pipelines/library/connect-to-azure
    https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-overview
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string]$Organization,

    [Parameter(Mandatory = $true)]
    [string]$Project,

    [Parameter(Mandatory = $true)]
    [string]$ServiceConnectionName,

    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$SubscriptionName,

    [Parameter(Mandatory = $false)]
    [string]$ServicePrincipalId,

    [Parameter(Mandatory = $false)]
    [string]$ServicePrincipalName,

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$RoleDefinitionName = "Contributor",

    [Parameter(Mandatory = $false)]
    [string]$Scope,

    [Parameter(Mandatory = $false)]
    [string]$ManagementGroupId,

    [Parameter(Mandatory = $false)]
    [switch]$CreateServicePrincipal,

    [Parameter(Mandatory = $false)]
    [string]$WorkloadIdentityScriptPath,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "=== Azure DevOps Service Connection Creation Script ===" -ForegroundColor Cyan
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
    
    Write-Error @"
Failed to get Azure DevOps access token. Please either:
1. Run Connect-AzAccount first (recommended)
2. Set the AZURE_DEVOPS_EXT_PAT environment variable with a Personal Access Token
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

function Find-WorkloadIdentityScript {
    <#
    .SYNOPSIS
        Finds the New-WorkloadIdentity.ps1 script
    #>
    $searchPaths = @(
        $WorkloadIdentityScriptPath,
        ".\New-WorkloadIdentity.ps1",
        "..\..\..\AzureKeyRotation\Scripts\New-WorkloadIdentity.ps1",
        "$PSScriptRoot\..\..\..\AzureKeyRotation\Scripts\New-WorkloadIdentity.ps1"
    )
    
    foreach ($path in $searchPaths) {
        if ($path -and (Test-Path $path)) {
            return (Resolve-Path $path).Path
        }
    }
    
    Write-Error @"
Could not find New-WorkloadIdentity.ps1. Please specify the path using -WorkloadIdentityScriptPath parameter.
Searched locations:
$($searchPaths | Where-Object { $_ } | ForEach-Object { "  - $_" } | Out-String)
"@
    throw "Script not found"
}

#endregion

# Validate parameters
if (-not $CreateServicePrincipal -and -not $ServicePrincipalId) {
    Write-Error "Either -ServicePrincipalId or -CreateServicePrincipal must be specified"
    exit 1
}

# Check Azure context
Write-Host "[1/5] Checking Azure connection..." -ForegroundColor Yellow
try {
    $context = Get-AzContext
    if (-not $context) {
        Write-Host "Not connected to Azure. Please run Connect-AzAccount first." -ForegroundColor Red
        exit 1
    }
    Write-Host "✓ Connected as: $($context.Account.Id)" -ForegroundColor Green
    
    # Get tenant ID if not provided
    if (-not $TenantId) {
        $TenantId = $context.Tenant.Id
    }
    Write-Host "✓ Tenant: $TenantId" -ForegroundColor Green
}
catch {
    Write-Error "Failed to get Azure context: $_"
    exit 1
}

# Get subscription details
try {
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    $subscription = Get-AzSubscription -SubscriptionId $SubscriptionId
    if (-not $SubscriptionName) {
        $SubscriptionName = $subscription.Name
    }
    Write-Host "✓ Subscription: $SubscriptionName" -ForegroundColor Green
}
catch {
    Write-Error "Failed to get subscription details: $_"
    exit 1
}

# Confirm operation
if (-not $Force) {
    Write-Host "`n⚠️  This will create a service connection with the following settings:" -ForegroundColor Yellow
    Write-Host "   - Organization: $Organization" -ForegroundColor Gray
    Write-Host "   - Project: $Project" -ForegroundColor Gray
    Write-Host "   - Connection Name: $ServiceConnectionName" -ForegroundColor Gray
    Write-Host "   - Subscription: $SubscriptionName ($SubscriptionId)" -ForegroundColor Gray
    if ($CreateServicePrincipal) {
        Write-Host "   - Will create new service principal" -ForegroundColor Gray
        Write-Host "   - Role: $RoleDefinitionName" -ForegroundColor Gray
    }
    else {
        Write-Host "   - Service Principal ID: $ServicePrincipalId" -ForegroundColor Gray
    }
    $confirmation = Read-Host "`nContinue? (yes/no)"
    if ($confirmation -ne "yes") {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        exit 0
    }
}

# Create service principal if requested
if ($CreateServicePrincipal) {
    Write-Host "`n[2/5] Creating service principal..." -ForegroundColor Yellow
    
    try {
        # Find the workload identity script
        $scriptPath = Find-WorkloadIdentityScript
        Write-Host "✓ Found workload identity script: $scriptPath" -ForegroundColor Green
        
        # Set service principal name
        if (-not $ServicePrincipalName) {
            $ServicePrincipalName = $ServiceConnectionName
        }
        
        # Build parameters for New-WorkloadIdentity.ps1
        $wiParams = @{
            ServicePrincipalName = $ServicePrincipalName
            SubscriptionId = $SubscriptionId
            RoleDefinitionName = $RoleDefinitionName
            AzureDevOpsOrganization = $Organization
            AzureDevOpsProject = $Project
            ServiceConnectionName = $ServiceConnectionName
            Force = $Force
        }
        
        if ($Scope) {
            $wiParams.Scope = $Scope
        }
        
        if ($ManagementGroupId) {
            $wiParams.ManagementGroupId = $ManagementGroupId
        }
        
        # Call New-WorkloadIdentity.ps1
        Write-Host "  Calling New-WorkloadIdentity.ps1..." -ForegroundColor Gray
        & $scriptPath @wiParams
        
        # Get the service principal that was created
        $sp = Get-AzADServicePrincipal -DisplayName $ServicePrincipalName
        $ServicePrincipalId = $sp.AppId
        
        Write-Host "✓ Service principal created/configured" -ForegroundColor Green
        Write-Host "  Application ID: $ServicePrincipalId" -ForegroundColor Gray
        
        # The New-WorkloadIdentity script already creates the service connection and federated credential
        Write-Host "`n✓ Service connection and federated credential created by New-WorkloadIdentity.ps1" -ForegroundColor Green
        
        # Summary
        Write-Host "`n=== Summary ===" -ForegroundColor Green
        Write-Host "Service Connection:" -ForegroundColor Cyan
        Write-Host "  Name: $ServiceConnectionName" -ForegroundColor White
        Write-Host "  Organization: $Organization" -ForegroundColor White
        Write-Host "  Project: $Project" -ForegroundColor White
        Write-Host ""
        Write-Host "Service Principal:" -ForegroundColor Cyan
        Write-Host "  Display Name: $ServicePrincipalName" -ForegroundColor White
        Write-Host "  Application ID: $ServicePrincipalId" -ForegroundColor White
        Write-Host "  Tenant ID: $TenantId" -ForegroundColor White
        Write-Host ""
        Write-Host "Azure Subscription:" -ForegroundColor Cyan
        Write-Host "  Name: $SubscriptionName" -ForegroundColor White
        Write-Host "  ID: $SubscriptionId" -ForegroundColor White
        Write-Host ""
        Write-Host "✓ Service connection setup complete!" -ForegroundColor Green
        
        exit 0
    }
    catch {
        Write-Error "Failed to create service principal: $_"
        exit 1
    }
}

# Use existing service principal
Write-Host "`n[2/5] Validating service principal..." -ForegroundColor Yellow
try {
    $sp = Get-AzADServicePrincipal -ApplicationId $ServicePrincipalId
    if (-not $sp) {
        Write-Error "Service principal with Application ID '$ServicePrincipalId' not found"
        exit 1
    }
    Write-Host "✓ Service principal found: $($sp.DisplayName)" -ForegroundColor Green
    Write-Host "  Application ID: $ServicePrincipalId" -ForegroundColor Gray
    Write-Host "  Object ID: $($sp.Id)" -ForegroundColor Gray
}
catch {
    Write-Error "Failed to get service principal: $_"
    exit 1
}

# Get authentication token
Write-Host "`n[3/5] Authenticating to Azure DevOps..." -ForegroundColor Yellow
try {
    $token = Get-AzureDevOpsToken
    Write-Host "✓ Successfully authenticated" -ForegroundColor Green
}
catch {
    Write-Error "Failed to authenticate: $_"
    exit 1
}

# Get project details
Write-Host "`n[4/5] Getting project details..." -ForegroundColor Yellow
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

# Create service connection
Write-Host "`n[5/5] Creating service connection..." -ForegroundColor Yellow
try {
    # Check if service connection already exists
    $listUrl = "https://dev.azure.com/$Organization/$Project/_apis/serviceendpoint/endpoints?api-version=7.2-preview.4"
    $existingConnections = Invoke-AzureDevOpsApi -Uri $listUrl -Token $token
    $existingConnection = $existingConnections.value | Where-Object { $_.name -eq $ServiceConnectionName }
    
    if ($existingConnection) {
        Write-Host "⚠️  Service connection already exists: $ServiceConnectionName" -ForegroundColor Yellow
        Write-Host "  Connection ID: $($existingConnection.id)" -ForegroundColor Gray
        $serviceConnectionId = $existingConnection.id
        $connectionExists = $true
    }
    else {
        # Create service connection
        $createUrl = "https://dev.azure.com/$Organization/_apis/serviceendpoint/endpoints?api-version=7.2-preview.4"
        
        $body = @"
{
    "data": {
        "subscriptionId": "$SubscriptionId",
        "subscriptionName": "$SubscriptionName",
        "environment": "AzureCloud",
        "scopeLevel": "Subscription",
        "creationMode": "Manual"
    },
    "name": "$ServiceConnectionName",
    "type": "AzureRM",
    "url": "https://management.azure.com/",
    "authorization": {
        "parameters": {
            "tenantid": "$TenantId",
            "serviceprincipalid": "$ServicePrincipalId"
        },
        "scheme": "WorkloadIdentityFederation"
    },
    "isShared": false,
    "isReady": true,
    "serviceEndpointProjectReferences": [
        {
            "projectReference": {
                "name": "$Project",
                "id": "$projectId"
            },
            "name": "$ServiceConnectionName"
        }
    ]
}
"@
        
        try {
            $response = Invoke-AzureDevOpsApi -Uri $createUrl -Method Post -Body $body -Token $token
            $serviceConnectionId = $response.id
            
            Write-Host "✓ Service connection created: $ServiceConnectionName" -ForegroundColor Green
            Write-Host "  Connection ID: $serviceConnectionId" -ForegroundColor Gray
            $connectionExists = $false
        }
        catch {
            if ($_.Exception.Message -like "*409*") {
                Write-Host "✓ Service connection already exists: $ServiceConnectionName" -ForegroundColor Green
                $existingConnection = $existingConnections.value | Where-Object { $_.name -eq $ServiceConnectionName } | Select-Object -First 1
                $serviceConnectionId = $existingConnection.id
                $connectionExists = $true
            }
            else {
                throw
            }
        }
    }
    
    # Retrieve issuer and subject from service connection
    $getUrl = "https://dev.azure.com/$Organization/$Project/_apis/serviceendpoint/endpoints/$serviceConnectionId" + "?api-version=7.2-preview.4"
    $serviceConnectionDetails = Invoke-AzureDevOpsApi -Uri $getUrl -Token $token
    
    $issuer = $serviceConnectionDetails.authorization.parameters.workloadIdentityFederationIssuer
    $subject = $serviceConnectionDetails.authorization.parameters.workloadIdentityFederationSubject
    
    if ($issuer -and $subject) {
        Write-Host "  Issuer: $issuer" -ForegroundColor Gray
        Write-Host "  Subject: $subject" -ForegroundColor Gray
        
        # Create or update federated credential
        Write-Host "`nConfiguring federated credential..." -ForegroundColor Yellow
        try {
            $app = Get-AzADApplication -ApplicationId $ServicePrincipalId
            
            # Check if federated credential exists with correct subject
            $existingCredential = Get-AzADAppFederatedCredential -ApplicationObjectId $app.Id -ErrorAction SilentlyContinue |
                Where-Object { $_.Subject -eq $subject }
            
            if ($existingCredential) {
                Write-Host "✓ Federated credential already exists with correct subject" -ForegroundColor Green
                Write-Host "  Name: $($existingCredential.Name)" -ForegroundColor Gray
            }
            else {
                # Check for old credential to update
                $credentialName = "AzureDevOps-$Project"
                $oldCredential = Get-AzADAppFederatedCredential -ApplicationObjectId $app.Id -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -eq $credentialName }
                
                if ($oldCredential) {
                    Write-Host "  Removing old federated credential..." -ForegroundColor Yellow
                    Remove-AzADAppFederatedCredential -ApplicationObjectId $app.Id -FederatedCredentialId $oldCredential.Id -ErrorAction Stop
                }
                
                # Create new credential
                New-AzADAppFederatedCredential `
                    -ApplicationObjectId $app.Id `
                    -Issuer $issuer `
                    -Subject $subject `
                    -Audience "api://AzureADTokenExchange" `
                    -Name $credentialName `
                    -ErrorAction Stop
                
                Write-Host "✓ Federated credential created" -ForegroundColor Green
            }
        }
        catch {
            Write-Warning "Failed to configure federated credential: $_"
            Write-Host "  You may need to configure it manually in Azure Portal" -ForegroundColor Yellow
        }
    }
    else {
        Write-Warning "Could not retrieve issuer/subject from service connection"
        Write-Host "  You may need to configure federated credential manually" -ForegroundColor Yellow
    }
}
catch {
    Write-Error "Failed to create service connection: $_"
    exit 1
}

# Summary
Write-Host "`n=== Summary ===" -ForegroundColor Green
Write-Host "Service Connection:" -ForegroundColor Cyan
Write-Host "  Name: $ServiceConnectionName" -ForegroundColor White
Write-Host "  ID: $serviceConnectionId" -ForegroundColor White
Write-Host "  Organization: $Organization" -ForegroundColor White
Write-Host "  Project: $Project" -ForegroundColor White
Write-Host "  URL: https://dev.azure.com/$Organization/$Project/_settings/adminservices" -ForegroundColor White
Write-Host ""
Write-Host "Service Principal:" -ForegroundColor Cyan
Write-Host "  Display Name: $($sp.DisplayName)" -ForegroundColor White
Write-Host "  Application ID: $ServicePrincipalId" -ForegroundColor White
Write-Host "  Tenant ID: $TenantId" -ForegroundColor White
Write-Host ""
Write-Host "Azure Subscription:" -ForegroundColor Cyan
Write-Host "  Name: $SubscriptionName" -ForegroundColor White
Write-Host "  ID: $SubscriptionId" -ForegroundColor White
Write-Host ""
Write-Host "✓ Service connection setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Verify the service connection in Azure DevOps" -ForegroundColor Gray
Write-Host "  2. Grant pipeline permissions to the service connection if needed" -ForegroundColor Gray
Write-Host "  3. Use the connection in your pipelines" -ForegroundColor Gray
