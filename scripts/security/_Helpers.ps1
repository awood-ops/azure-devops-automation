<#
.SYNOPSIS
    Shared helper functions for Azure DevOps security scripts.
    Dot-sourced by all scripts in this folder — do not run directly.
#>

function Resolve-MemberDescriptor {
    <#
    .SYNOPSIS
        Resolves a user email or group display name to its Azure DevOps graph descriptor.
        Returns a PSCustomObject with Descriptor, DisplayName, SubjectKind.
    #>
    param(
        [string]$Organization,
        [string]$Member,
        [string]$AuthHeader,
        [string]$ProjectScopeDescriptor   # optional; scopes group search to a specific project first
    )

    # ── User lookup (anything containing @) ──────────────────────────────────
    if ($Member -match '@') {
        Write-Verbose "Looking up user by email: $Member"
        $identityUrl = "https://vssps.dev.azure.com/$Organization/_apis/identities" +
                       "?searchFilter=MailAddress&filterValue=$([Uri]::EscapeDataString($Member))" +
                       "&queryMembership=None&api-version=7.1"
        $identityResult = Invoke-AzureDevOpsApi -Uri $identityUrl -AuthHeader $AuthHeader

        if (-not $identityResult.value -or $identityResult.value.Count -eq 0) {
            throw "No user found with email '$Member' in organisation '$Organization'."
        }

        $identity = $identityResult.value | Select-Object -First 1

        if (-not $identity.subjectDescriptor) {
            throw "User '$Member' was found but has no subjectDescriptor — they may not have signed in to Azure DevOps yet."
        }

        return [PSCustomObject]@{
            Descriptor  = $identity.subjectDescriptor
            DisplayName = $identity.providerDisplayName
            SubjectKind = "user"
        }
    }

    # ── Group lookup — project scope first, then org-level ───────────────────
    Write-Verbose "Looking up group by display name: $Member"

    $searchUrls = @()
    if ($ProjectScopeDescriptor) {
        $searchUrls += "https://vssps.dev.azure.com/$Organization/_apis/graph/groups" +
                       "?scopeDescriptor=$ProjectScopeDescriptor&api-version=7.1-preview.1"
    }
    $searchUrls += "https://vssps.dev.azure.com/$Organization/_apis/graph/groups?api-version=7.1-preview.1"

    foreach ($baseUrl in $searchUrls) {
        $continuationToken = $null
        do {
            $pagedUrl = if ($continuationToken) { "$baseUrl&continuationToken=$continuationToken" } else { $baseUrl }
            $tokenRef = [ref]$null
            $groupsResult = Invoke-AzureDevOpsApi -Uri $pagedUrl -AuthHeader $AuthHeader -OutContinuationToken $tokenRef
            $continuationToken = $tokenRef.Value

            $match = $groupsResult.value | Where-Object {
                $_.displayName -eq $Member -or $_.principalName -like "*\$Member"
            } | Select-Object -First 1

            if ($match) {
                return [PSCustomObject]@{
                    Descriptor  = $match.descriptor
                    DisplayName = $match.displayName
                    SubjectKind = "group"
                }
            }
        } while ($continuationToken)
    }

    # ── Fallback: Identities API for Entra ID groups materialised in ADO ─────
    Write-Verbose "Graph groups search exhausted — falling back to Identities API for '$Member'"
    $identityUrl = "https://vssps.dev.azure.com/$Organization/_apis/identities" +
                   "?searchFilter=General&filterValue=$([Uri]::EscapeDataString($Member))" +
                   "&queryMembership=None&api-version=7.1"
    $identityResult = Invoke-AzureDevOpsApi -Uri $identityUrl -AuthHeader $AuthHeader

    $groupIdentity = $identityResult.value | Where-Object {
        $_.providerDisplayName -eq $Member
    } | Select-Object -First 1

    if ($groupIdentity) {
        $descriptor = $groupIdentity.subjectDescriptor

        if (-not $descriptor) {
            Write-Verbose "Identity found but has no subjectDescriptor — resolving via storage key '$($groupIdentity.id)'"
            try {
                $storageKeyUrl = "https://vssps.dev.azure.com/$Organization/_apis/graph/descriptors/$($groupIdentity.id)?api-version=7.1-preview.1"
                $descriptor = (Invoke-AzureDevOpsApi -Uri $storageKeyUrl -AuthHeader $AuthHeader).value
            }
            catch {
                Write-Verbose "Could not resolve descriptor from storage key: $_"
            }
        }

        if ($descriptor) {
            return [PSCustomObject]@{
                Descriptor  = $descriptor
                DisplayName = $groupIdentity.providerDisplayName
                SubjectKind = "group"
            }
        }
    }

    # ── Final fallback: Identity Picker → materialise via Graph API ────────────
    # The ADO UI identity picker can find Entra groups not yet materialised in the
    # ADO identity store. We use it to get the Entra originId, then POST to the
    # Graph groups endpoint which materialises the group and returns its descriptor.
    Write-Verbose "Identities API exhausted — trying identity picker for '$Member'"
    try {
        $pickerUrl = "https://dev.azure.com/$Organization/_apis/identitypicker/identities?api-version=7.1-preview.1"
        $pickerBody = @{
            query            = $Member
            identityTypes    = @("Group")
            operationScopes  = @("ims", "source")
            properties       = @("DisplayName", "SubjectDescriptor")
            options          = @{ MinResults = 5; MaxResults = 40 }
        }
        $pickerResult = Invoke-AzureDevOpsApi -Uri $pickerUrl -Method Post -Body $pickerBody -AuthHeader $AuthHeader
        $pickerMatch  = $pickerResult.results[0].identities | Where-Object {
            $_.displayName -eq $Member
        } | Select-Object -First 1

        if ($pickerMatch) {
            # If subjectDescriptor is already set the group is fully materialised.
            if ($pickerMatch.subjectDescriptor) {
                return [PSCustomObject]@{
                    Descriptor  = $pickerMatch.subjectDescriptor
                    DisplayName = $pickerMatch.displayName
                    SubjectKind = "group"
                }
            }

            # Use originId to materialise the group into ADO.
            if ($pickerMatch.originId -and $pickerMatch.originDirectory -eq 'aad') {
                Write-Verbose "  Materialising Entra group via originId '$($pickerMatch.originId)'"
                $materialiseUrl = "https://vssps.dev.azure.com/$Organization/_apis/graph/groups?api-version=7.1-preview.1"
                $materialised   = Invoke-AzureDevOpsApi -Uri $materialiseUrl -Method Post -Body @{ originId = $pickerMatch.originId } -AuthHeader $AuthHeader
                $descriptor     = ($materialised.descriptor -replace '\s', '')
                if ($descriptor) {
                    return [PSCustomObject]@{
                        Descriptor  = $descriptor
                        DisplayName = $materialised.displayName
                        SubjectKind = "group"
                    }
                }
            }
        }
    } catch {
        Write-Verbose "  Identity picker / materialise attempt failed: $_"
    }

    throw "No group found with display name '$Member' in organisation '$Organization'. " +
          "If this is an Entra ID group, ensure it exists in Entra ID and your token has sufficient permissions."
}

function Get-AzureDevOpsAuthHeader {
    <#
    .SYNOPSIS
        Returns the Authorization header value for Azure DevOps API calls.
        OAuth tokens use "Bearer <token>"; PATs use "Basic <base64(:PAT)>".
    #>
    try {
        $tokenResult = Get-AzAccessToken -ResourceUrl "499b84ac-1321-427f-aa17-267ca6975798" -ErrorAction SilentlyContinue

        if ($tokenResult) {
            if ($tokenResult.Token -is [SecureString]) {
                $BSTR  = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenResult.Token)
                $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR)
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
            }
            elseif ($tokenResult.Token) {
                $plain = $tokenResult.Token
            }
            else {
                $plain = $null
            }
            if ($plain) {
                return "Bearer $plain"
            }
        }
    }
    catch {
        # Fall through to PAT check
    }

    if ($env:AZURE_DEVOPS_EXT_PAT) {
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($env:AZURE_DEVOPS_EXT_PAT)"))
        return "Basic $encoded"
    }

    try {
        $patResult = az account get-access-token --resource 499b84ac-1321-427f-aa17-267ca6975798 2>$null | ConvertFrom-Json
        if ($patResult.accessToken) {
            return "Bearer $($patResult.accessToken)"
        }
    }
    catch {
        # Continue
    }

    Write-Error @"
Failed to get Azure DevOps access token. Please either:
1. Run Connect-AzAccount first (recommended) — ensure you are signed in to the correct tenant
2. Set the AZURE_DEVOPS_EXT_PAT environment variable with a Personal Access Token
3. Run 'az devops login' if you have Azure CLI with DevOps extension installed
"@
    throw "No authentication available"
}

function Invoke-AzureDevOpsApi {
    <#
    .SYNOPSIS
        Invokes an Azure DevOps REST API endpoint and returns the parsed response.
        Throws a meaningful error for non-2xx responses or unexpected HTML (e.g. sign-in
        redirect caused by an invalid or wrong-tenant token).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [string]$Method = "Get",

        [Parameter(Mandatory = $false)]
        [object]$Body,

        [Parameter(Mandatory = $true)]
        [string]$AuthHeader,

        # Override the Content-Type for the request body.
        # Default is "application/json". Use "application/json-patch+json" for JSON Patch operations.
        [Parameter(Mandatory = $false)]
        [string]$ContentType = "application/json",

        # When provided, receives the X-MS-ContinuationToken header value for paginated responses.
        [Parameter(Mandatory = $false)]
        [ref]$OutContinuationToken
    )

    $headers = @{
        'Authorization' = $AuthHeader
        'Accept'        = 'application/json'
    }

    $params = @{
        Method             = $Method
        Uri                = $Uri
        Headers            = $headers
        SkipHttpErrorCheck = $true
    }

    if ($Body) {
        $headers['Content-Type'] = $ContentType
        # Use -InputObject to preserve array structure (piping unwraps single-element arrays)
        $params.Body = if ($Body -is [string]) { $Body } else { ConvertTo-Json -InputObject $Body -Depth 10 -Compress }
    }

    try {
        $webResponse = Invoke-WebRequest @params

        if ($webResponse.StatusCode -ge 400) {
            $detail = if ($webResponse.Content) { $webResponse.Content } else { "(no content)" }
            throw "HTTP $($webResponse.StatusCode) $($webResponse.StatusDescription): $detail"
        }

        if ($webResponse.Content) {
            $responseContent = $webResponse.Content

            # A sign-in HTML page (HTTP 203) is returned when the token is rejected.
            # This happens when Connect-AzAccount is logged in to a different tenant
            # than the one the Azure DevOps organisation is linked to.
            if ($responseContent.TrimStart().StartsWith('<')) {
                throw "Expected JSON but received HTML (Status: $($webResponse.StatusCode), Content-Type: $($webResponse.Headers['Content-Type'])). " +
                      "This usually means the token was rejected — verify your tenant with (Get-AzContext).Tenant.Id or use AZURE_DEVOPS_EXT_PAT."
            }

            if ($OutContinuationToken) {
                $OutContinuationToken.Value = $webResponse.Headers['X-MS-ContinuationToken']
            }

            return $responseContent | ConvertFrom-Json -Depth 20
        }
    }
    catch {
        Write-Error "API call failed: $($_.Exception.Message)"
        throw
    }
}
