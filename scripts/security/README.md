# Azure DevOps Security Scripts

PowerShell scripts for hardening Azure DevOps organisations and projects. All scripts require an authenticated Azure session (`Connect-AzAccount`) or a PAT set via `AZURE_DEVOPS_EXT_PAT`. Permissions required are noted per script.

---

## Scripts

### `Set-AzureDevOpsOrgSettings.ps1`

**Permissions required:** Organisation Administrator

Applies organisation-level security settings — controls that span every project in the org. Settings are reported before any changes are made; use `-ReportOnly` to audit without touching anything.

#### Pipeline settings (Contribution/HierarchyQuery API)

| Parameter | Default | What it does |
|---|---|---|
| `-DisableClassicReleasePipelines` | `$true` | Block creation of new classic release pipelines. Existing ones continue to work. |
| `-DisableClassicBuildPipelines` | `$true` | Block creation of new classic (designer-based) build pipelines. |
| `-EnableShellTaskValidation` | `$true` | Validate shell task arguments for command injection. Cannot be overridden at project level. |
| `-DisableNode6Tasks` | `$true` | Prevent tasks from running on the EOL Node.js 6 handler. |
| `-DisableMarketplaceTasks` | `$false` | Block Marketplace extension tasks. **Audit all pipelines before enabling** — any pipeline using a third-party task will fail. |

#### Organisation policies (OrganisationPolicy API)

> **Note:** The Organisation Policy API is write-only — current state cannot be read via REST. The script reports what will be applied. Verify actual state at `dev.azure.com/{org}/_settings/organizationPolicy`.

| Parameter | Default | What it does |
|---|---|---|
| `-RestrictPATCreation` | `$false` | Enable the "Restrict personal access token (PAT) creation" policy. After enabling, configure the allowlist at `/_settings/organizationPolicy`. |
| `-EnforceAuditLogging` | `$true` | Ensure audit events are being logged. Disabling removes forensic capability. |
| `-DisableSSHAuth` | `$true` | Block SSH-based git operations. HTTPS with tokens is preferred. |
| `-DisableExternalGuestAccess` | `$false` | Block Entra ID guest accounts. Only enable if you have no external collaborators. |
| `-DisableOAuthAppAccess` | `$false` | Block third-party OAuth application access. Audit connected apps first. |

#### Common flags

| Flag | Purpose |
|---|---|
| `-ReportOnly` | Show current state without making changes |
| `-Force` | Skip confirmation prompt |
| `-WhatIf` | Dry-run (ShouldProcess) |

#### Examples

```powershell
# Audit current state
.\Set-AzureDevOpsOrgSettings.ps1 -Organization "myorg" -ReportOnly

# Safe defaults — low-risk pipeline hardening only
.\Set-AzureDevOpsOrgSettings.ps1 `
    -Organization "myorg" `
    -DisableClassicReleasePipelines $true `
    -DisableClassicBuildPipelines $true `
    -EnableShellTaskValidation $true `
    -DisableNode6Tasks $true `
    -Force

# Full lockdown — review all parameters before running
.\Set-AzureDevOpsOrgSettings.ps1 `
    -Organization "myorg" `
    -DisableClassicReleasePipelines $true `
    -DisableClassicBuildPipelines $true `
    -EnableShellTaskValidation $true `
    -DisableNode6Tasks $true `
    -RestrictPATCreation $true `
    -EnforceAuditLogging $true `
    -DisableSSHAuth $true `
    -DisableExternalGuestAccess $true `
    -DisableOAuthAppAccess $true `
    -Force
```

> **After enabling `-RestrictPATCreation`:** configure the allowlist at `dev.azure.com/{org}/_settings/organizationPolicy` — this controls which users/groups can still create full-scope PATs.

---

### `Set-AzureDevOpsBranchPolicies.ps1`

**Permissions required:** Project Administrator

Applies branch protection policies to a single repository branch. Idempotent — updates existing policies rather than creating duplicates.

| Parameter | Default | What it does |
|---|---|---|
| `-MinimumReviewerCount` | `2` | Minimum PR approvals required |
| `-ProhibitSelfApproval` | `$true` | Creator cannot approve their own PR |
| `-ResetVotesOnPush` | `$true` | Approvals reset when new commits are pushed |
| `-RequireResolvedComments` | `$true` | All comments must be resolved before merge |
| `-AllowSquash` | `$true` | Allow squash merge |
| `-AllowRebase` | `$false` | Allow rebase merge |
| `-AllowNoFastForward` | `$false` | Allow basic merge commits (recommended: off) |
| `-BuildPipelineId` | — | Pipeline ID for build validation on PRs |
| `-RequiredReviewerEmails` | — | Auto-add specific reviewers to every PR |

```powershell
.\Set-AzureDevOpsBranchPolicies.ps1 `
    -Organization "myorg" `
    -Project "MyProject" `
    -RepositoryName "MyRepo" `
    -Branch "main" `
    -MinimumReviewerCount 2 `
    -ProhibitSelfApproval $true `
    -ResetVotesOnPush $true `
    -RequireResolvedComments $true `
    -RequiredReviewerEmails "lead@example.com" `
    -Force
```

---

### `Set-AzureDevOpsPipelineSecurity.ps1`

**Permissions required:** Project Administrator

Applies project-level pipeline security settings via the Build General Settings API.

| Setting | What it does |
|---|---|
| Limit job authorisation scope (non-release) | Pipelines cannot access resources in other projects |
| Limit job authorisation scope (release) | Same restriction for classic release pipelines |
| Protect access to repositories in YAML | YAML pipelines can only access explicitly authorised repos |
| Private status badge URLs | Pipeline status badges are not publicly queryable |

```powershell
# Audit first
.\Set-AzureDevOpsPipelineSecurity.ps1 -Organization "myorg" -Project "MyProject" -ReportOnly

# Apply all settings
.\Set-AzureDevOpsPipelineSecurity.ps1 -Organization "myorg" -Project "MyProject" -Force
```

---

### `Set-AzureDevOpsServiceConnectionSecurity.ps1`

**Permissions required:** Project Administrator or service connection Administrator

Locks service connections so no pipeline can use them by default. Service connections are high-value credentials — by default Azure DevOps grants all pipelines access, which is a significant risk for production connections.

| Parameter | Purpose |
|---|---|
| `-ServiceConnectionNames` | Target specific connections (omit to process all) |
| `-AuthorisedPipelineIds` | Pipeline IDs to explicitly grant access after locking |
| `-ReportOnly` | Show current permission state without changes |

```powershell
# Report which connections are open to all pipelines
.\Set-AzureDevOpsServiceConnectionSecurity.ps1 `
    -Organization "myorg" -Project "MyProject" -ReportOnly

# Lock all connections
.\Set-AzureDevOpsServiceConnectionSecurity.ps1 `
    -Organization "myorg" -Project "MyProject" -Force

# Lock a specific connection and allow two pipelines
.\Set-AzureDevOpsServiceConnectionSecurity.ps1 `
    -Organization "myorg" -Project "MyProject" `
    -ServiceConnectionNames "Azure-Production" `
    -AuthorisedPipelineIds 10,23 -Force
```

---

### `Get-AzureDevOpsAudit.ps1`

**Permissions required:** Project Administrator (read-only)

Enumerates Project Administrator group membership across one or more projects. Flags members not on an expected allowlist. Makes no changes.

```powershell
# Audit all projects
.\Get-AzureDevOpsAudit.ps1 -Organization "myorg"

# Audit a specific project with an allowlist
.\Get-AzureDevOpsAudit.ps1 `
    -Organization "myorg" `
    -Project "MyProject" `
    -ExpectedAdmins "alice@example.com","bob@example.com"

# Export results to CSV
.\Get-AzureDevOpsAudit.ps1 `
    -Organization "myorg" `
    -ExpectedAdmins "alice@example.com" `
    -ExportCsvPath ".\audit-$(Get-Date -Format 'yyyyMMdd').csv"
```

---

### `Invoke-AzureDevOpsHardening.ps1`

**Permissions required:** Project Administrator + Organisation Administrator

Orchestrator script that runs all hardening steps in sequence for a project. Calls the individual scripts above in the recommended order:

1. `Set-AzureDevOpsBranchPolicies.ps1` — protect default branch of every repo
2. `Get-AzureDevOpsAudit.ps1` — flag over-privileged accounts (read-only)
3. `Set-AzureDevOpsServiceConnectionSecurity.ps1` — lock service connections
4. `Set-AzureDevOpsPipelineSecurity.ps1` — apply project pipeline settings

Individual steps can be skipped with `-Skip*` switches. Use `-ReportOnly` to audit all steps without making changes.

```powershell
# Full audit — no changes
.\Invoke-AzureDevOpsHardening.ps1 `
    -Organization "myorg" -Project "MyProject" -ReportOnly

# Full hardening run
.\Invoke-AzureDevOpsHardening.ps1 `
    -Organization "myorg" -Project "MyProject" `
    -MinimumReviewerCount 2 `
    -ExpectedAdmins "lead@example.com" `
    -Force
```

---

### `_Helpers.ps1`

Shared helper functions dot-sourced by all scripts in this folder. Do not run directly.

| Function | Purpose |
|---|---|
| `Get-AzureDevOpsAuthHeader` | Returns a `Bearer` or `Basic` auth header, preferring an Azure AD token from the current `Connect-AzAccount` session before falling back to `AZURE_DEVOPS_EXT_PAT` |
| `Invoke-AzureDevOpsApi` | Thin wrapper around `Invoke-RestMethod` with consistent error handling, content-type defaulting, and auth header injection |

---

## Recommended hardening order

For a new organisation or project, run the scripts in this sequence:

```
1. Set-AzureDevOpsOrgSettings.ps1      — org-wide pipeline and policy settings
2. Set-AzureDevOpsBranchPolicies.ps1   — protect main branch per repo
3. Get-AzureDevOpsAdminAudit.ps1       — identify unexpected admins (read-only)
4. Set-AzureDevOpsServiceConnectionSecurity.ps1  — lock service connections
5. Set-AzureDevOpsPipelineSecurity.ps1 — project-level pipeline hardening
```

Or use `Invoke-AzureDevOpsHardening.ps1` to run steps 2–5 in a single command.

## Authentication

All scripts authenticate via `_Helpers.ps1`:

1. **Azure AD token** (preferred) — obtained from the current `Connect-AzAccount` / `az login` session. Scoped to the Azure DevOps resource (`499b84ac-1321-427f-aa17-267ca6975798`).
2. **PAT fallback** — set `AZURE_DEVOPS_EXT_PAT` environment variable with a token that has the required scopes.
