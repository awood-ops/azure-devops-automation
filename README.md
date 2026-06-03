# Azure DevOps Automation Scripts

PowerShell scripts for automating Azure DevOps operations using the REST API.

## 📋 Contents

### Project Management

- **[New-CustomerProject.ps1](scripts/project/New-CustomerProject.ps1)** - **Orchestrator** — create and fully secure a customer project in one command (creates project, wires PIM groups, applies hardening)
- **[New-AzureDevOpsProject.ps1](scripts/project/New-AzureDevOpsProject.ps1)** - Create an Azure DevOps project programmatically

### Pipeline Management

- **[New-AzureDevOpsPipeline.ps1](scripts/pipeline/New-AzureDevOpsPipeline.ps1)** - Create Azure DevOps pipelines programmatically

### Service Connection Management

- **[New-AzureDevOpsServiceConnection.ps1](scripts/service-connection/New-AzureDevOpsServiceConnection.ps1)** - Create Azure service connections with workload identity federation

### Security Hardening

**Organisation-level** (applies across all projects):
- **[Set-AzureDevOpsOrgSettings.ps1](scripts/security/Set-AzureDevOpsOrgSettings.ps1)** - Apply organisation-wide pipeline and policy settings (classic release pipelines, shell task validation, PAT restriction, guest access)

**Project-level** (run per project):
- **[Invoke-AzureDevOpsHardening.ps1](scripts/security/Invoke-AzureDevOpsHardening.ps1)** - **Orchestrator** — runs all four project-level hardening steps in sequence with a single command
- **[Set-AzureDevOpsBranchPolicies.ps1](scripts/security/Set-AzureDevOpsBranchPolicies.ps1)** - Apply branch protection policies (reviewers, comment resolution, merge strategy, build validation)
- **[Get-AzureDevOpsAudit.ps1](scripts/security/Get-AzureDevOpsAudit.ps1)** - Audit Project Administrator group membership across projects
- **[Set-AzureDevOpsServiceConnectionSecurity.ps1](scripts/security/Set-AzureDevOpsServiceConnectionSecurity.ps1)** - Lock service connections so only authorised pipelines can use them
- **[Set-AzureDevOpsPipelineSecurity.ps1](scripts/security/Set-AzureDevOpsPipelineSecurity.ps1)** - Apply project-level pipeline security settings (job scope, repo protection)
- **[Set-AzureDevOpsGroupMember.ps1](scripts/security/Set-AzureDevOpsGroupMember.ps1)** - Add or remove members from Azure DevOps groups
- **[New-AzureDevOpsPipelineOperatorAccess.ps1](scripts/security/New-AzureDevOpsPipelineOperatorAccess.ps1)** - Grant pipeline operator access to a group

## 🚀 Getting Started

### Prerequisites

- PowerShell 7.0 or later
- Azure PowerShell module (`Az.Accounts`)
- Permissions: Build Administrator or Project Administrator in Azure DevOps

### Authentication

The scripts support multiple authentication methods:

1. **Azure PowerShell (Recommended)**
   ```powershell
   Connect-AzAccount
   ```

2. **Personal Access Token (PAT)**
   ```powershell
   $env:AZURE_DEVOPS_EXT_PAT = "your-pat-token"
   ```

3. **Azure CLI**
   ```powershell
   az devops login
   ```

## 📖 Script Documentation

### New-AzureDevOpsProject.ps1

Creates Azure DevOps projects with customizable process templates and settings.

**Features:**
- ✅ Supports Agile, Scrum, CMMI, and Basic process templates
- ✅ Configurable version control (Git or TFVC)
- ✅ Public or private visibility settings
- ✅ Waits for project creation to complete
- ✅ Idempotent - safely run multiple times

**Basic Usage:**

```powershell
# Create a basic project with default settings
.\scripts\project\New-AzureDevOpsProject.ps1 `
    -Organization "myorg" `
    -ProjectName "MyNewProject"
```

**Advanced Examples:**

```powershell
# Create a Scrum project with description
.\scripts\project\New-AzureDevOpsProject.ps1 `
    -Organization "myorg" `
    -ProjectName "MyProject" `
    -Description "My awesome project" `
    -ProcessTemplate "Scrum" `
    -Force

# Create a public project with TFVC
.\scripts\project\New-AzureDevOpsProject.ps1 `
    -Organization "myorg" `
    -ProjectName "PublicProject" `
    -Description "Open source project" `
    -ProcessTemplate "Agile" `
    -VersionControl "Tfvc" `
    -Visibility "public"
```

**Parameters:**

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `Organization` | Yes | - | Azure DevOps organization name |
| `ProjectName` | Yes | - | Name for the new project |
| `Description` | No | - | Project description |
| `ProcessTemplate` | No | `Agile` | Process template: `Agile`, `Scrum`, `CMMI`, `Basic` |
| `VersionControl` | No | `Git` | Version control: `Git`, `Tfvc` |
| `Visibility` | No | `private` | Project visibility: `private`, `public` |
| `WaitForCompletion` | No | `true` | Wait for creation to complete |
| `TimeoutSeconds` | No | `300` | Timeout for waiting (seconds) |
| `Force` | No | `false` | Skip confirmation prompts |

---

### New-AzureDevOpsServiceConnection.ps1

Creates Azure DevOps service connections with workload identity federation, optionally creating the service principal.

**Features:**
- ✅ Creates or uses existing service principals
- ✅ Integrates with New-WorkloadIdentity.ps1 for automated SP creation
- ✅ Configures workload identity federation (no secrets)
- ✅ Automatically retrieves issuer/subject from Azure DevOps
- ✅ Supports subscription, resource group, and management group scopes
- ✅ Creates federated credentials automatically

**Basic Usage:**

```powershell
# Use existing service principal
.\scripts\service-connection\New-AzureDevOpsServiceConnection.ps1 `
    -Organization "myorg" `
    -Project "MyProject" `
    -ServiceConnectionName "Azure-Production" `
    -SubscriptionId "11111111-1111-1111-1111-111111111111" `
    -ServicePrincipalId "22222222-2222-2222-2222-222222222222"
```

**Advanced Examples:**

```powershell
# Create service connection AND service principal together
.\scripts\service-connection\New-AzureDevOpsServiceConnection.ps1 `
    -Organization "myorg" `
    -Project "MyProject" `
    -ServiceConnectionName "Azure-Dev" `
    -SubscriptionId "11111111-1111-1111-1111-111111111111" `
    -CreateServicePrincipal `
    -RoleDefinitionName "Contributor"

# Create with custom service principal name and management group scope
.\scripts\service-connection\New-AzureDevOpsServiceConnection.ps1 `
    -Organization "myorg" `
    -Project "MyProject" `
    -ServiceConnectionName "Azure-MG" `
    -SubscriptionId "11111111-1111-1111-1111-111111111111" `
    -CreateServicePrincipal `
    -ServicePrincipalName "sp-mg-deployment" `
    -ManagementGroupId "mg-corporate" `
    -RoleDefinitionName "Reader" `
    -Force
```

**Parameters:**

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `Organization` | Yes | - | Azure DevOps organization name |
| `Project` | Yes | - | Project name |
| `ServiceConnectionName` | Yes | - | Name for the service connection |
| `SubscriptionId` | Yes | - | Azure Subscription ID |
| `ServicePrincipalId` | No* | - | Existing service principal application ID |
| `CreateServicePrincipal` | No* | `false` | Create new service principal using New-WorkloadIdentity.ps1 |
| `ServicePrincipalName` | No | Connection name | Display name for new service principal |
| `RoleDefinitionName` | No | `Contributor` | Azure RBAC role (when creating SP) |
| `ManagementGroupId` | No | - | Management group scope (when creating SP) |
| `WorkloadIdentityScriptPath` | No | Auto-detected | Path to New-WorkloadIdentity.ps1 |
| `Force` | No | `false` | Skip confirmation prompts |

*Either `ServicePrincipalId` OR `CreateServicePrincipal` must be specified

---

### New-AzureDevOpsPipeline.ps1

Creates Azure DevOps pipelines with support for multiple repository types.

**Features:**
- ✅ Supports Azure Repos Git, GitHub, GitHub Enterprise, and Bitbucket
- ✅ Automatic repository and service connection lookup
- ✅ Idempotent - safely run multiple times
- ✅ Pipeline authorization for service connections
- ✅ Flexible configuration (folders, branches, YAML paths)

**Basic Usage:**

```powershell
# Create pipeline from Azure Repos
.\scripts\pipeline\New-AzureDevOpsPipeline.ps1 `
    -Organization "myorg" `
    -Project "MyProject" `
    -PipelineName "CI-Build" `
    -RepositoryName "MyRepo"
```

**Advanced Examples:**

```powershell
# GitHub repository with service connection
.\scripts\pipeline\New-AzureDevOpsPipeline.ps1 `
    -Organization "myorg" `
    -Project "MyProject" `
    -PipelineName "GitHub-CI" `
    -RepositoryType "github" `
    -RepositoryName "owner/repo" `
    -ServiceConnectionName "GitHub-Connection" `
    -YamlPath ".github/azure-pipelines.yml"

# Custom folder and branch with auto-authorization
.\scripts\pipeline\New-AzureDevOpsPipeline.ps1 `
    -Organization "myorg" `
    -Project "MyProject" `
    -PipelineName "Production-Deploy" `
    -RepositoryName "MyRepo" `
    -Branch "production" `
    -Folder "\Production\Deployments" `
    -AuthorizeResources `
    -Force
```

**Parameters:**

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `Organization` | Yes | - | Azure DevOps organization name |
| `Project` | Yes | - | Project name |
| `PipelineName` | Yes | - | Display name for the pipeline |
| `RepositoryType` | No | `azureReposGit` | Repository type: `azureReposGit`, `github`, `githubEnterprise`, `bitbucket` |
| `RepositoryName` | Yes | - | Repository name. Use `owner/repo` format for GitHub |
| `YamlPath` | No | `azure-pipelines.yml` | Path to YAML file in repository |
| `Branch` | No | `main` | Default branch |
| `ServiceConnectionName` | No* | - | Service connection name (required for external repos) |
| `Folder` | No | `\` | Pipeline folder path |
| `AuthorizeResources` | No | `false` | Auto-authorize service connections |
| `Force` | No | `false` | Skip confirmation prompts |

*Required for GitHub and external repositories

---

### Set-AzureDevOpsBranchPolicies.ps1

Applies branch protection policies to a repository branch. Covers the most impactful single hardening step.

**What it configures:**
- ✅ Minimum number of reviewers (default: 2), with optional self-approval prohibition
- ✅ Require all PR comments to be resolved before merge
- ✅ Merge strategy restrictions — enforce squash-only, block rebase and no-fast-forward merges
- ✅ Build validation — require a pipeline to pass before merge
- ✅ Required reviewers — auto-include specific team members on every PR
- ✅ Fetches policy type IDs dynamically (no hardcoded GUIDs)
- ✅ Idempotent — updates existing policies rather than creating duplicates
- ✅ Supports -WhatIf

**Why merge strategy matters:**

Squash-only merges (`-AllowSquash $true`, `-AllowRebase $false`, `-AllowNoFastForward $false`) give you three concrete security and auditability benefits:

| Without enforcement | With squash-only |
|---|---|
| Developers can bypass the clean history by choosing "merge commit" at merge time | Every merge into main is a single, reviewable commit — no choice at merge time |
| Rebase merges rewrite commit SHAs, making it hard to trace what was in a PR | The squash commit always references the PR, preserving the audit trail |
| Large PRs with noisy WIP commits obscure what actually changed | One commit per feature/fix — `git log` on main reads like a changelog |

**Basic Usage:**

```powershell
# Apply recommended baseline policies to main
.\scripts\security\Set-AzureDevOpsBranchPolicies.ps1 `
    -Organization "myorg" `
    -Project "MyProject" `
    -RepositoryName "MyRepo"
```

**Best Practice (all security controls enabled):**

```powershell
.\scripts\security\Set-AzureDevOpsBranchPolicies.ps1 `
    -Organization "myorg" `
    -Project "MyProject" `
    -RepositoryName "MyRepo" `
    -Branch "main" `
    -MinimumReviewerCount 2 `
    -ProhibitSelfApproval $true `
    -ResetVotesOnPush $true `
    -RequireResolvedComments $true `
    -AllowSquash $true `
    -AllowRebase $false `
    -AllowNoFastForward $false `
    -BuildPipelineId 42 `
    -BuildDisplayName "PR Validation" `
    -RequiredReviewerEmails "tech.lead@company.com","security@company.com" `
    -Force
```

| Setting | Value | Why |
|---------|-------|-----|
| `MinimumReviewerCount 2` | `2` | One reviewer can be pressured; two is a meaningful check |
| `ProhibitSelfApproval $true` | `$true` | Prevents "approve my own hotfix" bypass |
| `ResetVotesOnPush $true` | `$true` | Forces re-review after new commits — approvals don't carry over |
| `RequireResolvedComments $true` | `$true` | Security feedback can't be dismissed by merging anyway |
| `AllowSquash $true` | `$true` | Clean history — one commit per PR, easier to audit and revert |
| `AllowRebase $false` | `$false` | Rebase rewrites history, making audit trails unreliable |
| `AllowNoFastForward $false` | `$false` | Blocks direct merge commits that bypass the review record |
| `BuildPipelineId` | your CI ID | Merge blocked unless tests pass — no broken builds into main |
| `RequiredReviewerEmails` | leads/security | Guarantees the right eyes are on every PR — cannot be skipped |

> **Tip:** Find your CI pipeline ID before running:
> ```powershell
> # Preview what would change without applying anything
> .\scripts\security\Set-AzureDevOpsBranchPolicies.ps1 `
>     -Organization "myorg" -Project "MyProject" -RepositoryName "MyRepo" -WhatIf
> ```

**Other Examples:**

```powershell
# Baseline policies only (no build validation or required reviewers)
.\scripts\security\Set-AzureDevOpsBranchPolicies.ps1 `
    -Organization "myorg" `
    -Project "MyProject" `
    -RepositoryName "MyRepo" `
    -Force

# Preview changes without applying
.\scripts\security\Set-AzureDevOpsBranchPolicies.ps1 `
    -Organization "myorg" -Project "MyProject" -RepositoryName "MyRepo" -WhatIf
```

**Parameters:**

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `Organization` | Yes | - | Azure DevOps organization name |
| `Project` | Yes | - | Project name |
| `RepositoryName` | Yes | - | Repository to protect |
| `Branch` | No | `main` | Branch to apply policies to |
| `MinimumReviewerCount` | No | `2` | Minimum reviewers required |
| `ProhibitSelfApproval` | No | `$true` | Prevent PR creator self-approval |
| `ResetVotesOnPush` | No | `$true` | Reset votes when new commits pushed |
| `RequireResolvedComments` | No | `$true` | Block merge until comments resolved |
| `AllowSquash` | No | `$true` | Allow squash merge |
| `AllowRebase` | No | `$false` | Allow rebase merge |
| `AllowNoFastForward` | No | `$false` | Allow basic merge commits |
| `BuildPipelineId` | No | - | Pipeline ID for build validation |
| `BuildDisplayName` | No | `PR Validation` | Label for the build policy |
| `RequiredReviewerEmails` | No | - | Email addresses to auto-add as reviewers |
| `Force` | No | `$false` | Skip confirmation |

---

### Get-AzureDevOpsAudit.ps1

Read-only audit of Project Administrator group membership. Use this to find over-privileged accounts — anyone in Project Administrators can bypass almost all controls.

**What it reports:**
- ✅ All members of Project Administrators per project
- ✅ Flags accounts not on an expected allowlist
- ✅ Audits a single project or the whole organisation
- ✅ Optional CSV export

**Basic Usage:**

```powershell
# Audit all projects
.\scripts\security\Get-AzureDevOpsAudit.ps1 `
    -Organization "myorg"

# Audit with an expected allowlist — flag anyone unexpected
.\scripts\security\Get-AzureDevOpsAudit.ps1 `
    -Organization "myorg" `
    -ExpectedAdmins "alice@example.com","bob@example.com" `
    -ExportCsvPath "C:\Reports\admin-audit.csv"
```

**Parameters:**

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `Organization` | Yes | - | Azure DevOps organization name |
| `Project` | No | - | Single project to audit (omit for all projects) |
| `ExpectedAdmins` | No | - | Allowlist of expected admin email addresses |
| `ExportCsvPath` | No | - | Path to export results as CSV |

---

### Set-AzureDevOpsServiceConnectionSecurity.ps1

Restricts service connection access so only explicitly authorised pipelines can use them. Prevents any pipeline from using production credentials without explicit approval.

**What it does:**
- ✅ Reports which service connections are open to all pipelines
- ✅ Sets `allPipelines.authorized = false` on targeted connections
- ✅ Optionally grants access to a specified list of pipeline IDs
- ✅ -ReportOnly mode to inspect without changing
- ✅ Idempotent

**Basic Usage:**

```powershell
# Report current state
.\scripts\security\Set-AzureDevOpsServiceConnectionSecurity.ps1 `
    -Organization "myorg" -Project "MyProject" -ReportOnly

# Lock all connections (no pipelines authorised yet)
.\scripts\security\Set-AzureDevOpsServiceConnectionSecurity.ps1 `
    -Organization "myorg" -Project "MyProject" -Force

# Lock a specific connection and authorise two pipelines
.\scripts\security\Set-AzureDevOpsServiceConnectionSecurity.ps1 `
    -Organization "myorg" -Project "MyProject" `
    -ServiceConnectionNames "Azure-Production" `
    -AuthorisedPipelineIds 10,23 -Force
```

**Parameters:**

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `Organization` | Yes | - | Azure DevOps organization name |
| `Project` | Yes | - | Project name |
| `ServiceConnectionNames` | No | - | Connections to target (omit for all) |
| `AuthorisedPipelineIds` | No | - | Pipeline IDs to explicitly authorise |
| `ReportOnly` | No | `$false` | Report without making changes |
| `Force` | No | `$false` | Skip confirmation |

---

### Set-AzureDevOpsPipelineSecurity.ps1

Applies project-level pipeline security settings that limit what pipelines can access at runtime.

**What it configures:**
- ✅ Limit job authorisation scope to current project (non-release pipelines)
- ✅ Limit job authorisation scope to current project (release pipelines)
- ✅ Protect access to repositories in YAML pipelines
- ✅ Private status badge URLs
- ✅ -ReportOnly mode to inspect without changing

**Basic Usage:**

```powershell
# Report current state
.\scripts\security\Set-AzureDevOpsPipelineSecurity.ps1 `
    -Organization "myorg" -Project "MyProject" -ReportOnly

# Apply recommended settings
.\scripts\security\Set-AzureDevOpsPipelineSecurity.ps1 `
    -Organization "myorg" -Project "MyProject" -Force
```

**Parameters:**

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `Organization` | Yes | - | Azure DevOps organization name |
| `Project` | Yes | - | Project name |
| `ReportOnly` | No | `$false` | Report without making changes |
| `Force` | No | `$false` | Skip confirmation |

---

### Invoke-AzureDevOpsHardening.ps1

Orchestrates all four hardening steps for a project in a single run. Use this as your primary entry point.

**Audit current state (no changes):**

```powershell
.\scripts\security\Invoke-AzureDevOpsHardening.ps1 `
    -Organization "myorg" `
    -Project "MyProject" `
    -ReportOnly
```

**Best practice — full hardening run:**

```powershell
.\scripts\security\Invoke-AzureDevOpsHardening.ps1 `
    -Organization "myorg" `
    -Project "MyProject" `
    -RequiredReviewerEmails "tech.lead@company.com","security@company.com" `
    -ExpectedAdmins "admin@company.com","devops@company.com" `
    -AdminAuditCsvPath "C:\Reports\admin-audit.csv" `
    -Force
```

**Harden specific repositories, skip steps already completed:**

```powershell
.\scripts\security\Invoke-AzureDevOpsHardening.ps1 `
    -Organization "myorg" `
    -Project "MyProject" `
    -RepositoryNames "api-repo","frontend-repo" `
    -SkipAdminAudit `
    -SkipPipelineSecurity `
    -Force
```

**Parameters:**

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `Organization` | Yes | - | Azure DevOps organization name |
| `Project` | Yes | - | Project name |
| `RepositoryNames` | No | all repos | Repositories to apply branch policies to |
| `Branch` | No | `main` | Branch to protect |
| `MinimumReviewerCount` | No | `2` | Minimum PR reviewers |
| `RequiredReviewerEmails` | No | - | Email addresses auto-added as required reviewers |
| `ExpectedAdmins` | No | - | Allowlist of expected Project Administrators |
| `AdminAuditCsvPath` | No | - | Path to export admin audit as CSV |
| `ReportOnly` | No | `$false` | Audit all steps without making changes |
| `SkipBranchPolicies` | No | `$false` | Skip branch policies step |
| `SkipAdminAudit` | No | `$false` | Skip admin audit step |
| `SkipServiceConnectionSecurity` | No | `$false` | Skip service connection step |
| `SkipPipelineSecurity` | No | `$false` | Skip pipeline settings step |
| `Force` | No | `$false` | Skip confirmation prompts |

---

### Set-AzureDevOpsOrgSettings.ps1

Applies organisation-wide security settings that are outside the scope of individual projects. Run this once per organisation, before or alongside the project-level hardening.

**Report current state:**

```powershell
.\scripts\security\Set-AzureDevOpsOrgSettings.ps1 `
    -Organization "myorg" `
    -ReportOnly
```

**Best practice — safe defaults (low risk, apply to all orgs):**

```powershell
# DisableClassicReleasePipelines and EnableShellTaskValidation are low-risk.
.\scripts\security\Set-AzureDevOpsOrgSettings.ps1 `
    -Organization "myorg" `
    -DisableClassicReleasePipelines $true `
    -EnableShellTaskValidation $true `
    -Force
```

**Full lockdown (only if no external users or OAuth apps):**

```powershell
.\scripts\security\Set-AzureDevOpsOrgSettings.ps1 `
    -Organization "myorg" `
    -DisableClassicReleasePipelines $true `
    -EnableShellTaskValidation $true `
    -RestrictPATCreation $true `
    -DisableExternalGuestAccess $true `
    -DisableOAuthAppAccess $true `
    -Force
```

**What each setting does and why:**

| Setting | Default | Risk level | Why |
|---------|---------|------------|-----|
| `DisableClassicReleasePipelines` | `$true` | Low | Classic release pipelines can't be reviewed as code and are harder to audit. New ones should not be created. |
| `EnableShellTaskValidation` | `$true` | Low | Detects arguments to shell tasks that could inject commands. When set at org level, cannot be overridden per-project. |
| `RestrictPATCreation` | `$false` | Medium | Prevents users creating unlimited-scope PATs. Requires configuring an allowlist before enabling or legitimate users will be blocked. |
| `DisableExternalGuestAccess` | `$false` | Medium | Blocks Microsoft Entra guest accounts. Only safe if your org has no external collaborators. |
| `DisableOAuthAppAccess` | `$false` | High | Blocks all third-party OAuth apps. Audit connected apps first or integrations will break. |

**Settings that require manual configuration (UI only):**

| Setting | Location | Recommendation |
|---------|----------|----------------|
| PAT allowlist | Org Settings → Security → Policies | After enabling PAT restriction, add specific users/groups who need full-scope PATs |
| IP Conditional Access | Org Settings → Security → Policies | Restrict which IP ranges can access the organisation |
| SSH authentication | Org Settings → Security → Policies | Should be **OFF** — force HTTPS or service connections instead |
| Log audit events | Org Settings → Security → Policies | Should be **ON** — confirms all actions are auditable |

**Parameters:**

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `Organization` | Yes | - | Azure DevOps organization name |
| `DisableClassicReleasePipelines` | No | `$true` | Prevent new classic release pipeline creation |
| `EnableShellTaskValidation` | No | `$true` | Validate shell task arguments for injection |
| `RestrictPATCreation` | No | `$false` | Restrict users from creating broad-scope PATs |
| `DisableExternalGuestAccess` | No | `$false` | Block Entra guest accounts from the org |
| `DisableOAuthAppAccess` | No | `$false` | Block third-party OAuth application access |
| `ReportOnly` | No | `$false` | Report without making changes |
| `Force` | No | `$false` | Skip confirmation |

---

### Recommended Hardening Order

Run `Set-AzureDevOpsOrgSettings.ps1` once per organisation, then `Invoke-AzureDevOpsHardening.ps1` for each project.

**Organisation-level (once):**

| Priority | Script | What it protects |
|----------|--------|-----------------|
| 0 | `Set-AzureDevOpsOrgSettings.ps1` | Org-wide — classic release pipelines, shell injection, PAT scopes, guest access |

**Project-level (per project):**

| Priority | Script | What it protects |
|----------|--------|-----------------|
| — | `Invoke-AzureDevOpsHardening.ps1` | **All of the below in one run** |
| 1 | `Set-AzureDevOpsBranchPolicies.ps1` | main branch — requires PR, reviewers, passing build |
| 2 | `Get-AzureDevOpsAudit.ps1` | Over-privileged accounts (read-only — remediate manually) |
| 3 | `Set-AzureDevOpsServiceConnectionSecurity.ps1` | Production credentials — locks to specific pipelines only |
| 4 | `Set-AzureDevOpsPipelineSecurity.ps1` | Pipeline runtime access — limits cross-project and repo access |

## 🔗 Related Projects

- [AzureKeyRotation](https://github.com/awood-ops/AzureKeyRotation) - Azure key rotation automation

## 📚 Resources

- [Azure DevOps REST API Documentation](https://learn.microsoft.com/en-us/rest/api/azure/devops/)
- [Azure Pipelines Documentation](https://learn.microsoft.com/en-us/azure/devops/pipelines/)

## 📄 License

See [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.