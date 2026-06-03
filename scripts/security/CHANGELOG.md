# Changelog

All notable changes to the security scripts in this folder are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

---

## [1.5] — Add-PrValidationPipeline.ps1 + Invoke-AzureDevOpsHardening.ps1 — 2026-06-03

### Added
- `Add-PrValidationPipeline.ps1` — creates a "PR Validation" pipeline definition pointing to the existing YAML in a forked repository, then applies the "Build validation" branch policy on the default branch. Satisfies BRANCH-02. Called automatically by the `new-devops-project` skill after each repo fork (Fabric Accelerator and Data Platform).

### Fixed
- **Step 10 — Release Pipeline Security**: broadened deny mask from 7118 to 64510 (all 16 permission bits except ViewReleases and ViewReleaseDefinition). The previous mask missed the "Delete releases" permission because its bit position differs across ADO environments; the broad mask eliminates the dependency on individual bit values.

---

## [1.4] — Invoke-AzureDevOpsHardening.ps1 — 2026-06-03

### Added
- **Step 9 — Repository ACL Security** (`-SkipRepositoryAcl`): restricts Contributors and Build Administrators to Read-only on the Git Repositories security namespace (`repoV2/<projectId>` token). Denies Contribute, ForcePush, CreateBranch, CreateTag, ManageNote, PolicyExempt, RemoveOthersLocks, PullRequestContribute, and PullRequestBypassPolicy at the project level. Addresses PERM-06 audit findings.
- **Step 10 — Release Pipeline Security** (`-SkipReleasePipelineSecurity`): restricts Contributors to View-only on the Release Management security namespace. Denies EditReleaseDefinition, DeleteReleaseDefinition, ManageReleaseApprovals, CreateReleases, EditReleaseEnvironment, DeleteReleaseEnvironment, AdministerDeployments, DeleteReleases, and ManageDeployments. Addresses PERM-02 audit findings.

---

## [1.3] — Set-AzureDevOpsOrgSettings.ps1 — 2026-03-13

### Fixed
- Organisation Policy API is write-only (GET returns HTTP 405). `Get-OrgPolicy` was silently returning `$null` on every call, causing the report to always show policies as unset regardless of actual state. Removed the unworkable read attempt entirely.
- Hardcoded `salzdev` org name in the write-only note replaced with `$Organization`.
- Corrected `.DESCRIPTION` to accurately state that pipeline settings support current-state reporting but organisation policies do not.

### Changed
- Organisation policy section replaced with a pre-flight action summary showing what will be applied vs skipped, rather than a false "current state" comparison.
- Policy display labels updated to reflect Azure DevOps UI wording (e.g. "External guest access: Blocked" rather than "Disable external guest access: ON").
- `TargetDisplay` in pipeline settings is now dynamic per-parameter instead of always showing "ON".

---

## [1.2] — Set-AzureDevOpsOrgSettings.ps1 — 2026-03-13

### Added
- `-DisableClassicBuildPipelines` (`$true`) — blocks creation of new designer-based build pipelines via `disableClassicBuildPipelineCreation`.
- `-DisableNode6Tasks` (`$true`) — prevents tasks from running on the EOL Node.js 6 handler via `disableNode6Tasks`.
- `-EnforceAuditLogging` (`$true`) — applies `Policy.LogAuditEvents` to ensure authentication and authorisation events are captured.
- `-DisableSSHAuth` (`$true`) — applies `Policy.DisableSSHAuthentication` to block SSH-based git operations.
- `-DisableMarketplaceTasks` (`$false`) — applies `disableMarketplaceTasks`; defaults off as it breaks any pipeline using a Marketplace extension task.

### Added (documentation)
- `README.md` created covering all scripts: parameters, examples, hardening order, and authentication notes.

---

## [1.1] — Set-AzureDevOpsOrgSettings.ps1 — 2026-03-13

### Fixed
- `-RestrictPATCreation` was not wiring up to the PATCH call — it printed a manual-action message instead of applying `Policy.DisablePATCreation`. Now correctly added to `$policiesToApply`.
- Policy name corrected from `RestrictPersonalAccessTokenCreation` to `DisablePATCreation` (confirmed via browser network trace returning HTTP 204).

---

## [1.0] — Initial release — 2026-03-13

### Added
- `Set-AzureDevOpsOrgSettings.ps1` — org-level pipeline settings (classic release pipelines, shell task validation) and organisation policies (PAT creation, guest access, OAuth app access) via `Contribution/HierarchyQuery` and `OrganizationPolicy` APIs.
- `Set-AzureDevOpsBranchPolicies.ps1` — branch protection policies per repository: minimum reviewers, self-approval prohibition, vote reset on push, comment resolution, merge strategy restrictions, build validation, required reviewers. Idempotent.
- `Set-AzureDevOpsPipelineSecurity.ps1` — project-level pipeline settings: job authorisation scope, YAML repository protection, private status badges.
- `Set-AzureDevOpsServiceConnectionSecurity.ps1` — locks service connections to deny all pipelines by default; optionally grants access to specific pipeline IDs.
- `Get-AzureDevOpsAudit.ps1` — read-only audit of Project Administrator group membership with optional allowlist flagging and CSV export.
- `Invoke-AzureDevOpsHardening.ps1` — orchestrator that runs all project-level hardening steps in sequence with `-Skip*` switches and `-ReportOnly` support.
- `_Helpers.ps1` — shared `Get-AzureDevOpsAuthHeader` (Azure AD token → PAT fallback) and `Invoke-AzureDevOpsApi` wrapper.
