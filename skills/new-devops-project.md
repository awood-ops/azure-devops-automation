---
name: new-devops-project
description: >
  Create a new Azure DevOps customer project. Runs the full 3-step setup: project creation
  (Agile/Git/private), optional Entra ID group wiring, and security hardening. Trigger when
  the user wants to provision a new customer ADO project or onboard a new customer to Azure DevOps.
argument-hint: "<ProjectName>"
allowed-tools:
  - Bash
  - PowerShell
  - Read
  - mcp__ado__core_list_projects
  - mcp__ado__repo_get_repo_by_name_or_id
  - mcp__ado__repo_list_repos_by_project
  - mcp__ado__work_create_iterations
  - mcp__ado__work_assign_iterations
  - mcp__ado__work_list_iterations
  - mcp__ado__work_get_team_settings
  - mcp__ado__wit_create_work_item
  - mcp__ado__wit_add_child_work_items
  - mcp__ado__wit_work_items_link
  - mcp__ado__wit_update_work_items_batch
---

# New Azure DevOps Customer Project

You are creating a new Azure DevOps project. The process runs three scripts in sequence from
`$env:ADO_AUTOMATION_PATH\scripts\project\New-CustomerProject.ps1`:

1. **Create** the project (Agile process, Git, private)
2. **Wire Entra ID groups** — optional, maps groups to Project Administrators and Readers
3. **Security hardening** — applies the standard 10-step lockdown baseline

---

## Prerequisites

Ensure `$env:ADO_AUTOMATION_PATH` is set to the root of your local clone before running:

```powershell
# Add to your PowerShell $PROFILE once
$env:ADO_AUTOMATION_PATH = 'C:\path\to\azure-devops-automation'
```

---

## Step 1 — Confirm project details

Ask for, or accept from the argument:

> "What should the new project be called?"

Then ask:

> "What is the Azure DevOps organisation name? (e.g. `my-org` from dev.azure.com/my-org)"

Then ask (or accept a default):

> "Description? (leave blank to default to '<ProjectName> customer project')"

Then ask:

> "What type of project is this? (Fabric Accelerator / Data Platform / Standard, defaults to Standard)"

Then ask about Entra ID group wiring:

> "Do you have Entra ID groups to wire into the project? If yes, provide:
> - Admin group name(s) → Project Administrators (comma-separated if more than one)
> - Reader group name → Readers
> Or press Enter to skip group wiring."

Store the answers as `<Organisation>`, `<AdminGroups>` (array), and `<ReaderGroup>`. If the
user skips group wiring, `<AdminGroups>` and `<ReaderGroup>` are empty.

Keep this to one or two quick exchanges — don't ask about process template, version control,
or visibility; those are fixed defaults (Agile, Git, private).

**Important:** The ProjectName must be unique in the organisation. If you have any reason to
believe the name might already be taken (e.g. the user mentions it exists, or you can check via
MCP), flag it before proceeding.

---

## Step 2 — Show a confirmation summary

Present the following and ask: **"Ready to create this project?"**

```
Organisation   : <Organisation>
Project        : <ProjectName>
Description    : <description>
Entra ID groups: <AdminGroups joined by newline with "→ Project Administrators", then ReaderGroup "→ Readers", or "None — skipped">
Repo fork      : <"FabricBicep from Infrastructure and Security" | "DataLandingZone_bicepavm from Infrastructure and Security" | "None">
Board setup    : <"Fabric Accelerator (9 epics, 45 stories, 5 iterations, 5-phase delivery approach)" | "Data Platform (9 epics, 50 stories, 5 iterations, 5-phase delivery approach)" | "None">
```

Wait for confirmation before running anything.

---

## Step 3 — Run the script

Once confirmed, Before invoking, verify the env var is set:

```powershell
if (-not $env:ADO_AUTOMATION_PATH) {
    throw 'ADO_AUTOMATION_PATH is not set. Add it to your $PROFILE.'
}
```

run the orchestrator script using PowerShell:

```powershell
& "$env:ADO_AUTOMATION_PATH\scripts\project\New-CustomerProject.ps1" `
    -Organization       "<Organisation>" `
    -ProjectName        "<ProjectName>" `
    -ProjectDescription "<description>" `
    [-AdminGroups @("<AdminGroup1>", "<AdminGroup2>")] `   # omit if no groups provided
    [-ReaderGroup "<ReaderGroup>"] `                        # omit if no groups provided
    -Force
```

Omit `-AdminGroups` and `-ReaderGroup` entirely if the user skipped group wiring in Step 1.

Stream the output to the user as it runs. The script takes 30–60 seconds — tell the user it's
running and will poll until the project is confirmed created.

**Authentication:** The script calls `Get-AzAccessToken` first. If it fails, the error will say
"Failed to authenticate". In that case tell the user:
> "Run `Connect-AzAccount` in your terminal first, then try again."

---

## Step 4 — Delete the default repository

After the script completes, ADO creates a default repo with the same name as the project. Delete
it using the REST API before proceeding:

```powershell
$org        = "<Organisation>"
$targetProj = "<ProjectName>"

$token   = az account get-access-token --resource "499b84ac-1321-427f-aa17-267ca6975798" --query accessToken -o tsv
$headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }

# Find the default repo (same name as the project)
$repos = Invoke-RestMethod `
    -Uri     "https://dev.azure.com/$org/$([Uri]::EscapeDataString($targetProj))/_apis/git/repositories?api-version=7.1" `
    -Headers $headers
$defaultRepo = $repos.value | Where-Object { $_.name -eq $targetProj }

if ($defaultRepo) {
    Invoke-RestMethod `
        -Uri     "https://dev.azure.com/$org/$([Uri]::EscapeDataString($targetProj))/_apis/git/repositories/$($defaultRepo.id)?api-version=7.1" `
        -Method  Delete `
        -Headers $headers
    Write-Host "Default repo '$($defaultRepo.name)' deleted."
} else {
    Write-Host "No default repo found to delete (may have already been removed)."
}
```

---

## Step 5 — Repo fork (skip for Standard projects)

Skip this step entirely for Standard projects.

### Fabric Accelerator — Fork FabricBicep

The Fabric Accelerator source code lives at:
- **Project:** `Infrastructure and Security`
- **Repo:** `FabricBicep`
- **Branch:** `main`

First, verify the source repo exists using `mcp__ado__repo_get_repo_by_name_or_id` with
`project = "Infrastructure and Security"` and `repositoryNameOrId = "FabricBicep"`. If it
doesn't exist, warn the user and skip the fork (do not abort the whole setup).

Then use PowerShell to create a new `FabricBicep` repo in the target project and copy only the
`main` branch into it:

```powershell
$org        = "<Organisation>"
$sourceProj = "Infrastructure and Security"
$targetProj = "<ProjectName>"
$repoName   = "FabricBicep"

$token   = az account get-access-token --resource "499b84ac-1321-427f-aa17-267ca6975798" --query accessToken -o tsv
$headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }
$base    = "https://dev.azure.com/$org"

$newRepo = Invoke-RestMethod `
    -Uri     "$base/$([Uri]::EscapeDataString($targetProj))/_apis/git/repositories?api-version=7.1" `
    -Method  Post `
    -Headers $headers `
    -Body    (ConvertTo-Json @{ name = $repoName })

$tempDir   = "$([System.IO.Path]::GetTempPath())fabricbicep-$([System.Guid]::NewGuid().ToString().Substring(0,8))"
$sourceUrl = "https://x:$token@dev.azure.com/$org/$([Uri]::EscapeDataString($sourceProj))/_git/$repoName"
$targetUrl = "https://x:$token@dev.azure.com/$org/$([Uri]::EscapeDataString($targetProj))/_git/$repoName"

git -c credential.helper="" clone --branch main --single-branch $sourceUrl $tempDir
Set-Location $tempDir
git -c credential.helper="" remote set-url origin $targetUrl
git -c credential.helper="" push origin main
Set-Location C:\
Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
```

On success: `"FabricBicep forked into <ProjectName> from Infrastructure and Security."`

Then create the PR validation pipeline and apply the build validation branch policy:

```powershell
& "$env:ADO_AUTOMATION_PATH\scripts\pipeline\Add-PrValidationPipeline.ps1" `
    -Organization   "<Organisation>" `
    -Project        "<ProjectName>" `
    -RepositoryName "FabricBicep" `
    -YamlPath       "azure-pipelines.yml" `
    -Force
```

On pipeline setup failure, note it in the outcome and tell the user to run the script manually once the fork is confirmed.

On failure to fork, show the error and tell the user to fork manually from:
`https://dev.azure.com/<Organisation>/Infrastructure%20and%20Security/_git/FabricBicep`

---

### Data Platform — Fork DataLandingZone_bicepavm

The Data Platform source code lives at:
- **Project:** `Infrastructure and Security`
- **Repo:** `DataLandingZone_bicepavm`
- **Branch:** `main`

First, verify the source repo exists using `mcp__ado__repo_get_repo_by_name_or_id` with
`project = "Infrastructure and Security"` and `repositoryNameOrId = "DataLandingZone_bicepavm"`.
If it doesn't exist, warn the user and skip the fork (do not abort the whole setup).

Then use PowerShell to create a new `DataLandingZone_bicepavm` repo in the target project and
copy only the `main` branch into it:

```powershell
$org        = "<Organisation>"
$sourceProj = "Infrastructure and Security"
$targetProj = "<ProjectName>"
$repoName   = "DataLandingZone_bicepavm"

$token   = az account get-access-token --resource "499b84ac-1321-427f-aa17-267ca6975798" --query accessToken -o tsv
$headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }
$base    = "https://dev.azure.com/$org"

$newRepo = Invoke-RestMethod `
    -Uri     "$base/$([Uri]::EscapeDataString($targetProj))/_apis/git/repositories?api-version=7.1" `
    -Method  Post `
    -Headers $headers `
    -Body    (ConvertTo-Json @{ name = $repoName })

$tempDir   = "$([System.IO.Path]::GetTempPath())dlz-$([System.Guid]::NewGuid().ToString().Substring(0,8))"
$sourceUrl = "https://x:$token@dev.azure.com/$org/$([Uri]::EscapeDataString($sourceProj))/_git/$repoName"
$targetUrl = "https://x:$token@dev.azure.com/$org/$([Uri]::EscapeDataString($targetProj))/_git/$repoName"

git -c credential.helper="" clone --branch main --single-branch $sourceUrl $tempDir
Set-Location $tempDir
git -c credential.helper="" remote set-url origin $targetUrl
git -c credential.helper="" push origin main
Set-Location C:\
Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
```

On success: `"DataLandingZone_bicepavm forked into <ProjectName> from Infrastructure and Security."`

Then create the PR validation pipeline and apply the build validation branch policy:

```powershell
& "$env:ADO_AUTOMATION_PATH\scripts\pipeline\Add-PrValidationPipeline.ps1" `
    -Organization   "<Organisation>" `
    -Project        "<ProjectName>" `
    -RepositoryName "DataLandingZone_bicepavm" `
    -YamlPath       "azure-pipelines.yml" `
    -Force
```

On pipeline setup failure, note it in the outcome and tell the user to run the script manually once the fork is confirmed.

On failure to fork, show the error and tell the user to fork manually from:
`https://dev.azure.com/<Organisation>/Infrastructure%20and%20Security/_git/DataLandingZone_bicepavm`

---

## Step 6 — Board setup (skip for Standard projects)

Skip this step entirely for Standard projects.

Use the ADO MCP tools to set up the board **after** the repo fork completes.
The default team name is `<ProjectName> Team`.

---

### Fabric Accelerator board setup

#### 6a — Create iterations (Fabric Accelerator)

Create the following iterations under the project root using `mcp__ado__work_create_iterations`,
then assign each to the default team using `mcp__ado__work_assign_iterations`. Do not assign
start/finish dates — leave scheduling to the delivery team.

| Iteration name          |
|-------------------------|
| Discovery               |
| Deployment              |
| Configuration           |
| Automation              |
| Validation and Handover |

#### 6b — Create epics (Fabric Accelerator)

Create the following Epics using `mcp__ado__wit_create_work_item` (type: `Epic`):

1. Discovery Workshop
2. LLD Creation
3. Infrastructure Deployment
4. Fabric Capacities, Domains & Workspaces
5. Entra ID & RBAC Configuration
6. Azure DevOps Pipeline Automation
7. Data Gateway Installation
8. Capacity Metrics App
9. Validation & Documentation

#### 6c — Create user stories (Fabric Accelerator)

Create User Stories using `mcp__ado__wit_create_work_item` (type: `User Story`) — create all
stories in parallel first, then link each to its parent Epic in a single batch call using
`mcp__ado__wit_work_items_link` with `type: "parent"` (set `id` = story ID, `linkToId` = epic ID).
Note: `wit_add_child_work_items` creates new child items — do not use it here.

The board follows the SA 5-phase delivery approach: Workshop → LLD Creation → IaC/SalzDev →
Customer Deployment → Post Deployment. Stories that are specific to SalzDev (SA internal test
environment) are labelled accordingly; stories for the customer environment are labelled
"in customer environment".

**Epic 1 — Discovery Workshop**
- Run adoption roadmap workshop with customer stakeholders
- Document RBAC and security requirements
- Complete capacity planning
- Produce and share discovery report

**Epic 2 — LLD Creation**
- Create LLD v0.1
- SA internal peer review of LLD
- LLD playback to customer
- Customer sign-off on LLD v1.0

**Epic 3 — Infrastructure Deployment**
SalzDev track:
- Configure IaC templates (Bicep/PowerShell)
- Configure workload identities in SalzDev
- WhatIf/plan validation run
- Deploy Fabric environment to SalzDev
- Peer review and validate SalzDev deployment
Customer track:
- Deploy Fabric environment to customer environment
- Peer review and validate customer deployment

**Epic 4 — Fabric Capacities, Domains & Workspaces**
SalzDev track:
- Provision Fabric capacities in SalzDev (up to 10)
- Create Fabric domains in SalzDev
- Provision workspaces per domain in SalzDev
Customer track:
- Provision Fabric capacities in customer environment
- Create Fabric domains in customer environment
- Provision workspaces per domain in customer environment

**Epic 5 — Entra ID & RBAC Configuration** (both environments — Entra ID groups apply to SalzDev and customer)
SalzDev track:
- Create Entra ID security groups in SalzDev
- Assign RBAC roles to groups in SalzDev
- Validate access controls in SalzDev
Customer track:
- Create Entra ID security groups in customer environment
- Assign RBAC roles to groups in customer environment
- Validate access controls in customer environment

**Epic 6 — Azure DevOps Pipeline Automation**
SalzDev track:
- Create deployment pipelines
- Configure service connections for SalzDev
- Test pipeline execution against SalzDev end-to-end
Customer track:
- Configure service connections for customer environment
- Test pipeline execution in customer environment end-to-end

**Epic 7 — Data Gateway Installation** (customer environment only — not applicable in SalzDev)
- Install standard data gateway in customer environment
- Configure gateway connections in customer environment
- Test gateway connectivity in customer environment

**Epic 8 — Capacity Metrics App** (both environments)
SalzDev track:
- Install Capacity Metrics App in SalzDev
- Configure Capacity Metrics App permissions in SalzDev
- Validate metrics reporting in SalzDev
Customer track:
- Install Capacity Metrics App in customer environment
- Configure Capacity Metrics App permissions in customer environment
- Validate metrics reporting in customer environment

**Epic 9 — Validation & Documentation**
- Execute validation test plan
- Complete handover documentation
- Obtain customer sign-off
- Sign off on Cloud Platform Task Board

#### 6d — Wire predecessor/successor dependencies (Fabric Accelerator)

After all stories are created and parent-linked, add predecessor links using
`mcp__ado__wit_work_items_link` with `type: "predecessor"` to enforce the delivery sequence.
Use `{ id: <blocked story>, linkToId: <blocking story>, type: "predecessor" }`.

**Important:** The batch tool processes only one update per work item per call. Stories with
multiple predecessors must be sent in a **separate** second batch call (one entry per predecessor).

The dependency chain (using story position within each epic, since IDs vary per project):

```
Phase 1 — Discovery (E1):
  E1.S1 → E1.S2
  E1.S1 → E1.S3
  E1.S2 + E1.S3 → E1.S4   (two separate batch entries for E1.S4)

Phase 2 — LLD Creation (E2, follows Discovery):
  E1.S4 → E2.S1 → E2.S2 → E2.S3 → E2.S4

Phase 3 — IaC & SalzDev (E3 SalzDev track, follows LLD sign-off):
  E2.S4 → E3.S1 → E3.S2 → E3.S3 → E3.S4 → E3.S5

  After SalzDev infra validated (E3.S5), two parallel tracks start immediately:
    Capacities SalzDev: E3.S5 → E4.S1 → E4.S2 → E4.S3
    Pipelines SalzDev:  E3.S5 → E6.S1 → E6.S2 → E6.S3

  After SalzDev workspaces provisioned (E4.S3), two more parallel tracks:
    RBAC SalzDev:    E4.S3 → E5.S1(SalzDev) → E5.S2(SalzDev) → E5.S3(SalzDev)
    Metrics SalzDev: E4.S3 → E8.S1(SalzDev) → E8.S2(SalzDev) → E8.S3(SalzDev)

Phase 4 — Customer Deployment (follows SalzDev infra + SalzDev pipelines):
  E3.S5 → E3.S6  (two separate batch entries for E3.S6)
  E6.S3 → E3.S6
  E3.S6 → E3.S7

  After customer infra validated (E3.S7), parallel tracks:
    Customer Capacities: E3.S7 → E4.S4 → E4.S5 → E4.S6
    Customer Pipelines:  E3.S7 → E6.S4 → E6.S5
    Gateway:             E3.S7 → E7.S1 → E7.S2 → E7.S3

  After customer workspaces provisioned (E4.S6):
    RBAC customer:    E4.S6 → E5.S4(customer) → E5.S5(customer) → E5.S6(customer)
    Metrics customer: E4.S6 → E8.S4(customer) → E8.S5(customer) → E8.S6(customer)

Phase 5 — Validation (E9, follows all customer tracks):
  E5.S6(customer) + E6.S5 + E7.S3 + E8.S6(customer) → E9.S1  (four separate batch entries)
  E9.S1 → E9.S2 → E9.S3 → E9.S4
```

Submit predecessor links in batches — first all single-predecessor links, then a second batch
for each story that has more than one predecessor (E1.S4, E3.S6, E9.S1).

#### 6e — Backlog priority ordering (Fabric Accelerator)

After all stories are created and linked, set `Microsoft.VSTS.Common.BacklogPriority` on every
story to enforce delivery order in the backlog. **Higher value = higher in the backlog (top).**
Stories default to creation-order values, so the newest stories sink to the bottom without this step.

Use `mcp__ado__wit_update_work_items_batch` to set values in one or two parallel calls. Assign
values from 45000 down to 1000 in steps of 1000 (45 stories total), ordered by delivery sequence:

| Delivery sequence | Group | Value range |
|---|---|---|
| 1–4 | Discovery (E1, all 4 stories) | 45000–42000 |
| 5–8 | LLD Creation (E2, all 4 stories) | 41000–38000 |
| 9–13 | Infrastructure SalzDev (E3 S1–S5) | 37000–33000 |
| 14–16 | Capacities SalzDev (E4 S1–S3) | 32000–30000 |
| 17–19 | Pipelines SalzDev (E6 S1–S3) | 29000–27000 |
| 20–22 | RBAC SalzDev (E5 S1–S3) | 26000–24000 |
| 23–25 | Metrics SalzDev (E8 S1–S3) | 23000–21000 |
| 26–27 | Infrastructure customer (E3 S6–S7) | 20000–19000 |
| 28–30 | Capacities customer (E4 S4–S6) | 18000–16000 |
| 31–32 | Pipelines customer (E6 S4–S5) | 15000–14000 |
| 33–35 | RBAC customer (E5 S4–S6) | 13000–11000 |
| 36–38 | Gateway customer (E7 S1–S3) | 10000–8000 |
| 39–41 | Metrics customer (E8 S4–S6) | 7000–5000 |
| 42–44 | Validation (E9 S1–S3) | 4000–2000 |
| 45 | Sign off on Cloud Platform Task Board (E9 S4) | 1000 |

#### 6f — Team settings (Fabric Accelerator)

Use `mcp__ado__work_get_team_settings` to confirm the default team exists, then set working days
to Monday–Friday if the API permits it.

---

### Data Platform board setup

#### 6a — Create iterations (Data Platform)

Create the following iterations under the project root using `mcp__ado__work_create_iterations`,
then assign each to the default team using `mcp__ado__work_assign_iterations`. Do not assign
start/finish dates — leave scheduling to the delivery team.

| Iteration name            |
|---------------------------|
| Discovery                 |
| Infrastructure Deployment |
| Configuration             |
| Automation                |
| Validation and Handover   |

#### 6b — Create epics (Data Platform)

Create the following Epics using `mcp__ado__wit_create_work_item` (type: `Epic`):

1. Discovery Workshop
2. LLD Creation
3. Landing Zone Infrastructure Deployment
4. Networking & Connectivity
5. Management Groups & Policy
6. Entra ID & RBAC Configuration
7. Azure DevOps Pipeline Automation
8. Data Platform Services
9. Validation & Documentation

#### 6c — Create user stories (Data Platform)

Create User Stories using `mcp__ado__wit_create_work_item` (type: `User Story`) — create all
stories in parallel first, then link each to its parent Epic in a single batch call using
`mcp__ado__wit_work_items_link` with `type: "parent"` (set `id` = story ID, `linkToId` = epic ID).
Note: `wit_add_child_work_items` creates new child items — do not use it here.

The board follows the SA 5-phase delivery approach: Workshop → LLD Creation → IaC/SalzDev →
Customer Deployment → Post Deployment. Stories that are specific to SalzDev (SA internal test
environment) are labelled accordingly; stories for the customer environment are labelled
"in customer environment".

**Epic 1 — Discovery Workshop** (6 stories)
- Run ALZ assessment workshop with customer stakeholders
- Document environment requirements (dev/test/prod tiers and subscription model)
- Capture IP address ranges and network topology requirements
- Define management group structure and hierarchy
- Agree naming conventions and tagging standards
- Produce and share discovery report

**Epic 2 — LLD Creation** (4 stories)
- Create LLD v0.1
- SA internal peer review of LLD
- LLD playback to customer
- Customer sign-off on LLD v1.0

**Epic 3 — Landing Zone Infrastructure Deployment** (7 stories)
SalzDev track:
- Configure IaC templates (Bicep/PowerShell) in SalzDev
- Configure workload identities in SalzDev
- WhatIf/plan validation run in SalzDev
- Deploy Landing Zone to SalzDev
- Peer review and validate SalzDev deployment
Customer track:
- Deploy Landing Zone to customer environment
- Peer review and validate customer deployment

**Epic 4 — Networking & Connectivity** (6 stories)
SalzDev track:
- Configure hub VNet, subnets and peering in SalzDev
- Configure private DNS zones in SalzDev
- Validate end-to-end connectivity in SalzDev
Customer track:
- Configure hub VNet, subnets and peering in customer environment
- Configure private DNS zones in customer environment
- Validate end-to-end connectivity in customer environment

**Epic 5 — Management Groups & Policy** (6 stories)
SalzDev track:
- Create management group hierarchy in SalzDev
- Apply Azure Policy initiatives in SalzDev
- Validate policy compliance in SalzDev
Customer track:
- Create management group hierarchy in customer environment
- Apply Azure Policy initiatives in customer environment
- Validate policy compliance in customer environment

**Epic 6 — Entra ID & RBAC Configuration** (6 stories)
SalzDev track:
- Create Entra ID security groups in SalzDev
- Assign RBAC roles to groups in SalzDev
- Validate access controls in SalzDev
Customer track:
- Create Entra ID security groups in customer environment
- Assign RBAC roles to groups in customer environment
- Validate access controls in customer environment

**Epic 7 — Azure DevOps Pipeline Automation** (5 stories)
SalzDev track:
- Create deployment pipelines
- Configure service connections for SalzDev
- Test pipeline execution against SalzDev end-to-end
Customer track:
- Configure service connections for customer environment
- Test pipeline execution in customer environment end-to-end

**Epic 8 — Data Platform Services** (6 stories)
SalzDev track:
- Deploy data platform services in SalzDev (ADLS Gen2, Key Vault, monitoring)
- Configure private endpoints for data services in SalzDev
- Validate data platform services in SalzDev
Customer track:
- Deploy data platform services in customer environment
- Configure private endpoints for data services in customer environment
- Validate data platform services in customer environment

**Epic 9 — Validation & Documentation** (4 stories)
- Execute validation test plan
- Complete handover documentation
- Obtain customer sign-off
- Sign off on Cloud Platform Task Board

#### 6d — Wire predecessor/successor dependencies (Data Platform)

After all stories are created and parent-linked, add predecessor links using
`mcp__ado__wit_work_items_link` with `type: "predecessor"` to enforce the delivery sequence.
Use `{ id: <blocked story>, linkToId: <blocking story>, type: "predecessor" }`.

**Important:** The batch tool processes only one update per work item per call. Stories with
multiple predecessors must be sent in a **separate** second batch call (one entry per predecessor).

The dependency chain (using story position within each epic, since IDs vary per project):

```
Phase 1 — Discovery (E1):
  E1.S1 → E1.S2
  E1.S1 → E1.S3
  E1.S1 → E1.S4
  E1.S1 → E1.S5
  E1.S2 + E1.S3 + E1.S4 + E1.S5 → E1.S6   (four separate batch entries for E1.S6)

Phase 2 — LLD Creation (E2, follows Discovery):
  E1.S6 → E2.S1 → E2.S2 → E2.S3 → E2.S4

Phase 3 — IaC & SalzDev (E3 SalzDev track, follows LLD sign-off):
  E2.S4 → E3.S1 → E3.S2 → E3.S3 → E3.S4 → E3.S5

  After SalzDev infra validated (E3.S5), three parallel tracks start immediately:
    Networking SalzDev:    E3.S5 → E4.S1 → E4.S2 → E4.S3
    Pipelines SalzDev:     E3.S5 → E7.S1 → E7.S2 → E7.S3
    Mgmt Groups SalzDev:   E3.S5 → E5.S1 → E5.S2 → E5.S3

  After SalzDev networking validated (E4.S3), two more parallel tracks:
    RBAC SalzDev:          E4.S3 → E6.S1 → E6.S2 → E6.S3
    Data Platform SalzDev: E4.S3 → E8.S1 → E8.S2 → E8.S3

Phase 4 — Customer Deployment (follows SalzDev infra + SalzDev pipelines):
  E3.S5 → E3.S6  (two separate batch entries for E3.S6)
  E7.S3 → E3.S6
  E3.S6 → E3.S7

  After customer infra validated (E3.S7), three parallel tracks start immediately:
    Networking customer:   E3.S7 → E4.S4 → E4.S5 → E4.S6
    Mgmt Groups customer:  E3.S7 → E5.S4 → E5.S5 → E5.S6
    Pipelines customer:    E3.S7 → E7.S4 → E7.S5

  After customer networking validated (E4.S6), two more parallel tracks:
    RBAC customer:         E4.S6 → E6.S4 → E6.S5 → E6.S6
    Data Platform customer: E4.S6 → E8.S4 → E8.S5 → E8.S6

Phase 5 — Validation (E9, follows all customer tracks):
  E5.S6(customer) + E6.S6 + E7.S5 + E8.S6(customer) → E9.S1  (four separate batch entries)
  E9.S1 → E9.S2 → E9.S3 → E9.S4
```

Submit predecessor links in batches — first all single-predecessor links, then a second batch
for each story that has more than one predecessor (E1.S6, E3.S6, E9.S1).

#### 6e — Backlog priority ordering (Data Platform)

After all stories are created and linked, set `Microsoft.VSTS.Common.BacklogPriority` on every
story to enforce delivery order in the backlog. **Higher value = higher in the backlog (top).**

Use `mcp__ado__wit_update_work_items_batch` to set values in one or two parallel calls. Assign
values from 50000 down to 1000 in steps of 1000 (50 stories total), ordered by delivery sequence:

| Delivery sequence | Group | Value range |
|---|---|---|
| 1–6 | Discovery (E1, all 6 stories) | 50000–45000 |
| 7–10 | LLD Creation (E2, all 4 stories) | 44000–41000 |
| 11–15 | Infrastructure SalzDev (E3 S1–S5) | 40000–36000 |
| 16–18 | Networking SalzDev (E4 S1–S3) | 35000–33000 |
| 19–21 | Pipelines SalzDev (E7 S1–S3) | 32000–30000 |
| 22–24 | Mgmt Groups SalzDev (E5 S1–S3) | 29000–27000 |
| 25–27 | RBAC SalzDev (E6 S1–S3) | 26000–24000 |
| 28–30 | Data Platform SalzDev (E8 S1–S3) | 23000–21000 |
| 31–32 | Infrastructure customer (E3 S6–S7) | 20000–19000 |
| 33–35 | Networking customer (E4 S4–S6) | 18000–16000 |
| 36–38 | Mgmt Groups customer (E5 S4–S6) | 15000–13000 |
| 39–40 | Pipelines customer (E7 S4–S5) | 12000–11000 |
| 41–43 | RBAC customer (E6 S4–S6) | 10000–8000 |
| 44–46 | Data Platform customer (E8 S4–S6) | 7000–5000 |
| 47–49 | Validation (E9 S1–S3) | 4000–2000 |
| 50 | Sign off on Cloud Platform Task Board (E9 S4) | 1000 |

#### 6f — Team settings (Data Platform)

Use `mcp__ado__work_get_team_settings` to confirm the default team exists, then set working days
to Monday–Friday if the API permits it.

---

### Board setup error handling

If any MCP call fails during board setup, log the error clearly but do not abort — continue with
remaining items. Report all failures at the end so the user can manually create what's missing.

---

## Step 7 — Report the outcome (all project types)

On success, confirm:

```
Project created : https://dev.azure.com/<Organisation>/<ProjectName>
Repo fork       : <"FabricBicep (main only) forked from Infrastructure and Security"
                  | "DataLandingZone_bicepavm (main only) forked from Infrastructure and Security"
                  | "skipped — standard project">
Board setup     : <summary of what was created, or "skipped — standard project">

Next steps:
- Add a service connection (New-AzureDevOpsServiceConnection.ps1)
- Confirm PIM group materialisation in ADO Security settings
- Create a customer branch from main if needed
- Set the `ServiceConnection` pipeline variable on the PR Validation pipeline once a service connection exists — this enables the Bicep what-if stage
```

If board setup had partial failures, list them here with a note to create manually.

On script failure, show the error output clearly and suggest whether to retry or investigate.

---

## Notes

- The `-Force` flag bypasses all interactive prompts inside the scripts — all confirmation is
  handled here before we invoke.
- If the project already exists, the creation script exits cleanly with a warning — the PIM and
  hardening steps will still run, which is idempotent and safe.
- If an Azure DevOps MCP server is available in your session, you can use it to verify the project
  was created (list projects, get project details) rather than relying solely on the script output.
- Board setup is idempotent in spirit but not enforced — running the skill twice on the same
  project will duplicate iterations and work items. Only run board setup once per project.
