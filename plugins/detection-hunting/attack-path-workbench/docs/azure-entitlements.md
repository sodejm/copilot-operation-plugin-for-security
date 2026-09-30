# Offline Azure entitlement analysis

The Azure profile models control-plane entitlement chains from local Microsoft Graph
and Azure Resource Manager evidence. It evaluates a declared controlled principal,
user-selected targets and an explicit UTC analysis time. Reports describe predicates
supported by the supplied model and assumptions, not compromise or successful
exploitation. Both commands are standard-library-only and require Python 3.11+.

## Commands

From the plugin directory:

```sh
python3 scripts/attackpath.py plan-azure-collection --scope-file scopes.json --output collection-plan
python3 scripts/attackpath.py analyze-azure --input bundle/manifest.json --as-of 2026-09-28T12:00:00Z --output azure-report
```

Use a fresh output directory. The planner writes `collection-plan.json`; it does not
collect evidence. The analyzer writes `report.json`, `report.md`, `graph.json`,
`evidence-ledger.json`, `remediation.json`, and finally `completion.json`. The marker
contains SHA-256 hashes of the five report files. Check both the marker and report
status before using results. Exit 2 means a rejected input or output error; no
successful completion marker is emitted for that failed analysis.

All commands are offline. Collection, credential changes, entitlement changes,
secret access and remediation execution require separate authorized tooling.

## Collection scope and evidence contract

A minimal collection scope is:

```json
{
  "schema_version": "attackpath.azure.scope/v1",
  "tenants": [{"id": "TENANT-ID", "scopes": ["/subscriptions/SUBSCRIPTION-ID"]}]
}
```

Optional explicit `groups`, `applications`, `service_principals`,
`administrative_units`, `management_groups`, `user_assigned_identities`, and
`resources` lists add object-specific requests. The planner pins supported Graph
and ARM API versions, required permissions, pagination requirements and Microsoft
documentation for each request. It also plans read-only Azure Resource Graph POST
queries for explicitly declared subscription and management-group scopes. Queries
for narrower scopes filter to that scope and its descendants; root and ancestry-only
management groups do not expand inventory. Only resource IDs and types are projected.
Resource Graph can omit resources the collector cannot read, so successful inventory
does not establish complete coverage. Use returned IDs in a second typed ARM
collection plan; inventory is not an analyzable evidence family. Follow-up object
requests require explicit IDs; the planner does not infer or fetch them. The scope schema is
[azure-scope-v1.schema.json](../schemas/azure-scope-v1.schema.json), and the output
contract is [azure-collection-v1.schema.json](../schemas/azure-collection-v1.schema.json).
Only Azure public-cloud endpoints are supported.

The input manifest uses
[azure-input-v1.schema.json](../schemas/azure-input-v1.schema.json). Each source
names an allowlisted `family`, pinned `api`, `tenant`, explicit `scopes`, relative
JSONL `path`, SHA-256 `sha256`, relative `receipt`, `receipt_sha256`, and
`max_age_seconds`. Object-specific families require `context.groupId` or
`context.objectId`. Each JSONL line is one `cops.evidence/v1` page envelope whose
record uses `cops.record/v1`; its payload has a `value` array of projected objects.
A `cops.acquisition/v1` receipt binds the ordered pages, counts, continuation state
and terminal acquisition status. Both receipt `pages` and `records` equal consumed
page-envelope count. Page envelopes and inner projected objects share one
ingestion record budget.
Original record parents and locators must survive collector-side projections.

Hash mismatches, unsupported APIs, malformed receipts, inconsistent pagination,
unsafe paths and invalid object projections reject analysis. Source and receipt
paths must remain within the manifest directory and resolve to regular files;
symlinks and special files are rejected. The descriptor-based reader requires a
POSIX platform with safe directory-relative open support. Stale, redacted and
incomplete acquisitions can support uncertainty explanations but cannot establish
modelled reachability. Declared completeness is bounded by the API behavior:
Graph v1.0 group membership omits service principals, and hidden membership needs
additional read permission. Positive membership witnesses remain usable.

Supported families include users, groups and membership; applications, service
principals, owners and federation; directory role assignments and definitions,
administrative units and membership; app-role assignments, Conditional Access and
authentication strengths; directory and Azure PIM schedules and policies; ARM
resources, role assignments and definitions, deny assignments and management-group
ancestry; and Lighthouse registration definitions and assignments. Unsupported
policy semantics remain unknown rather than inferred from their presence.

## Data-acquisition matrix

The matrix below describes the requests and read permissions emitted by the
planner. Microsoft Graph requests use `v1.0`; ARM requests use the listed API
version at each explicitly declared scope. The generated plan supplies the exact
URLs, projections, documentation references and continuation instructions.
Permissions must be authorized for the requested tenant and scope; the planner
does not grant them or verify the collector's access.

| Evidence family | API endpoint or ARM provider/type | Read permission in the plan |
| --- | --- | --- |
| `users` | Graph `/users` | `User.Read.All` |
| `groups` | Graph `/groups` | `Group.Read.All` |
| `group_members` | Graph `/groups/{id}/members` | `GroupMember.Read.All`; hidden membership also needs `Member.Read.Hidden` |
| `applications` | Graph `/applications` | `Application.Read.All` |
| `service_principals` | Graph `/servicePrincipals` | `Application.Read.All` |
| `owners` | Graph `/{applications\|servicePrincipals}/{id}/owners` | `Application.Read.All` |
| `federated_credentials` (application) | Graph `/applications/{id}/federatedIdentityCredentials` | `Application.Read.All` |
| `directory_assignments`, `directory_definitions` | Graph `/roleManagement/directory/{roleAssignments\|roleDefinitions}` | `RoleManagement.Read.Directory` |
| `administrative_units`, `administrative_members` | Graph `/directory/administrativeUnits` and `/{id}/members` | `AdministrativeUnit.Read.All` |
| `app_role_assignments` | Graph `/servicePrincipals/{id}/appRoleAssignments` | `Application.Read.All` |
| `conditional_access`, `authentication_strengths` | Graph `/identity/conditionalAccess/policies` and `/authenticationStrength/policies` | `Policy.Read.All` |
| `directory_pim_eligible` | Graph `/roleManagement/directory/roleEligibilityScheduleInstances` | `RoleEligibilitySchedule.Read.Directory` |
| `directory_pim_active` | Graph `/roleManagement/directory/roleAssignmentScheduleInstances` | `RoleAssignmentSchedule.Read.Directory` |
| `directory_pim_policies`, `directory_pim_policy_assignments` | Graph `/policies/{roleManagementPolicies\|roleManagementPolicyAssignments}` | `RoleManagementPolicy.Read.Directory` |
| `resources` | Typed ARM GETs listed below | Resource-specific `read` operation listed below |
| `role_assignments`, `role_definitions`, `deny_assignments` | ARM `Microsoft.Authorization/{roleAssignments\|roleDefinitions\|denyAssignments}`, `2022-04-01` | Corresponding provider/type followed by `/read` |
| `scope_parents` | ARM `Microsoft.Management/managementGroups`, `2020-05-01` | `Microsoft.Management/managementGroups/read` |
| `azure_pim_eligible` | ARM `Microsoft.Authorization/roleEligibilityScheduleInstances`, `2020-10-01` | `Microsoft.Authorization/roleEligibilityScheduleInstances/read` |
| `azure_pim_active` | ARM `Microsoft.Authorization/roleAssignmentScheduleInstances`, `2020-10-01` | `Microsoft.Authorization/roleAssignmentScheduleInstances/read` |
| `azure_pim_policies`, `azure_pim_policy_assignments` | ARM `Microsoft.Authorization/{roleManagementPolicies\|roleManagementPolicyAssignments}`, `2020-10-01` | Corresponding provider/type followed by `/read` |
| `lighthouse`, `lighthouse_assignments` | ARM `Microsoft.ManagedServices/{registrationDefinitions\|registrationAssignments}`, `2022-10-01` | Corresponding provider/type followed by `/read` |
| `federated_credentials` (user-assigned identity) | ARM `Microsoft.ManagedIdentity/userAssignedIdentities/{id}/federatedIdentityCredentials`, `2023-01-31` | `Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/read` |
| `resource_inventory` (planning only) | Resource Graph `/providers/Microsoft.ResourceGraph/resources`, `2024-04-01` | `Microsoft.ResourceGraph/resources/read` and underlying resource-type read at the declared scope |

Typed `resources` requests support these profiles:

| Resource type | ARM API version | Read permission |
| --- | --- | --- |
| Virtual machine | `2024-07-01` | `Microsoft.Compute/virtualMachines/read` |
| Automation account | `2024-10-23` | `Microsoft.Automation/automationAccounts/read` |
| Functions site | `2024-11-01` | `Microsoft.Web/sites/read` |
| Logic Apps workflow | `2019-05-01` | `Microsoft.Logic/workflows/read` |
| Key Vault | `2023-07-01` | `Microsoft.KeyVault/vaults/read` |
| User-assigned identity | `2023-01-31` | `Microsoft.ManagedIdentity/userAssignedIdentities/read` |

Object-specific requests require the optional ID lists described above. Graph
membership limitations and Resource Graph omissions still bound coverage even
when the listed permissions are present. Collect only allowlisted projections;
do not acquire credentials, secret values, app settings, certificates or tokens.
Keep receipts, hashes and evidence locally with the privacy controls below.

## Scenario and authorization rules

The manifest requires `scenario.controlled` entries with tenant and principal ID,
and `scenario.targets` entries with tenant, ARM scope, action and `plane` (`control`
or `data`). Identities are tenant-qualified. ARM scope comparisons use normalized
segments and observed management-group ancestry. Role-local `notActions` and
`notDataActions` exclusions do not remove permissions from a different grant.
Applicable denies take precedence. Only a narrow GUID-based version 2.0 condition
subset is evaluated; other conditions remain unknown. Directory roles honor object
and administrative-unit scope. Administrative-unit membership cannot establish
application or service-principal credential rights: Microsoft limits those units
to [users, groups and devices](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/administrative-units).
Group and PIM relations require actual witnesses.

An eligible PIM schedule is latent until a declared activation meets its supported
duration, approval, MFA and authentication-context requirements. Credential routes
also require explicit credential-policy or owner-rights assumptions. Those claims
are listed as scenario assumptions, separate from evidence ledger references.
Lighthouse considers supported built-in control-plane roles and restricted
user-access delegation; it does not infer data-plane or Owner permissions from
cross-tenant management alone.

| Transition | Required control rights and scenario prerequisites |
| --- | --- |
| RBAC grant | `Microsoft.Authorization/roleAssignments/write`, a supported role definition and assignable scope; hypothetical access is re-evaluated against denies and conditions |
| Application credentials | Scoped directory credential-update authorization or explicitly asserted owner rights, a same-tenant application/service-principal relationship and permitted credential update |
| VM execution | VM `write` and extensions `write`; `vm_agent`, `network`, `token_endpoint` |
| ARM deployment execution | All nine supported deployment operations at the resource group, extensions `write` on an observed VM, and `vm_agent`, `network`, `token_endpoint` |
| Automation execution | Runbook draft content `write`, runbook `publish/action`, jobs `write`; `automation_sandbox`, `network`, `token_endpoint` |
| Functions execution | Site `write` and `publish/action`; `function_deployment`, `invocation`, `network`, `token_endpoint` |
| Logic Apps execution | Workflow `write` and triggers `run/action`; `logic_consumption`, `identity_action`, `invocation`, `network`, `token_endpoint` |
| User-assigned identity attachment | Identity `assign/action`, workload configuration rights and the execution prerequisites of the selected workload |
| Federation | Credential-update authorization plus an exact issuer, subject and audience match to an explicitly controlled assertion |
| Key Vault access policy | Access-policy update rights, a supported policy-mode vault, and explicit network/token assumptions; vault `write` alone does not grant secret access |

The ARM deployment route requires `Microsoft.Resources/deployments/` operations
`read`, `write`, `delete`, `cancel/action`, `validate/action`, `whatIf/action`,
`exportTemplate/action`, `operations/read`, and `operationstatuses/read`. It checks
each operation and the underlying VM-extension write separately, including scope,
role exclusions, conditions and denies. This follows the [ARM deployment permission
requirements](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/deploy-powershell).
The supported route installs an extension on an observed VM with an observed
identity; arbitrary templates, creation of a new VM and unobserved identities
remain unsupported. Deployment rights alone cannot establish identity execution.

`scenario.runtime` maps normalized resource IDs to Boolean prerequisites. Missing
values remain unknown; explicit `false` blocks the transition. An identity must
also have supported downstream target authorization. The initial data-plane target
catalog covers Key Vault secret-get and Storage blob-read actions. Control-plane
roles do not automatically establish data-plane rights. Arbitrary target actions
and unsupported resource profiles remain unknown.

## Results and counterfactuals

| Classification | Meaning |
| --- | --- |
| `modelled_reachable` | Required authorization predicates and scenario assumptions are supported within the bounded model |
| `conditional` | Missing runtime assumptions prevent a supported execution conclusion |
| `latent_eligibility` | An eligible entitlement has unmet activation requirements |
| `blocked` | A deny, expired assignment or explicitly false prerequisite prevents the route |
| `unknown` | Missing evidence, incomplete coverage or unsupported semantics prevent a decision |

The report includes versioned rules, prerequisite decisions, evidence references,
scenario assumptions, uncertainty and stable ranking factors. Business impact is
`not_supplied` unless the scenario provides a scope-specific label; no probability
or approved business-impact rating is inferred. Schemas are supplied for
[reports](../schemas/azure-report-v1.schema.json),
[graphs](../schemas/azure-graph-v1.schema.json),
[ledgers](../schemas/azure-ledger-v1.schema.json),
[remediation](../schemas/azure-remediation-v1.schema.json), and
[completion](../schemas/azure-completion-v1.schema.json).

The remediation ledger removes one observed entitlement at a time and reruns the
bounded analysis. It records broken, surviving and alternate paths, remaining
reachable paths and whether that bounded comparison is conclusive. At most 64
candidate cuts are evaluated under the shared work budget. A surviving alternate
grant prevents a claimed cut. There is no global minimum-cut claim, automatic
entitlement removal, owner assignment or closure; owner validation is required.

## Limits, privacy and operations

Defaults allow 64 files, 4 MiB per evidence file, 64 MiB total bytes read,
50,000 combined page envelopes and projected records, 50,000 nodes, 200,000
edges, 12 hops, 1,000 paths, 200,000 work expansions and 32 MiB output.
Bounded manifest overrides cannot exceed the ceilings in the input schema.
Manifest and collection scope files are capped at 256 KiB, receipts at 64 KiB,
physical JSONL lines at 1 MiB and JSON depth at 32. The total includes
manifests, receipts, sources and integrity rechecks. The per-file, total-byte,
file-count, line-byte, record and JSON-depth ceilings are 16 MiB, 256 MiB, 256,
4 MiB, 200,000 and 64 respectively. The analyzer accepts `--max-file-bytes`,
`--max-total-bytes`, `--max-files`, `--max-line-bytes`, `--max-records` and
`--max-json-depth` to tighten manifest limits. Successful reports record
effective limits and counters with the run ID. Collection plans allow 16 tenants,
128 entries per optional object list and 2,048 requests. A graph, hop, path or
work limit makes the report partial and prevents a completeness claim. An input
or output byte-limit violation rejects the run instead of emitting a successful
marker.

Set `scenario.pseudonymize` to `true` for stable opaque tenant, principal, scope
and resource identifiers with consistent graph joins. Owner-supplied business
impact labels are withheld in that mode. This is pseudonymization, not guaranteed
anonymity: hashes, timestamps, actions and graph structure remain correlatable.
Raw records and credential values are not copied into reports. Allowlisted source
fields, ledger hashes and observation metadata support local traceability.

Output directories are created with mode 0700 and files with mode 0600. Existing
output directories and symlink parents are rejected. Markdown escapes source text.
The completion marker is written last; a failed write can leave partial files and
requires a fresh directory for retry. Keep raw evidence and reports in approved
local storage and review them before sharing with a model provider.

The synthetic illustrative commands and identifiers continue to work unchanged.
The Azure commands and versioned contracts are additive; no stored-data migration
is required. Rollback consists of using the earlier plugin version and retaining
Azure evidence/report directories separately. The portable export bundles only a
generated SDK validation subset and needs neither the COPS repository nor network
access at runtime. Live collection, Attack Flow and automated workflow integration
remain separate workstreams.
