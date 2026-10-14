# Model and effort routing suggestions

Use the `model-effort-routing` skill before implementing an issue or planning
security work. It combines the task's requirements with an operator-supplied host
catalog and explains which exact model and effort pairs qualify. The advisor is
offline and deterministic: it makes no provider requests, changes no settings and
grants no execution authority.

## Runtime and usage

Run from a COPS repository checkout with Python 3.11 or newer, as described in the
[installation guide](../README.md#installation-and-runtime-availability). Plugin
installation alone does not install the root `cops` runtime. A standalone portable
archive includes this skill and guide, but needs that checkout to run the advisor.
Do not install an unrelated package named `cops` to satisfy this dependency.

```bash
python3 -m cops route "Review the issue's authorization boundary" \
  --suggest-model --model-catalog ./host-models.json \
  --current-model exact-current-host-id --current-effort medium --json
```

`python3 -m cops.routing route` accepts the same flags. `--model-catalog` implies
advice; `--suggest-model` without a catalog reports requirements and requests host
discovery. Calls without advice flags retain the existing specialist route output.
Use `--task-kind` and `--complexity` to correct ambiguous keyword classification.
These flags affect advice only; specialist selection and authorization gates keep
their existing behavior. Omit the advice flags to return to the previous workflow.
There is no stored state or data migration.

## Obtain a catalog

Read the current host's model selector or supported discovery API, the account's
access status and current provider documentation. Record exact IDs, supported
efforts and capabilities for that host. A provider's public model announcement
does not establish availability in a particular account or subagent launcher.

Catalogs contain operator assertions. COPS validates their structure and freshness;
it cannot authenticate them or independently verify entitlement. Keep the file
local and omit credentials, account identifiers, internal URLs and private prompts.
`source` should be a short, non-sensitive description of the discovery evidence.
Refresh the underlying evidence when refreshing `observed_at`; changing only the
timestamp does not establish current availability.

The following is **synthetic, deliberately stale example data**, not an inventory
of available models. Replace it with observed host evidence before use:

```json
{
  "schema_version": "cops.model-catalog/v1",
  "source": "Example host selector and access check",
  "observed_at": "2000-01-01T00:00:00Z",
  "models": [
    {
      "id": "example-efficient-model",
      "family": "Example general model",
      "tier": "efficient",
      "capabilities": ["general", "coding"],
      "available": true,
      "access": "granted",
      "efforts": ["low", "medium"],
      "preference": 0
    },
    {
      "id": "example-daybreak-blue-model",
      "family": "Daybreak",
      "tier": "flagship",
      "capabilities": ["security", "advanced-security"],
      "available": true,
      "access": "granted",
      "efforts": ["medium", "high"],
      "preference": 0
    }
  ]
}
```

All shown fields are required; unknown or duplicate fields and duplicate IDs are
rejected. Files must be UTF-8 JSON, at most 1 MiB, with at most 256 model records.
An empty inventory is valid and yields no eligible model. `observed_at` requires a
timezone, must be no more than 24 hours old and cannot be in the future. Correct
host clock errors before using the advice.

| Field | Contract |
| --- | --- |
| `id` | Exact host ID, at most 128 characters; letters, digits, `.`, `_`, `:`, `/`, `-`; starts with a letter or digit. |
| `family` | Printable display label, at most 80 characters; never an eligibility rule. |
| `tier` | `efficient`, `balanced` or `flagship`, based on documented model capability. |
| `capabilities` | Nonempty distinct subset of `general`, `coding`, `security`, `advanced-security`. |
| `available` | Boolean from host discovery. |
| `access` | `granted`, `denied` or `unknown`, checked separately for each exact model. |
| `efforts` | Nonempty distinct supported values from `low`, `medium`, `high`, `xhigh`, `max`, `ultra`. |
| `preference` | Integer 0–10000; smaller values rank first within a sufficient tier. |

Capability tags are independent. `advanced-security` does not imply `security`,
`coding` or `general`; list each supported capability explicitly. Normalize a
provider's native effort control only when its mapping is verified for the exact
host/model. Do not invent a `high` setting for a model that lacks it.

Daybreak, Fable, Mythos, Astra and future model families qualify through these same
fields. Names alone establish neither a cybersecurity specialty nor access.
Daybreak Blue and Red require separate exact records and access checks; Blue access
never supplies Red access. Unknown or denied access cannot be forced by a prompt.

## Task requirements and ranking

| Task kind | Required capability | Minimum tier | Minimum effort |
| --- | --- | --- | --- |
| `routine` | `general` | `efficient` | `low` |
| `coding` | `coding` | `balanced` | `medium` |
| `security-review` | `security` | `flagship` | `high` |
| `adversarial-research` | `advanced-security` | `flagship` | `high` |

`auto` uses explainable keywords and can misclassify issue prose. Review the
reported `task` against the issue and acceptance criteria. `--complexity simple`
allows coding at efficient/low; `--complexity complex` requires flagship/high for
any task kind. Security and adversarial tasks retain their flagship/high minimum
even at simple complexity. A complex documentation task also requires flagship/high.

The advisor picks the lowest sufficient tier, then operator preference, then exact
ID. It chooses the lowest supported sufficient effort among low, medium and high.
Tiers and preference are not measured prices, quality benchmarks or proof that one
qualifying family is better than another. Set preference from relevant evaluations
when several models qualify. Insufficient capability or effort never silently
falls back to a weaker model.

`xhigh`, `max` and `ultra` are manual escalations. The advisor can recognize an
explicitly selected supported setting as adequate, but never selects those values
automatically. Model choice and effort are separate decisions; the general approach
follows [OpenAI's model selection guidance](https://developers.openai.com/api/docs/guides/model-selection#how-to-think-about-models-and-reasoning-effort).

## Interpret the result before implementation

JSON adds `model_advice` with `task`, `recommendation`, `alternatives`, `excluded`,
`current` and `next_action`. A suggested pair is an option to select through the
host; no model call or automatic switch has occurred.

| Result | Required response |
| --- | --- |
| `catalog_required`, `catalog_stale`, `catalog_future` | Refresh host evidence before choosing a model. |
| `no_eligible_model` | Review exclusions and obtain an appropriate available model; do not weaken requirements merely to get a result. |
| `current.status: unverified` | Verify both current model and effort through the host before implementation. |
| `current.status: change_recommended` | Present the exact qualified model and supported effort; pause until the host selection or an authorized supported delegation is verified. |
| `current.status: adequate` | Current settings meet the catalog requirements; retain them unless task evidence supports a beneficial change. |

Exclusions explain unavailable/unknown/denied access, missing capability,
insufficient tier or lack of an automatically selectable effort. An invalid catalog
exits with code 2 before routing authorization; a valid advisory result, including
no eligible model, exits successfully. Automation must inspect the result fields,
not treat exit code 0 as permission to implement.

For every issue, read its full scope and assess whether Daybreak would materially
benefit the work. If a qualified Daybreak option would help and requires a change,
stop and name its exact ID and effort. Otherwise still verify the current pair.
If the user authorizes delegation, use only model/effort overrides supported by
the actual subagent launcher and its applicable routing/workboard policy. A child
model setting does not change the parent; catalog eligibility does not establish
launcher support. This skill itself neither launches agents nor changes settings.

Retain the existing engagement scope, approval and execution gates. A model
recommendation is not authorization to conduct an assessment.
