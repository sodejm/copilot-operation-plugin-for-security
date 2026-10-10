# Supporting guidance registry

`catalog/provenance.json` registers the following stable identifiers for
supporting-guidance inventory mappings. Each identifier resolves to this document
and names COPS guidance, rather than external procedure text.

| Guidance ID | COPS guidance record |
| --- | --- |
| `COPS-E01.01-GUIDE` | Network discovery safety guidance |
| `COPS-E03.01-GUIDE` | Pivoting scope guidance |
| `COPS-E06.03-GUIDE` | Privilege boundary guidance |
| `COPS-E10.07-GUIDE` | Pod Security Standards guidance |
| `COPS-E10.08-GUIDE` | Kubernetes RBAC guidance |
| `COPS-E14.01-GUIDE` | Web assessment safety guidance |
| `COPS-E17.02-GUIDE` | Active Directory assessment guidance |

The registry validates that an inventory mapping names one of these records. A
record is a resolution target and does not, by itself, establish authorship,
license compatibility, copying, or operational evidence.

## Applicability decisions

The provenance registry also maintains a `decisions` table. Every
`applicability_decision` mapping must name a registered decision ID, whose
rationale records the COPS scoping basis. A decision records inventory treatment;
it does not authorize reuse, execution, or an external security assessment.
