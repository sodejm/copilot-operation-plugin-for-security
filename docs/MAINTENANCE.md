# COPS maintenance

Review compatibility when a host changes discovery, permissions, skills or hooks.
Verify current official host documentation before changing integration claims.
Review contributor skills for overlap and stale commands, synchronize adapters,
and run `make check`. Record version-specific host smoke tests separately from
static checks. Review dependency and GitHub Action updates before merging.

For PARK upgrades, compare upstream with the revision in
[the adoption record](decisions/0001-park-adoption.md), apply a reviewed diff, and
preserve COPS-specific checks, plugin behavior, specifications and licensing.
Update attribution and the adopted revision when importing a later version.
Do not re-run a project generator over this configured repository.
