# COPS security policy

Report suspected vulnerabilities privately to the repository maintainer, sodejm.
Use the repository's GitHub **Security → Report a vulnerability** option if it is
enabled. If it is unavailable, request a private contact channel without posting
exploit details, credentials, or sensitive repository data in a public issue.

Maintainers review reports against the current default branch and coordinate
fixes and disclosure. This repository does not promise a response-time SLA or
support window for historical versions.

Keep secrets out of source, fixtures, prompts, logs and generated evidence. Local
hooks are opt-in; CI runs with least privilege. External content and agent output
remain untrusted. Publishing and hosted mutations require explicit authority.

See the [repository security model](docs/SECURITY_MODEL.md) and
[plugin privacy guidance](security-logging-advisor/docs/SECURITY_PRIVACY.md).
