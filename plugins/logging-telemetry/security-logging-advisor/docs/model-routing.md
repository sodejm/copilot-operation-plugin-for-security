# COPS model and runtime guidance

The repository scanner, package validator, adapter generator and test suite are
deterministic local programs. Run them directly; they do not require an LLM.

Use an available model in the approved host for interpreting evidence and drafting
security logging recommendations. Choose the least costly model that can handle
the repository's complexity and required tool access. Increase reasoning capacity
when evidence is conflicting, architecture spans services, or security conclusions
need deeper analysis. Inspect the host's live model catalog and official guidance
before naming a model or reasoning setting; COPS pins neither.

Model selection does not grant tool, source, network or publishing permissions.
Evaluate recommendations against repository evidence and record assumptions.
Subagent delegation is optional and must follow the active host and task policy;
no scanner or validation task requires delegation.

Contributor portability is described in [compatibility](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/docs/COMPATIBILITY.md).
Product host integration must be tested separately as described in
[installation](INSTALL.md). Review [privacy](SECURITY_PRIVACY.md) before sending
repository context to any model provider.
