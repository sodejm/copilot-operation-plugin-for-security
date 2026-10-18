# Web API inventory and replay

The workbench imports HAR 1.2, OpenAPI 3, Swagger 2, Postman collections, and
raw HTTP without changing their source documents. Live HTTP and GraphQL replay
is permitted only for requests represented by an immutable `ActionPlan`, after
the approval authority returns a matching receipt for the worker identity and
after the destination and resolved address pass scope checks. Preview produces
a redacted plan report and performs no I/O.

Source provenance hashes exact file or inline UTF-8 bytes, including whitespace;
mapping inputs use sorted, compact JSON. Inventories retain an opaque digest
reference, never a source path or inline document. Caller-supplied digests must
match the imported bytes. Ambiguous raw HTTP authorities are rejected.
Report serialization strips URL user information and redacts query values,
fragments and recognizable credentials in relative references and metadata.
Wire requests remain separate: approval digests bind their lossless content.

Authorization assessment uses actual disposable loopback services. Each REST
and GraphQL object case records owner, other-user, and anonymous outcomes. A
vulnerable profile exposes the owner's object to the other user; a corrected
profile denies it. Rate-limit assessment records each response and requires
enough requests to reach the configured enforcement threshold. Missing
observations are reported as insufficient evidence rather than success.

WebSocket import metadata is preserved, but live WebSocket replay is not
implemented. Production approval-provider deployment validation is a separate
Linux integration concern; focused tests use the same consume-only approval
protocol with a deterministic local authority double.
