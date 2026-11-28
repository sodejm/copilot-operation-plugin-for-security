"""Inert regression examples; these functions are extracted, never executed."""

import hashlib

from cops.evidence.canonical import canonical as serialize
from cops.evidence.contract import build_envelope
from cops.execution.redaction import StreamRedactor


class EvidenceRecorder:
    def __init__(self):
        self.redactor = StreamRedactor()

    def record_step_output(self, stdout, stderr, error, action, artifact_outputs):
        reservation = object()
        # Raw output bytes bypass the redactor.
        self._write_reserved_artifact(reservation, content=stdout)  # $ Alert

        # Calling a redactor does not modify the original bytes in place.
        self.redactor.redact_bytes(stderr)
        self._write_reserved_artifact(reservation, stderr)  # $ Alert

        # The actual persisted shape is a payload inside an envelope, serialized later.
        envelope = build_envelope(payload={"streams": {"error": {"sha256": hashlib.sha256(error).hexdigest()}}})
        self._write_reserved_artifact(reservation, serialize(envelope))  # $ Alert

        action_envelope = build_envelope(payload={"provenance": {"action": action}})
        self._persist(reservation, serialize(action_envelope))

        for path, content in artifact_outputs.items():
            self.redactor.redact_bytes(content)
            artifact_envelope = build_envelope(payload={"artifacts": [{
                "path": self.redactor.redact_string(path),
                "content_sha256": hashlib.sha256(content).hexdigest(),
            }]})
            self._write_reserved_artifact(reservation, serialize(artifact_envelope))  # $ Alert
            path_envelope = build_envelope(payload={"artifacts": [{
                "path": path,
                "content_sha256": hashlib.sha256(self.redactor.redact_bytes(content)).hexdigest(),
            }]})
            self._write_portable_reserved_artifact(reservation, serialize(path_envelope))  # $ Alert

        # Sanitizing one value does not bless the original or the whole envelope.
        mixed = build_envelope(payload={"streams": {
            "stdout": self.redactor.redact_bytes(stdout).decode("utf-8"),
            "stderr": stderr.decode("utf-8"),
        }})
        self._write_reserved_artifact(reservation, serialize(mixed))  # $ Alert

    def _persist(self, reservation, content):
        self._write_reserved_artifact(reservation, content)  # $ Alert

    def _write_reserved_artifact(self, reservation, content):
        pass

    def _write_portable_reserved_artifact(self, reservation, content):
        pass
