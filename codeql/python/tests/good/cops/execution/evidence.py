"""Inert examples with returned sanitized values and unrelated file operations."""

import hashlib
from pathlib import Path

from cops.evidence.canonical import canonical
from cops.evidence.contract import build_envelope
from cops.execution.redaction import StreamRedactor


class EvidenceRecorder:
    def __init__(self):
        self.redactor = StreamRedactor()

    def record_step_output(self, stdout, stderr, error, action, artifact_outputs):
        reservation = object()
        clean_stdout = self.redactor.redact_bytes(stdout)
        clean_stderr = self.redactor.redact_bytes(stderr)
        clean_error = self._clean_error(error)
        clean_action = self.redactor.redact_string(action)
        artifacts = []
        for path, content in artifact_outputs.items():
            clean_path = self.redactor.redact_string(path)
            clean_content = self.redactor.redact_bytes(content)
            artifacts.append({"path": clean_path, "content_sha256": hashlib.sha256(clean_content).hexdigest()})
        envelope = build_envelope(payload={
            "provenance": {"action": clean_action},
            "streams": {
                "stdout": {"sha256": hashlib.sha256(clean_stdout).hexdigest()},
                "stderr": {"sha256": hashlib.sha256(clean_stderr).hexdigest()},
                "error": {"sha256": hashlib.sha256(clean_error).hexdigest()},
            },
            "artifacts": artifacts,
        })
        self._write_reserved_artifact(reservation, clean_stdout + clean_stderr)
        self._write_reserved_artifact(reservation, canonical(envelope))
        self._write_reserved_artifact(reservation, b"benign fixed marker")

    def _write_reserved_artifact(self, reservation, content):
        pass

    def _clean_error(self, error):
        return self.redactor.redact_bytes(error)


def unrelated_debug_output(stdout):
    # A parameter's name alone does not make it evidence capture or persistence.
    Path("unused-fixture-path").write_bytes(stdout)


class OtherRecorder:
    def record_step_output(self, stdout):
        self._write_reserved_artifact(None, stdout)

    def _write_reserved_artifact(self, reservation, content):
        pass
