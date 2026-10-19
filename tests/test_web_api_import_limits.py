from __future__ import annotations

import hashlib
import io
import json
import traceback
from pathlib import Path

import pytest

from cops.web_api import importer, models
from cops.web_api.importer import ImporterError, import_har, import_openapi, import_postman, import_raw_http
from cops.web_api.models import ApiInventory, ReplayBudget, ReplaySessionReport

LIMIT = 512


def _json_bytes(document: dict[str, object]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


CASES = (
    ("har", import_har, _json_bytes({"log": {"entries": []}})),
    ("openapi", import_openapi, _json_bytes({"openapi": "3.0.3", "paths": {}})),
    ("postman", import_postman, _json_bytes({"info": {"name": "bounded"}, "item": []})),
    ("raw", import_raw_http, b"GET / HTTP/1.1\r\nHost: bounded.example\r\n\r\n"),
)


@pytest.mark.parametrize(("suffix", "loader", "base_content"), CASES)
def test_file_import_accepts_exact_limit_and_hashes_exact_bytes(suffix, loader, base_content, tmp_path, monkeypatch):
    monkeypatch.setattr(importer, "MAX_IMPORT_BYTES", LIMIT)
    content = base_content + (b" " * (LIMIT - len(base_content)))
    source = tmp_path / f"exact.{suffix}"
    source.write_bytes(content)

    inventory = loader(source)

    assert inventory.provenance is not None
    assert inventory.provenance.sha256 == hashlib.sha256(content).hexdigest()


@pytest.mark.parametrize(("suffix", "loader", "base_content"), CASES)
def test_file_import_rejects_limit_plus_one_without_path_or_content(
    suffix, loader, base_content, tmp_path, monkeypatch
):
    monkeypatch.setattr(importer, "MAX_IMPORT_BYTES", LIMIT)
    secret = "never-echo-this-import-secret"
    content = base_content + secret.encode() + (b" " * (LIMIT + 1 - len(base_content) - len(secret)))
    source = tmp_path / f"private-{secret}.{suffix}"
    source.write_bytes(content)

    with pytest.raises(ImporterError, match="API import input exceeds the byte limit") as caught:
        loader(source)
    formatted = "".join(traceback.format_exception(caught.type, caught.value, caught.tb))

    assert secret not in formatted
    assert str(source) not in formatted


def test_bounded_reader_handles_short_binary_reads(monkeypatch):
    content = _json_bytes({"openapi": "3.0.3", "paths": {"/short": {"get": {}}}})

    class ShortReader(io.BytesIO):
        def read(self, size=-1):
            assert 0 < size <= importer.MAX_IMPORT_BYTES + 1
            return super().read(min(size, 3))

    monkeypatch.setattr(importer, "MAX_IMPORT_BYTES", LIMIT)
    monkeypatch.setattr(Path, "open", lambda self, mode: ShortReader(content))

    inventory = import_openapi(Path("opaque-input.json"))

    assert inventory.provenance is not None
    assert inventory.provenance.sha256 == hashlib.sha256(content).hexdigest()


def test_bounded_reader_consumes_only_max_plus_one_bytes(monkeypatch):
    content = _json_bytes({"openapi": "3.0.3", "paths": {}, "padding": "x" * LIMIT})

    class CountingReader(io.BytesIO):
        consumed = 0

        def read(self, size=-1):
            result = super().read(size)
            self.consumed += len(result)
            return result

    reader = CountingReader(content)
    monkeypatch.setattr(importer, "MAX_IMPORT_BYTES", LIMIT)
    monkeypatch.setattr(Path, "open", lambda self, mode: reader)

    with pytest.raises(ImporterError, match="API import input exceeds the byte limit"):
        import_openapi(Path("opaque-input.json"))

    assert reader.consumed == LIMIT + 1


def test_import_paths_do_not_use_unbounded_path_helpers(tmp_path, monkeypatch):
    source = tmp_path / "bounded.json"
    content = _json_bytes({"openapi": "3.0.3", "paths": {}})
    source.write_bytes(content)
    monkeypatch.setattr(Path, "read_bytes", lambda self: pytest.fail("unbounded read_bytes used"))
    monkeypatch.setattr(Path, "read_text", lambda self, *args, **kwargs: pytest.fail("unbounded read_text used"))

    assert import_openapi(source).provenance.sha256 == hashlib.sha256(content).hexdigest()


def test_inline_text_and_mapping_obey_encoded_byte_limit(monkeypatch):
    monkeypatch.setattr(importer, "MAX_IMPORT_BYTES", 32)

    with pytest.raises(ImporterError, match="API import input exceeds the byte limit"):
        import_raw_http("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
    with pytest.raises(ImporterError, match="API import input exceeds the byte limit"):
        import_openapi({"openapi": "3.0.3", "paths": {"/too-large": {"get": {}}}})


@pytest.mark.parametrize("loader", [import_har, import_openapi, import_postman, import_raw_http])
def test_malformed_binary_input_errors_are_content_free(loader, tmp_path):
    secret = "malformed-private-secret"
    source = tmp_path / f"private-{secret}.input"
    source.write_bytes(b"\xff" + secret.encode())

    with pytest.raises(ImporterError) as caught:
        loader(source)
    formatted = "".join(traceback.format_exception(caught.type, caught.value, caught.tb))

    assert secret not in formatted
    assert str(source) not in formatted


@pytest.mark.parametrize(
    ("loader", "content"),
    [
        (import_har, b'{"malformed-private-secret":'),
        (import_openapi, b'{"malformed-private-secret":'),
        (import_postman, b'{"malformed-private-secret":'),
        (import_raw_http, b"malformed-private-secret"),
    ],
)
def test_malformed_text_input_errors_are_content_free(loader, content, tmp_path):
    secret = "malformed-private-secret"
    source = tmp_path / f"private-{secret}.input"
    source.write_bytes(content)

    with pytest.raises(ImporterError) as caught:
        loader(source)
    formatted = "".join(traceback.format_exception(caught.type, caught.value, caught.tb))

    assert secret not in formatted
    assert str(source) not in formatted


def _saved_documents():
    return (
        (
            ApiInventory.load,
            ApiInventory(inventory_id="inv-bounded", name="Bounded inventory").to_dict(),
        ),
        (
            ReplaySessionReport.load,
            ReplaySessionReport(
                session_id="rep-bounded",
                target_hosts=[],
                allowed_destinations=[],
                budget=ReplayBudget(),
            ).to_dict(),
        ),
    )


@pytest.mark.parametrize(("loader", "document"), _saved_documents())
def test_saved_document_load_accepts_exact_limit(loader, document, tmp_path, monkeypatch):
    encoded = _json_bytes(document)
    limit = len(encoded) + 17
    monkeypatch.setattr(models, "MAX_WEB_API_DOCUMENT_BYTES", limit)
    source = tmp_path / "exact-document.json"
    source.write_bytes(encoded + (b" " * (limit - len(encoded))))

    assert loader(source).to_dict() == document


@pytest.mark.parametrize(("loader", "document"), _saved_documents())
def test_saved_document_load_rejects_limit_plus_one_without_disclosure(loader, document, tmp_path, monkeypatch):
    encoded = _json_bytes(document)
    limit = len(encoded) + 17
    marker = "private-saved-document-secret"
    monkeypatch.setattr(models, "MAX_WEB_API_DOCUMENT_BYTES", limit)
    source = tmp_path / f"{marker}.json"
    source.write_bytes(encoded + (b" " * (limit + 1 - len(encoded))))

    with pytest.raises(ValueError, match="web API document exceeds the byte limit") as caught:
        loader(source)
    formatted = "".join(traceback.format_exception(caught.type, caught.value, caught.tb))

    assert marker not in formatted
    assert str(source) not in formatted


def test_saved_document_reader_handles_short_binary_reads(monkeypatch):
    document = ApiInventory(inventory_id="inv-short", name="Short reads").to_dict()
    content = _json_bytes(document)

    class ShortReader(io.BytesIO):
        def read(self, size=-1):
            assert 0 < size <= models.MAX_WEB_API_DOCUMENT_BYTES + 1
            return super().read(min(size, 3))

    monkeypatch.setattr(models, "MAX_WEB_API_DOCUMENT_BYTES", len(content))
    monkeypatch.setattr(Path, "open", lambda self, mode: ShortReader(content))

    assert ApiInventory.load(Path("opaque-document.json")).to_dict() == document


def test_saved_document_paths_do_not_use_unbounded_path_helpers(tmp_path, monkeypatch):
    source = tmp_path / "bounded-inventory.json"
    document = ApiInventory(inventory_id="inv-bounded", name="Bounded document").to_dict()
    source.write_bytes(_json_bytes(document))
    monkeypatch.setattr(Path, "read_bytes", lambda self: pytest.fail("unbounded read_bytes used"))
    monkeypatch.setattr(Path, "read_text", lambda self, *args, **kwargs: pytest.fail("unbounded read_text used"))

    assert ApiInventory.load(source).to_dict() == document


@pytest.mark.parametrize("content", [b"\xffprivate-json-secret", b'{"private-json-secret":'])
def test_saved_document_malformed_input_errors_are_content_free(content, tmp_path):
    marker = "private-json-secret"
    source = tmp_path / f"{marker}.json"
    source.write_bytes(content)

    with pytest.raises(ValueError, match="web API document is invalid") as caught:
        ApiInventory.load(source)
    formatted = "".join(traceback.format_exception(caught.type, caught.value, caught.tb))

    assert marker not in formatted
    assert str(source) not in formatted
