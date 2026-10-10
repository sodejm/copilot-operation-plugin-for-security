"""Shared evidence contracts; portable consumers use the generated approved subset."""

from .ai_components import (
    ComponentVerificationError,
    assess_component_baselines,
    canonical_component_identity,
    validate_component_manifest,
    verify_component_manifest,
)
from .ai_inventory import (
    InventoryError,
    InventoryRegistry,
    adapt_entra_service_principals,
    compare_inventories,
    import_inventory,
    inventory_report,
)
from .assessment import assess, report
from .canonical import EvidenceError, canonical, decode_json
from .contract import build_envelope
from .validation import validate_envelope, validate_receipt

__all__ = [
    "EvidenceError",
    "canonical",
    "decode_json",
    "build_envelope",
    "validate_envelope",
    "validate_receipt",
    "assess",
    "report",
]
__all__ += [
    "InventoryError",
    "InventoryRegistry",
    "import_inventory",
    "compare_inventories",
    "inventory_report",
    "adapt_entra_service_principals",
]
__all__ += [
    "ComponentVerificationError",
    "canonical_component_identity",
    "validate_component_manifest",
    "verify_component_manifest",
    "assess_component_baselines",
]
