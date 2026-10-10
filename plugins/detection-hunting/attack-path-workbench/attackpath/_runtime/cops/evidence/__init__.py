"""Shared evidence contracts; portable consumers use the generated approved subset."""
from .assessment import assess, report
from .canonical import EvidenceError, canonical, decode_json
from .contract import build_envelope
from .validation import validate_envelope, validate_receipt
from .ai_inventory import (InventoryError, InventoryRegistry, adapt_entra_service_principals,
                           compare_inventories, import_inventory, inventory_report)

__all__ = ["EvidenceError", "canonical", "decode_json", "build_envelope",
           "validate_envelope", "validate_receipt", "assess", "report"]
__all__ += ["InventoryError", "InventoryRegistry", "import_inventory", "compare_inventories",
            "inventory_report", "adapt_entra_service_principals"]
