"""Finite, validated acquisition limits; resumes may only tighten them."""
import math
from dataclasses import asdict, dataclass

from cops.evidence import EvidenceError


@dataclass(frozen=True)
class Limits:
    pages: int = 100
    attempts: int = 401
    records: int = 10000
    response_bytes: int = 4 * 1024 * 1024
    total_bytes: int = 64 * 1024 * 1024
    record_bytes: int = 1024 * 1024
    storage_bytes: int = 64 * 1024 * 1024
    depth: int = 32
    request_seconds: float = 10
    active_seconds: float = 300
    retries: int = 3

    def __post_init__(self):
        ceilings = dict(pages=10000, attempts=100000, records=1000000,
                        response_bytes=16777216, total_bytes=1073741824,
                        record_bytes=16777216, storage_bytes=1073741824,
                        depth=64, request_seconds=120, active_seconds=86400, retries=10)
        for name, value in asdict(self).items():
            expected = (int, float) if name.endswith('seconds') else (int,)
            if type(value) not in expected or not math.isfinite(value) or not (0 if name == 'retries' else 1) <= value <= ceilings[name]:
                raise EvidenceError('invalid_limit')

    def export(self):
        return asdict(self)
