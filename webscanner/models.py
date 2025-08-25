from dataclasses import dataclass, field, asdict
from typing import Optional, List
import time
import uuid

@dataclass
class Finding:
    id: str
    scan_id: str
    url: str
    param: Optional[str]
    vuln_type: str
    severity: str
    evidence: str
    payload: Optional[str] = None
    owasp: Optional[str] = None
    cwe: Optional[str] = None
    risk_score: int = 0

    def to_dict(self):
        return asdict(self)

@dataclass
class ScanState:
    id: str
    target: str
    scope_domain: str
    started_at: float
    finished_at: Optional[float] = None
    pages_crawled: int = 0
    status: str = "running"
    error: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)

    def add_finding(self, f: Finding):
        self.findings.append(f)

    @property
    def progress(self) -> float:
        # progress heuristic: pages crawled vs MAX_PAGES is computed by UI
        return min(1.0, float(self.pages_crawled) / max(1.0, 50.0))

def new_scan_id() -> str:
    return str(uuid.uuid4())
