from pydantic import BaseModel
from typing import List

class RemediateRequest(BaseModel):
    team: str
    cve_ids: List[str]

class SeveritySummary(BaseModel):
    severity: str
    count: int