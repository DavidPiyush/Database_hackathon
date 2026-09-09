from typing import TypedDict, Any, Dict, List


class EmailInput(TypedDict, total=False):
    file_path: str
    subject: str
    body: str
    sender: str
    recipient: str


class ModelResult(TypedDict, total=False):
    model: str
    label: str
    probability: float
    score: float
    findings: List[str]
    details: Dict[str, Any]


class RiskResult(TypedDict, total=False):
    final_score: float
    threat_level: str
    model_scores: Dict[str, float]
    risk_factors: List[str]
    details: Dict[str, Any]


class PipelineResult(TypedDict, total=False):
    email: EmailInput
    model_results: List[ModelResult]
    risk_result: RiskResult