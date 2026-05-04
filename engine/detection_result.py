from dataclasses import dataclass, field

@dataclass
class DetectionResult:
    detectorname : str
    riskscore:int
    perdict: str
    reason: str
    parameters: dict = field(default_factory=dict)
