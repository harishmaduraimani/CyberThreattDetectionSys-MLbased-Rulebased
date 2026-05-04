from engine.detection_result import DetectionResult
class RiskEngine:
    def __init__(self):
        self.suspicious_threshold = 30
        self.dangerous_threshold =70
    def normalize_score(self,score):
        if score<0:
            return 0
        if score>100:
            return 100
        
        return score
    def calculate_perdict(self,score):
        score = self.dangerous_threshold
        if score >= self.dangerous_threshold:
            return "Dangerous"
        if score >= self.suspicious_threshold:
            return "Suspicious"
        return "safe"
    
    def evaluate_single_result(self,detector_result):
        final_score = self.normalize_score(detector_result.riskscore)
        final_perdict = self.calculate_perdict(final_score)
        return DetectionResult(
            detectorname = detector_result.detectorname,
            riskscore=final_score,
            perdict=final_perdict,
            reason=detector_result.reason,
            parameters=detector_result.parameters
        )