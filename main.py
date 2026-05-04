from detectors.file_detector import detect_file
from detectors.url_detector import detect_url
from detectors.port_scanner import detect_open_ports
from engine.risk_engine import RiskEngine
risk_engine = RiskEngine()
url = "http://example.com/login.php?user=admin"
raw_result = detect_url(url)
result = risk_engine.evaluate_single_result(raw_result)


# Print the result
print("Detector:", result.detectorname)
print("Risk Score:", result.riskscore)
print("Verdict:", result.perdict)
print("Reason:", result.reason)
