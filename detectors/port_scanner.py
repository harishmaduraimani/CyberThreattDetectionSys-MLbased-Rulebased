import socket

from engine.detection_result import DetectionResult


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "Remote Desktop"
}


RISKY_PORTS = {
    21: "FTP can expose file transfer access",
    23: "Telnet sends data without encryption",
    445: "SMB is commonly targeted in Windows attacks",
    3306: "MySQL database should not be exposed publicly",
    3389: "Remote Desktop is commonly targeted by attackers"
}


def scan_port(target_host, port, timeout=1):
    # Create a TCP socket
    scanner_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Set timeout so the scanner does not wait forever
    scanner_socket.settimeout(timeout)

    try:
        # Try connecting to the target host and port
        result = scanner_socket.connect_ex((target_host, port))

        # connect_ex returns 0 when the port is open
        if result == 0:
            return True

        # Any non-zero result means closed or unreachable
        return False

    finally:
        # Always close the socket after checking the port
        scanner_socket.close()


def scan_ports(target_host, ports):
    # Store all open ports here
    open_ports = []

    # Check each port one by one
    for port in ports:
        # Scan the current port
        is_open = scan_port(target_host, port)

        # If port is open, save it
        if is_open:
            service_name = COMMON_PORTS.get(port, "Unknown Service")

            open_ports.append({
                "port": port,
                "service": service_name
            })

    # Return list of open ports
    return open_ports


def detect_open_ports(target_host, ports=None):
    # If no custom ports are given, scan common ports
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    # Scan the selected ports
    open_ports = scan_ports(target_host, ports)

    # Start risk score at zero
    risk_score = 0

    # Store explanation messages
    reasons = []

    # If no ports are open, this is low risk
    if not open_ports:
        reasons.append("No open common ports found")

    # Analyze each open port
    for item in open_ports:
        # Get port number from result
        port = item["port"]

        # Get service name from result
        service = item["service"]

        # Add a basic risk score for every open port
        risk_score += 10
        reasons.append(f"Open port found: {port} ({service})")

        # Add extra risk for sensitive ports
        if port in RISKY_PORTS:
            risk_score += 20
            reasons.append(RISKY_PORTS[port])

    # Keep risk score between 0 and 100
    if risk_score > 100:
        risk_score = 100

    # Decide final verdict
    if risk_score >= 70:
        verdict = "Dangerous"
    elif risk_score >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    # Return structured detector result
    return DetectionResult(
        detectorname="Port Scanner Detector",
        riskscore=risk_score,
        perdict=verdict,
        reason="; ".join(reasons),
        parameters={
        "target_host": target_host,
        "scanned_ports": ports,
        "open_ports": open_ports,
        "open_port_count": len(open_ports)
    }
    )
