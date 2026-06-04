"""
draugr_ics.py — ICS/OT ATT&CK technique library for Draugr.

Maps CWE weakness classes and common OT/ICS vulnerability patterns
to MITRE ATT&CK for ICS (https://attack.mitre.org/matrices/ics/)
technique IDs and provides business/technical narratives.

ICS ATT&CK technique IDs use the Txxxx namespace distinct from
Enterprise ATT&CK.
"""
from typing import Dict, List, Optional, Any


# ── ICS ATT&CK technique definitions ────────────────────────────────
ICS_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T0817": {
        "name":        "Drive-by Compromise",
        "tactic":      "Initial Access",
        "description": "Adversaries may gain initial access to ICS/OT systems through compromised websites visited by operators on engineering workstations or HMI systems connected to the internet.",
        "impact":      "Engineering workstation compromise; potential pivot to OT network",
        "detection":   "Monitor web proxy logs from workstations with OT network access; alert on unusual download activity from engineering stations.",
    },
    "T0819": {
        "name":        "Exploit Public-Facing Application",
        "tactic":      "Initial Access",
        "description": "Adversaries may exploit internet-accessible ICS/SCADA applications (historian servers, remote access portals, SCADA web interfaces) to gain initial access to OT environments.",
        "impact":      "Direct OT network access; potential for process disruption or safety system manipulation",
        "detection":   "Monitor ICS web interfaces for anomalous HTTP requests; alert on authentication failures on OT-accessible portals.",
    },
    "T0822": {
        "name":        "External Remote Services",
        "tactic":      "Initial Access",
        "description": "Adversaries may leverage remote access services (VPN, RDP, vendor remote support tools) to gain access to ICS/OT networks.",
        "impact":      "Persistent access to OT environment; vendor jump-host compromise can cascade to all connected sites",
        "detection":   "Monitor VPN and remote access authentication logs; alert on off-hours or unusual-origin connections to OT jump hosts.",
    },
    "T0859": {
        "name":        "Valid Accounts",
        "tactic":      "Persistence / Lateral Movement",
        "description": "Adversaries may use valid OT credentials (often default, shared, or unchanged from commissioning) to access ICS systems and move laterally between process control network segments.",
        "impact":      "Authenticated access to PLCs, HMIs, and historian servers; difficult to distinguish from legitimate operator activity",
        "detection":   "Audit and enforce credential hygiene on all OT accounts; alert on authentication from unusual hosts or time windows.",
    },
    "T0886": {
        "name":        "Remote Services",
        "tactic":      "Lateral Movement",
        "description": "Adversaries may use legitimate remote services protocols native to ICS environments (Modbus, DNP3, OPC-UA, proprietary vendor protocols) to move laterally between OT devices without triggering traditional IT security controls.",
        "impact":      "Lateral movement between OT network segments; direct PLC/RTU command injection capability",
        "detection":   "Deploy OT-aware network monitoring (Claroty, Dragos, Nozomi) to baseline and alert on anomalous protocol usage.",
    },
    "T0855": {
        "name":        "Unauthorized Command Message",
        "tactic":      "Impair Process Control",
        "description": "Adversaries may send unauthorized commands to PLCs, RTUs, or other field devices to disrupt, damage, or manipulate physical processes.",
        "impact":      "Direct physical process manipulation; potential equipment damage, safety system bypass, or production disruption",
        "detection":   "Deploy protocol-aware deep packet inspection; baseline and alert on anomalous command sequences on OT field bus networks.",
    },
    "T0813": {
        "name":        "Denial of Control",
        "tactic":      "Impair Process Control",
        "description": "Adversaries may cause a denial of control condition where operators are unable to issue commands to field devices, forcing manual intervention or automated failsafe activation.",
        "impact":      "Loss of process control; emergency shutdown may cause production loss or unsafe condition depending on failsafe design",
        "detection":   "Monitor HMI command acknowledgement rates; alert on operator control failures or unexpected safety system activations.",
    },
    "T0816": {
        "name":        "Device Restart/Shutdown",
        "tactic":      "Inhibit Response Function",
        "description": "Adversaries may restart or shutdown field devices to disrupt process control, remove evidence of malicious activity, or trigger failsafe conditions.",
        "impact":      "Process disruption; controller restart may trigger undefined states in dependent equipment",
        "detection":   "Monitor OT device availability; alert on unexpected device restarts or communication loss in the OT network.",
    },
    "T0800": {
        "name":        "Activate Firmware Update Mode",
        "tactic":      "Impair Process Control",
        "description": "Adversaries may force a device into firmware update mode to install malicious firmware or render the device inoperable.",
        "impact":      "Permanent device compromise or bricking; malicious firmware can persist through factory resets",
        "detection":   "Alert on firmware update mode activation outside of scheduled maintenance windows; enforce code-signing on all firmware updates.",
    },
    "T0845": {
        "name":        "Program Upload",
        "tactic":      "Collection",
        "description": "Adversaries may upload programs from PLCs or other field devices to obtain process logic for reconnaissance, understand safety interlocks, or identify targets for manipulation.",
        "impact":      "Disclosure of proprietary process logic and safety system design; enables targeted manipulation attacks",
        "detection":   "Baseline and alert on PLC upload operations from unexpected engineering stations or at unexpected times.",
    },
    "T0843": {
        "name":        "Program Download",
        "tactic":      "Impair Process Control",
        "description": "Adversaries may download modified or malicious programs to PLCs or other field devices, altering process behaviour in ways that may be difficult to detect through normal HMI monitoring.",
        "impact":      "Persistent process manipulation; modified PLC logic can survive controller reboots and may not be visible on HMI displays",
        "detection":   "Implement PLC program integrity monitoring; alert on any program download outside of change management windows.",
    },
    "T0836": {
        "name":        "Modify Parameter",
        "tactic":      "Impair Process Control",
        "description": "Adversaries may modify setpoints, thresholds, or operating parameters to drive processes outside safe operating ranges or to degrade product quality without triggering alarms.",
        "impact":      "Equipment damage, product quality degradation, or unsafe process conditions that may not trigger existing alarm thresholds",
        "detection":   "Monitor and log all setpoint and parameter changes; alert on changes outside of approved change windows.",
    },
    "T0831": {
        "name":        "Manipulation of Control",
        "tactic":      "Impair Process Control",
        "description": "Adversaries may manipulate physical process control to cause unintended equipment behaviour, production disruption, or safety system activation.",
        "impact":      "Physical process disruption; potential equipment damage or safety incident depending on process type",
        "detection":   "Cross-reference sensor data with expected process behaviour; alert on anomalous physical process deviations.",
    },
    "T0851": {
        "name":        "Rootkit",
        "tactic":      "Evasion",
        "description": "Adversaries may use rootkits on ICS/OT systems to hide malicious activity from operators and security tools.",
        "impact":      "Persistent covert access; rootkit can mask process manipulation from HMI displays, making attacks extremely difficult to detect",
        "detection":   "Implement file integrity monitoring on engineering workstations and historian servers; use OT-specific endpoint security.",
    },
    "T0856": {
        "name":        "Spoof Reporting Message",
        "tactic":      "Impair Process Control",
        "description": "Adversaries may spoof sensor readings or status messages to deceive operators about the true state of the physical process.",
        "impact":      "Operators make decisions based on falsified data; safety systems may not trigger even when physical conditions warrant intervention",
        "detection":   "Cross-validate sensor readings against physics-based process models; alert on statistically improbable sensor value combinations.",
    },
}

# ── CWE → ICS ATT&CK technique mappings ─────────────────────────────
# These map common CWE weaknesses found in OT/ICS products to likely
# adversary techniques if exploited in an ICS context.
ICS_CWE_TECHNIQUE_MAP: Dict[str, List[str]] = {
    "CWE-287":  ["T0819", "T0822", "T0859"],   # auth bypass → initial access
    "CWE-306":  ["T0819", "T0859"],             # missing auth
    "CWE-798":  ["T0859"],                      # hard-coded creds
    "CWE-78":   ["T0819", "T0855"],             # cmd injection → cmd messages
    "CWE-119":  ["T0819", "T0843"],             # buffer overflow → code exec → program download
    "CWE-787":  ["T0819", "T0843"],             # OOB write
    "CWE-416":  ["T0819"],                      # use-after-free
    "CWE-22":   ["T0845", "T0843"],             # path traversal → program upload/download
    "CWE-434":  ["T0800", "T0843"],             # file upload → firmware update / program download
    "CWE-319":  ["T0886", "T0856"],             # cleartext → sniff + spoof
    "CWE-295":  ["T0886"],                      # cert validation → MitM on OT protocols
    "CWE-400":  ["T0813", "T0816"],             # resource exhaustion → DoC / restart
    "CWE-770":  ["T0813", "T0816"],             # unbounded alloc → DoC
    "CWE-20":   ["T0836", "T0843"],             # input validation → param modify / program dl
}

# ── Tactic groups ────────────────────────────────────────────────────
ICS_TACTICS: Dict[str, List[str]] = {
    "Initial Access":           ["T0817","T0819","T0822"],
    "Execution":                ["T0843","T0800"],
    "Persistence":              ["T0843","T0851","T0859"],
    "Evasion":                  ["T0851","T0856"],
    "Discovery":                ["T0845"],
    "Lateral Movement":         ["T0886","T0859"],
    "Collection":               ["T0845"],
    "Command and Control":      ["T0822"],
    "Inhibit Response Function":["T0816","T0813"],
    "Impair Process Control":   ["T0855","T0813","T0800","T0843","T0836","T0831","T0856"],
}


def get_ics_techniques_for_cwe(cwe_id: str) -> List[Dict[str, Any]]:
    """Return ICS ATT&CK techniques mapped from a CWE ID."""
    tids = ICS_CWE_TECHNIQUE_MAP.get(cwe_id, [])
    return [
        {"technique_id": tid, **ICS_TECHNIQUES[tid]}
        for tid in tids
        if tid in ICS_TECHNIQUES
    ]


def get_ics_technique(tid: str) -> Optional[Dict[str, Any]]:
    return ICS_TECHNIQUES.get(tid)


def enrich_row_with_ics(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Augment a CVE row with ICS ATT&CK mappings where applicable.
    Adds 'ICS ATT&CK Techniques' field if any CWE maps to ICS techniques.
    """
    cwes = [c.strip() for c in str(row.get("CWE","") or "").split(";") if c.strip()]
    ics_techs: List[str] = []
    seen: set = set()
    for cwe in cwes:
        for t in get_ics_techniques_for_cwe(cwe):
            tid = t["technique_id"]
            if tid not in seen:
                seen.add(tid)
                ics_techs.append(f"{tid} ({t['name']})")
    if ics_techs:
        row["ICS ATT&CK Techniques"] = "; ".join(ics_techs)
    return row


def is_ics_relevant(row: Dict[str, Any]) -> bool:
    """
    Heuristic: is this CVE row likely relevant to an ICS/OT environment?
    True if CWEs map to ICS techniques or if software name suggests OT context.
    """
    cwes = [c.strip() for c in str(row.get("CWE","") or "").split(";") if c.strip()]
    if any(cwe in ICS_CWE_TECHNIQUE_MAP for cwe in cwes):
        return True
    name_l = str(row.get("Software Name","") or "").lower()
    ot_keywords = [
        "scada","hmi","plc","dcs","rtu","historian","wonderware","ignition",
        "factorytalk","wincc","simatic","step 7","tia portal","rslogix",
        "profinet","modbus","dnp3","opc","fieldbus","codesys","beckhoff",
    ]
    return any(kw in name_l for kw in ot_keywords)


def ics_summary_section(rows: List[Dict[str, Any]]) -> str:
    """
    Return a markdown section summarising ICS/OT-relevant findings.
    Returns empty string if no ICS-relevant rows exist.
    """
    ics_rows = [r for r in rows if is_ics_relevant(r)]
    if not ics_rows:
        return ""

    lines = [
        "## ICS / OT Attack Surface Analysis",
        "",
        f"**{len(ics_rows)} CVE(s)** in this scan have weakness classes or affected software "
        "indicative of ICS/OT relevance. The following ATT&CK for ICS technique mappings "
        "were identified:",
        "",
    ]

    # Aggregate technique coverage
    from collections import Counter
    tech_counter: Counter = Counter()
    for r in ics_rows:
        ics_str = str(r.get("ICS ATT&CK Techniques","") or "")
        for t in ics_str.split(";"):
            t = t.strip()
            if t:
                tech_counter[t] += 1

    if tech_counter:
        lines.append("| Technique | CVE Count | Tactic | Reference |")
        lines.append("|---|---|---|---|")
        for tech_str, cnt in tech_counter.most_common(10):
            import re
            m = re.match(r"(T\d{4})", tech_str)
            if m:
                tid  = m.group(1)
                info = ICS_TECHNIQUES.get(tid, {})
                tactic = info.get("tactic","—")
                url    = f"https://attack.mitre.org/techniques/{tid}/"
                lines.append(f"| {tech_str} | {cnt} | {tactic} | {url} |")
        lines.append("")

    lines += [
        "> **Note:** ICS/OT environments require specialised remediation approaches. "
        "Patches must be validated against process safety requirements before deployment. "
        "Compensating controls (network segmentation, OT-aware monitoring, change control) "
        "are critical for vulnerabilities that cannot be immediately patched in live process environments.",
        "",
    ]
    return "\n".join(lines)
