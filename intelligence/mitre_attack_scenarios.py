#!/usr/bin/env python3
"""
MITRE ATT&CK Technique-to-Tactic Impact Mapping
For integration with vulnerability scanning tools.
Maps CVEs to ATT&CK techniques with tactic categories and impact descriptions.
Total techniques: 632
"""

# ============================================================
# ATT&CK Tactic Definitions (14 Enterprise Tactics)
# ============================================================
TACTICS = {
    "TA0001": {
        "name": "Initial Access",
        "impact": (
            "An adversary gaining an initial foothold within the network, which could lead to unauthorized entry into systems, data exposure, and serve as a launching point for deeper compromise."
        ),
    },
    "TA0002": {
        "name": "Execution",
        "impact": (
            "An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "TA0003": {
        "name": "Persistence",
        "impact": (
            "An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
        ),
    },
    "TA0004": {
        "name": "Privilege Escalation",
        "impact": (
            "An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "TA0005": {
        "name": "Defense Evasion",
        "impact": (
            "An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "TA0006": {
        "name": "Credential Access",
        "impact": (
            "An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "TA0007": {
        "name": "Discovery",
        "impact": (
            "An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "TA0008": {
        "name": "Lateral Movement",
        "impact": (
            "An adversary moving through the network to reach additional systems, expanding the scope of compromise, accessing segmented resources, and potentially reaching high-value targets or critical infrastructure."
        ),
    },
    "TA0009": {
        "name": "Collection",
        "impact": (
            "An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "TA0010": {
        "name": "Exfiltration",
        "impact": (
            "An adversary stealing data from the network, potentially resulting in loss of sensitive information, intellectual property theft, regulatory compliance violations, and reputational damage."
        ),
    },
    "TA0011": {
        "name": "Command and Control",
        "impact": (
            "An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "TA0040": {
        "name": "Impact",
        "impact": (
            "An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "TA0042": {
        "name": "Resource Development",
        "impact": (
            "An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "TA0043": {
        "name": "Reconnaissance",
        "impact": (
            "An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
}

# ============================================================
# Technique Scenario Templates
# Usage: TECHNIQUE_SCENARIOS["T1190"]["description"].format(
#            cve_id="CVE-2024-1234", software_name="Apache HTTP Server")
# ============================================================
TECHNIQUE_SCENARIOS = {
    "T1001": {
        "name": "Data Obfuscation",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1001 (Data Obfuscation), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1001.001": {
        "name": "Junk Data",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1001.001 (Junk Data), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1001.002": {
        "name": "Steganography",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1001.002 (Steganography), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1001.003": {
        "name": "Protocol Impersonation",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1001.003 (Protocol Impersonation), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1003 (OS Credential Dumping), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1003.001": {
        "name": "LSASS Memory",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1003.001 (LSASS Memory), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1003.002": {
        "name": "Security Account Manager",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1003.002 (Security Account Manager), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1003.003": {
        "name": "NTDS",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1003.003 (NTDS), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1003.004": {
        "name": "LSA Secrets",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1003.004 (LSA Secrets), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1003.005": {
        "name": "Cached Domain Credentials",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1003.005 (Cached Domain Credentials), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1003.006": {
        "name": "DCSync",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1003.006 (DCSync), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1003.007": {
        "name": "Proc Filesystem",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1003.007 (Proc Filesystem), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1003.008": {
        "name": "/etc/passwd and /etc/shadow",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1003.008 (/etc/passwd and /etc/shadow), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1005": {
        "name": "Data from Local System",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1005 (Data from Local System), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1006": {
        "name": "Direct Volume Access",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1006 (Direct Volume Access), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1007": {
        "name": "System Service Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1007 (System Service Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1008": {
        "name": "Fallback Channels",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1008 (Fallback Channels), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1010": {
        "name": "Application Window Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1010 (Application Window Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1011": {
        "name": "Exfiltration Over Other Network Medium",
        "tactics": ['Exfiltration'],
        "tactic_ids": ['TA0010'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1011 (Exfiltration Over Other Network Medium), which falls under the following tactic "
            "category: Exfiltration. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Exfiltration: An adversary stealing data from the network, potentially resulting in loss of sensitive information, intellectual property theft, regulatory compliance violations, and reputational damage."
        ),
    },
    "T1011.001": {
        "name": "Exfiltration Over Bluetooth",
        "tactics": ['Exfiltration'],
        "tactic_ids": ['TA0010'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1011.001 (Exfiltration Over Bluetooth), which falls under the following tactic "
            "category: Exfiltration. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Exfiltration: An adversary stealing data from the network, potentially resulting in loss of sensitive information, intellectual property theft, regulatory compliance violations, and reputational damage."
        ),
    },
    "T1012": {
        "name": "Query Registry",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1012 (Query Registry), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1014": {
        "name": "Rootkit",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1014 (Rootkit), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1016": {
        "name": "System Network Configuration Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1016 (System Network Configuration Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1016.001": {
        "name": "Internet Connection Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1016.001 (Internet Connection Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1016.002": {
        "name": "Wi-Fi Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1016.002 (Wi-Fi Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1018": {
        "name": "Remote System Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1018 (Remote System Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1020": {
        "name": "Automated Exfiltration",
        "tactics": ['Exfiltration'],
        "tactic_ids": ['TA0010'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1020 (Automated Exfiltration), which falls under the following tactic "
            "category: Exfiltration. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Exfiltration: An adversary stealing data from the network, potentially resulting in loss of sensitive information, intellectual property theft, regulatory compliance violations, and reputational damage."
        ),
    },
    "T1020.001": {
        "name": "Traffic Duplication",
        "tactics": ['Exfiltration'],
        "tactic_ids": ['TA0010'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1020.001 (Traffic Duplication), which falls under the following tactic "
            "category: Exfiltration. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Exfiltration: An adversary stealing data from the network, potentially resulting in loss of sensitive information, intellectual property theft, regulatory compliance violations, and reputational damage."
        ),
    },
    "T1021": {
        "name": "Remote Services",
        "tactics": ['Lateral Movement'],
        "tactic_ids": ['TA0008'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1021 (Remote Services), which falls under the following tactic "
            "category: Lateral Movement. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Lateral Movement: An adversary moving through the network to reach additional systems, expanding the scope of compromise, accessing segmented resources, and potentially reaching high-value targets or critical infrastructure."
        ),
    },
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactics": ['Lateral Movement'],
        "tactic_ids": ['TA0008'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1021.001 (Remote Desktop Protocol), which falls under the following tactic "
            "category: Lateral Movement. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Lateral Movement: An adversary moving through the network to reach additional systems, expanding the scope of compromise, accessing segmented resources, and potentially reaching high-value targets or critical infrastructure."
        ),
    },
    "T1021.002": {
        "name": "SMB/Windows Admin Shares",
        "tactics": ['Lateral Movement'],
        "tactic_ids": ['TA0008'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1021.002 (SMB/Windows Admin Shares), which falls under the following tactic "
            "category: Lateral Movement. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Lateral Movement: An adversary moving through the network to reach additional systems, expanding the scope of compromise, accessing segmented resources, and potentially reaching high-value targets or critical infrastructure."
        ),
    },
    "T1021.003": {
        "name": "Distributed Component Object Model",
        "tactics": ['Lateral Movement'],
        "tactic_ids": ['TA0008'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1021.003 (Distributed Component Object Model), which falls under the following tactic "
            "category: Lateral Movement. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Lateral Movement: An adversary moving through the network to reach additional systems, expanding the scope of compromise, accessing segmented resources, and potentially reaching high-value targets or critical infrastructure."
        ),
    },
    "T1021.004": {
        "name": "SSH",
        "tactics": ['Lateral Movement'],
        "tactic_ids": ['TA0008'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1021.004 (SSH), which falls under the following tactic "
            "category: Lateral Movement. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Lateral Movement: An adversary moving through the network to reach additional systems, expanding the scope of compromise, accessing segmented resources, and potentially reaching high-value targets or critical infrastructure."
        ),
    },
    "T1021.005": {
        "name": "VNC",
        "tactics": ['Lateral Movement'],
        "tactic_ids": ['TA0008'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1021.005 (VNC), which falls under the following tactic "
            "category: Lateral Movement. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Lateral Movement: An adversary moving through the network to reach additional systems, expanding the scope of compromise, accessing segmented resources, and potentially reaching high-value targets or critical infrastructure."
        ),
    },
    "T1021.006": {
        "name": "Windows Remote Management",
        "tactics": ['Lateral Movement'],
        "tactic_ids": ['TA0008'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1021.006 (Windows Remote Management), which falls under the following tactic "
            "category: Lateral Movement. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Lateral Movement: An adversary moving through the network to reach additional systems, expanding the scope of compromise, accessing segmented resources, and potentially reaching high-value targets or critical infrastructure."
        ),
    },
    "T1021.007": {
        "name": "Cloud Services",
        "tactics": ['Lateral Movement'],
        "tactic_ids": ['TA0008'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1021.007 (Cloud Services), which falls under the following tactic "
            "category: Lateral Movement. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Lateral Movement: An adversary moving through the network to reach additional systems, expanding the scope of compromise, accessing segmented resources, and potentially reaching high-value targets or critical infrastructure."
        ),
    },
    "T1021.008": {
        "name": "Direct Cloud VM Connections",
        "tactics": ['Lateral Movement'],
        "tactic_ids": ['TA0008'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1021.008 (Direct Cloud VM Connections), which falls under the following tactic "
            "category: Lateral Movement. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Lateral Movement: An adversary moving through the network to reach additional systems, expanding the scope of compromise, accessing segmented resources, and potentially reaching high-value targets or critical infrastructure."
        ),
    },
    "T1025": {
        "name": "Data from Removable Media",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1025 (Data from Removable Media), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1027 (Obfuscated Files or Information), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1027.001": {
        "name": "Binary Padding",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1027.001 (Binary Padding), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1027.002": {
        "name": "Software Packing",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1027.002 (Software Packing), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1027.003": {
        "name": "Steganography",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1027.003 (Steganography), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1027.004": {
        "name": "Compile After Delivery",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1027.004 (Compile After Delivery), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1027.005": {
        "name": "Indicator Removal from Tools",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1027.005 (Indicator Removal from Tools), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1027.006": {
        "name": "HTML Smuggling",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1027.006 (HTML Smuggling), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1027.007": {
        "name": "Dynamic API Resolution",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1027.007 (Dynamic API Resolution), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1027.008": {
        "name": "Stripped Payloads",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1027.008 (Stripped Payloads), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1027.009": {
        "name": "Embedded Payloads",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1027.009 (Embedded Payloads), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1027.010": {
        "name": "Command Obfuscation",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1027.010 (Command Obfuscation), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1027.011": {
        "name": "Fileless Storage",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1027.011 (Fileless Storage), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1027.012": {
        "name": "LNK Icon Smuggling",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1027.012 (LNK Icon Smuggling), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1027.013": {
        "name": "Encrypted/Encoded File",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1027.013 (Encrypted/Encoded File), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1029": {
        "name": "Scheduled Transfer",
        "tactics": ['Exfiltration'],
        "tactic_ids": ['TA0010'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1029 (Scheduled Transfer), which falls under the following tactic "
            "category: Exfiltration. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Exfiltration: An adversary stealing data from the network, potentially resulting in loss of sensitive information, intellectual property theft, regulatory compliance violations, and reputational damage."
        ),
    },
    "T1030": {
        "name": "Data Transfer Size Limits",
        "tactics": ['Exfiltration'],
        "tactic_ids": ['TA0010'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1030 (Data Transfer Size Limits), which falls under the following tactic "
            "category: Exfiltration. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Exfiltration: An adversary stealing data from the network, potentially resulting in loss of sensitive information, intellectual property theft, regulatory compliance violations, and reputational damage."
        ),
    },
    "T1033": {
        "name": "System Owner/User Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1033 (System Owner/User Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1036": {
        "name": "Masquerading",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1036 (Masquerading), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1036.001": {
        "name": "Invalid Code Signature",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1036.001 (Invalid Code Signature), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1036.002": {
        "name": "Right-to-Left Override",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1036.002 (Right-to-Left Override), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1036.003": {
        "name": "Rename System Utilities",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1036.003 (Rename System Utilities), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1036.004": {
        "name": "Masquerade Task or Service",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1036.004 (Masquerade Task or Service), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1036.005": {
        "name": "Match Legitimate Name or Location",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1036.005 (Match Legitimate Name or Location), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1036.006": {
        "name": "Space after Filename",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1036.006 (Space after Filename), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1036.007": {
        "name": "Double File Extension",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1036.007 (Double File Extension), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1036.008": {
        "name": "Masquerade File Type",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1036.008 (Masquerade File Type), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1036.009": {
        "name": "Break Process Trees",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1036.009 (Break Process Trees), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1037": {
        "name": "Boot or Logon Initialization Scripts",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1037 (Boot or Logon Initialization Scripts), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1037.001": {
        "name": "Logon Script (Windows)",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1037.001 (Logon Script (Windows)), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1037.002": {
        "name": "Login Hook",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1037.002 (Login Hook), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1037.003": {
        "name": "Network Logon Script",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1037.003 (Network Logon Script), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1037.004": {
        "name": "RC Scripts",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1037.004 (RC Scripts), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1037.005": {
        "name": "Startup Items",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1037.005 (Startup Items), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1039": {
        "name": "Data from Network Shared Drive",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1039 (Data from Network Shared Drive), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1040": {
        "name": "Network Sniffing",
        "tactics": ['Credential Access', 'Discovery'],
        "tactic_ids": ['TA0006', 'TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1040 (Network Sniffing), which falls under the following tactic "
            "categories: Credential Access, Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactics": ['Exfiltration'],
        "tactic_ids": ['TA0010'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1041 (Exfiltration Over C2 Channel), which falls under the following tactic "
            "category: Exfiltration. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Exfiltration: An adversary stealing data from the network, potentially resulting in loss of sensitive information, intellectual property theft, regulatory compliance violations, and reputational damage."
        ),
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1046 (Network Service Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1047": {
        "name": "Windows Management Instrumentation",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1047 (Windows Management Instrumentation), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactics": ['Exfiltration'],
        "tactic_ids": ['TA0010'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1048 (Exfiltration Over Alternative Protocol), which falls under the following tactic "
            "category: Exfiltration. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Exfiltration: An adversary stealing data from the network, potentially resulting in loss of sensitive information, intellectual property theft, regulatory compliance violations, and reputational damage."
        ),
    },
    "T1048.001": {
        "name": "Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
        "tactics": ['Exfiltration'],
        "tactic_ids": ['TA0010'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1048.001 (Exfiltration Over Symmetric Encrypted Non-C2 Protocol), which falls under the following tactic "
            "category: Exfiltration. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Exfiltration: An adversary stealing data from the network, potentially resulting in loss of sensitive information, intellectual property theft, regulatory compliance violations, and reputational damage."
        ),
    },
    "T1048.002": {
        "name": "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
        "tactics": ['Exfiltration'],
        "tactic_ids": ['TA0010'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1048.002 (Exfiltration Over Asymmetric Encrypted Non-C2 Protocol), which falls under the following tactic "
            "category: Exfiltration. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Exfiltration: An adversary stealing data from the network, potentially resulting in loss of sensitive information, intellectual property theft, regulatory compliance violations, and reputational damage."
        ),
    },
    "T1048.003": {
        "name": "Exfiltration Over Unencrypted Non-C2 Protocol",
        "tactics": ['Exfiltration'],
        "tactic_ids": ['TA0010'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1048.003 (Exfiltration Over Unencrypted Non-C2 Protocol), which falls under the following tactic "
            "category: Exfiltration. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Exfiltration: An adversary stealing data from the network, potentially resulting in loss of sensitive information, intellectual property theft, regulatory compliance violations, and reputational damage."
        ),
    },
    "T1049": {
        "name": "System Network Connections Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1049 (System Network Connections Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1052": {
        "name": "Exfiltration Over Physical Medium",
        "tactics": ['Exfiltration'],
        "tactic_ids": ['TA0010'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1052 (Exfiltration Over Physical Medium), which falls under the following tactic "
            "category: Exfiltration. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Exfiltration: An adversary stealing data from the network, potentially resulting in loss of sensitive information, intellectual property theft, regulatory compliance violations, and reputational damage."
        ),
    },
    "T1052.001": {
        "name": "Exfiltration over USB",
        "tactics": ['Exfiltration'],
        "tactic_ids": ['TA0010'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1052.001 (Exfiltration over USB), which falls under the following tactic "
            "category: Exfiltration. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Exfiltration: An adversary stealing data from the network, potentially resulting in loss of sensitive information, intellectual property theft, regulatory compliance violations, and reputational damage."
        ),
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactics": ['Execution', 'Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0002', 'TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1053 (Scheduled Task/Job), which falls under the following tactic "
            "categories: Execution, Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1053.002": {
        "name": "At",
        "tactics": ['Execution', 'Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0002', 'TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1053.002 (At), which falls under the following tactic "
            "categories: Execution, Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1053.003": {
        "name": "Cron",
        "tactics": ['Execution', 'Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0002', 'TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1053.003 (Cron), which falls under the following tactic "
            "categories: Execution, Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "tactics": ['Execution', 'Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0002', 'TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1053.005 (Scheduled Task), which falls under the following tactic "
            "categories: Execution, Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1053.006": {
        "name": "Systemd Timers",
        "tactics": ['Execution', 'Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0002', 'TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1053.006 (Systemd Timers), which falls under the following tactic "
            "categories: Execution, Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1053.007": {
        "name": "Container Orchestration Job",
        "tactics": ['Execution', 'Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0002', 'TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1053.007 (Container Orchestration Job), which falls under the following tactic "
            "categories: Execution, Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1055": {
        "name": "Process Injection",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1055 (Process Injection), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1055.001": {
        "name": "Dynamic-link Library Injection",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1055.001 (Dynamic-link Library Injection), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1055.002": {
        "name": "Portable Executable Injection",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1055.002 (Portable Executable Injection), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1055.003": {
        "name": "Thread Execution Hijacking",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1055.003 (Thread Execution Hijacking), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1055.004": {
        "name": "Asynchronous Procedure Call",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1055.004 (Asynchronous Procedure Call), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1055.005": {
        "name": "Thread Local Storage",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1055.005 (Thread Local Storage), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1055.008": {
        "name": "Ptrace System Calls",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1055.008 (Ptrace System Calls), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1055.009": {
        "name": "Proc Memory",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1055.009 (Proc Memory), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1055.011": {
        "name": "Extra Window Memory Injection",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1055.011 (Extra Window Memory Injection), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1055.012": {
        "name": "Process Hollowing",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1055.012 (Process Hollowing), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1055.013": {
        "name": "Process Doppelganging",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1055.013 (Process Doppelganging), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1055.014": {
        "name": "VDSO Hijacking",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1055.014 (VDSO Hijacking), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1055.015": {
        "name": "ListPlanting",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1055.015 (ListPlanting), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1056": {
        "name": "Input Capture",
        "tactics": ['Credential Access', 'Collection'],
        "tactic_ids": ['TA0006', 'TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1056 (Input Capture), which falls under the following tactic "
            "categories: Credential Access, Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1056.001": {
        "name": "Keylogging",
        "tactics": ['Credential Access', 'Collection'],
        "tactic_ids": ['TA0006', 'TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1056.001 (Keylogging), which falls under the following tactic "
            "categories: Credential Access, Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1056.002": {
        "name": "GUI Input Capture",
        "tactics": ['Credential Access', 'Collection'],
        "tactic_ids": ['TA0006', 'TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1056.002 (GUI Input Capture), which falls under the following tactic "
            "categories: Credential Access, Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1056.003": {
        "name": "Web Portal Capture",
        "tactics": ['Credential Access', 'Collection'],
        "tactic_ids": ['TA0006', 'TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1056.003 (Web Portal Capture), which falls under the following tactic "
            "categories: Credential Access, Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1056.004": {
        "name": "Credential API Hooking",
        "tactics": ['Credential Access', 'Collection'],
        "tactic_ids": ['TA0006', 'TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1056.004 (Credential API Hooking), which falls under the following tactic "
            "categories: Credential Access, Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1057": {
        "name": "Process Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1057 (Process Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1059 (Command and Scripting Interpreter), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1059.001 (PowerShell), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1059.002": {
        "name": "AppleScript",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1059.002 (AppleScript), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1059.003 (Windows Command Shell), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1059.004": {
        "name": "Unix Shell",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1059.004 (Unix Shell), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1059.005": {
        "name": "Visual Basic",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1059.005 (Visual Basic), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1059.006": {
        "name": "Python",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1059.006 (Python), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1059.007": {
        "name": "JavaScript",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1059.007 (JavaScript), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1059.008": {
        "name": "Network Device CLI",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1059.008 (Network Device CLI), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1059.009": {
        "name": "Cloud API",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1059.009 (Cloud API), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1059.010": {
        "name": "AutoHotKey & AutoIT",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1059.010 (AutoHotKey & AutoIT), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactics": ['Privilege Escalation'],
        "tactic_ids": ['TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1068 (Exploitation for Privilege Escalation), which falls under the following tactic "
            "category: Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1069": {
        "name": "Permission Groups Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1069 (Permission Groups Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1069.001": {
        "name": "Local Groups",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1069.001 (Local Groups), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1069.002": {
        "name": "Domain Groups",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1069.002 (Domain Groups), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1069.003": {
        "name": "Cloud Groups",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1069.003 (Cloud Groups), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1070": {
        "name": "Indicator Removal",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1070 (Indicator Removal), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1070.001": {
        "name": "Clear Windows Event Logs",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1070.001 (Clear Windows Event Logs), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1070.002": {
        "name": "Clear Linux or Mac System Logs",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1070.002 (Clear Linux or Mac System Logs), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1070.003": {
        "name": "Clear Command History",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1070.003 (Clear Command History), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1070.004": {
        "name": "File Deletion",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1070.004 (File Deletion), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1070.005": {
        "name": "Network Share Connection Removal",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1070.005 (Network Share Connection Removal), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1070.006": {
        "name": "Timestomp",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1070.006 (Timestomp), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1070.007": {
        "name": "Clear Network Connection History and Configurations",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1070.007 (Clear Network Connection History and Configurations), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1070.008": {
        "name": "Clear Mailbox Data",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1070.008 (Clear Mailbox Data), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1070.009": {
        "name": "Clear Persistence",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1070.009 (Clear Persistence), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1071 (Application Layer Protocol), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1071.001": {
        "name": "Web Protocols",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1071.001 (Web Protocols), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1071.002": {
        "name": "File Transfer Protocols",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1071.002 (File Transfer Protocols), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1071.003": {
        "name": "Mail Protocols",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1071.003 (Mail Protocols), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1071.004": {
        "name": "DNS",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1071.004 (DNS), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1071.005": {
        "name": "Publish/Subscribe Protocols",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1071.005 (Publish/Subscribe Protocols), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1072": {
        "name": "Software Deployment Tools",
        "tactics": ['Execution', 'Lateral Movement'],
        "tactic_ids": ['TA0002', 'TA0008'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1072 (Software Deployment Tools), which falls under the following tactic "
            "categories: Execution, Lateral Movement. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
            "\n  - Lateral Movement: An adversary moving through the network to reach additional systems, expanding the scope of compromise, accessing segmented resources, and potentially reaching high-value targets or critical infrastructure."
        ),
    },
    "T1074": {
        "name": "Data Staged",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1074 (Data Staged), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1074.001": {
        "name": "Local Data Staging",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1074.001 (Local Data Staging), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1074.002": {
        "name": "Remote Data Staging",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1074.002 (Remote Data Staging), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactics": ['Initial Access', 'Persistence', 'Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0001', 'TA0003', 'TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1078 (Valid Accounts), which falls under the following tactic "
            "categories: Initial Access, Persistence, Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Initial Access: An adversary gaining an initial foothold within the network, which could lead to unauthorized entry into systems, data exposure, and serve as a launching point for deeper compromise."
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1078.001": {
        "name": "Default Accounts",
        "tactics": ['Initial Access', 'Persistence', 'Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0001', 'TA0003', 'TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1078.001 (Default Accounts), which falls under the following tactic "
            "categories: Initial Access, Persistence, Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Initial Access: An adversary gaining an initial foothold within the network, which could lead to unauthorized entry into systems, data exposure, and serve as a launching point for deeper compromise."
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1078.002": {
        "name": "Domain Accounts",
        "tactics": ['Initial Access', 'Persistence', 'Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0001', 'TA0003', 'TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1078.002 (Domain Accounts), which falls under the following tactic "
            "categories: Initial Access, Persistence, Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Initial Access: An adversary gaining an initial foothold within the network, which could lead to unauthorized entry into systems, data exposure, and serve as a launching point for deeper compromise."
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1078.003": {
        "name": "Local Accounts",
        "tactics": ['Initial Access', 'Persistence', 'Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0001', 'TA0003', 'TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1078.003 (Local Accounts), which falls under the following tactic "
            "categories: Initial Access, Persistence, Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Initial Access: An adversary gaining an initial foothold within the network, which could lead to unauthorized entry into systems, data exposure, and serve as a launching point for deeper compromise."
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1078.004": {
        "name": "Cloud Accounts",
        "tactics": ['Initial Access', 'Persistence', 'Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0001', 'TA0003', 'TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1078.004 (Cloud Accounts), which falls under the following tactic "
            "categories: Initial Access, Persistence, Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Initial Access: An adversary gaining an initial foothold within the network, which could lead to unauthorized entry into systems, data exposure, and serve as a launching point for deeper compromise."
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1080": {
        "name": "Taint Shared Content",
        "tactics": ['Lateral Movement'],
        "tactic_ids": ['TA0008'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1080 (Taint Shared Content), which falls under the following tactic "
            "category: Lateral Movement. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Lateral Movement: An adversary moving through the network to reach additional systems, expanding the scope of compromise, accessing segmented resources, and potentially reaching high-value targets or critical infrastructure."
        ),
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1082 (System Information Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1087": {
        "name": "Account Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1087 (Account Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1087.001": {
        "name": "Local Account",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1087.001 (Local Account), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1087.002": {
        "name": "Domain Account",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1087.002 (Domain Account), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1087.003": {
        "name": "Email Account",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1087.003 (Email Account), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1087.004": {
        "name": "Cloud Account",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1087.004 (Cloud Account), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1090": {
        "name": "Proxy",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1090 (Proxy), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1090.001": {
        "name": "Internal Proxy",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1090.001 (Internal Proxy), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1090.002": {
        "name": "External Proxy",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1090.002 (External Proxy), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1090.003": {
        "name": "Multi-hop Proxy",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1090.003 (Multi-hop Proxy), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1090.004": {
        "name": "Domain Fronting",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1090.004 (Domain Fronting), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1091": {
        "name": "Replication Through Removable Media",
        "tactics": ['Initial Access', 'Lateral Movement'],
        "tactic_ids": ['TA0001', 'TA0008'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1091 (Replication Through Removable Media), which falls under the following tactic "
            "categories: Initial Access, Lateral Movement. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Initial Access: An adversary gaining an initial foothold within the network, which could lead to unauthorized entry into systems, data exposure, and serve as a launching point for deeper compromise."
            "\n  - Lateral Movement: An adversary moving through the network to reach additional systems, expanding the scope of compromise, accessing segmented resources, and potentially reaching high-value targets or critical infrastructure."
        ),
    },
    "T1092": {
        "name": "Communication Through Removable Media",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1092 (Communication Through Removable Media), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1095": {
        "name": "Non-Application Layer Protocol",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1095 (Non-Application Layer Protocol), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1098 (Account Manipulation), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1098.001": {
        "name": "Additional Cloud Credentials",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1098.001 (Additional Cloud Credentials), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1098.002": {
        "name": "Additional Email Delegate Permissions",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1098.002 (Additional Email Delegate Permissions), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1098.003": {
        "name": "Additional Cloud Roles",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1098.003 (Additional Cloud Roles), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1098.004": {
        "name": "SSH Authorized Keys",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1098.004 (SSH Authorized Keys), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1098.005": {
        "name": "Device Registration",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1098.005 (Device Registration), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1098.006": {
        "name": "Additional Container Cluster Roles",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1098.006 (Additional Container Cluster Roles), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1098.007": {
        "name": "Additional Local or Domain Groups",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1098.007 (Additional Local or Domain Groups), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1102": {
        "name": "Web Service",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1102 (Web Service), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1102.001": {
        "name": "Dead Drop Resolver",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1102.001 (Dead Drop Resolver), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1102.002": {
        "name": "Bidirectional Communication",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1102.002 (Bidirectional Communication), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1102.003": {
        "name": "One-Way Communication",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1102.003 (One-Way Communication), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1104": {
        "name": "Multi-Stage Channels",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1104 (Multi-Stage Channels), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1105 (Ingress Tool Transfer), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1106": {
        "name": "Native API",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1106 (Native API), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1110": {
        "name": "Brute Force",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1110 (Brute Force), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1110.001": {
        "name": "Password Guessing",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1110.001 (Password Guessing), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1110.002": {
        "name": "Password Cracking",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1110.002 (Password Cracking), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1110.003": {
        "name": "Password Spraying",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1110.003 (Password Spraying), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1110.004": {
        "name": "Credential Stuffing",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1110.004 (Credential Stuffing), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1111": {
        "name": "Multi-Factor Authentication Interception",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1111 (Multi-Factor Authentication Interception), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1112": {
        "name": "Modify Registry",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1112 (Modify Registry), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1113": {
        "name": "Screen Capture",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1113 (Screen Capture), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1114": {
        "name": "Email Collection",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1114 (Email Collection), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1114.001": {
        "name": "Local Email Collection",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1114.001 (Local Email Collection), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1114.002": {
        "name": "Remote Email Collection",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1114.002 (Remote Email Collection), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1114.003": {
        "name": "Email Forwarding Rule",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1114.003 (Email Forwarding Rule), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1115": {
        "name": "Clipboard Data",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1115 (Clipboard Data), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1119": {
        "name": "Automated Collection",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1119 (Automated Collection), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1120": {
        "name": "Peripheral Device Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1120 (Peripheral Device Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1123": {
        "name": "Audio Capture",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1123 (Audio Capture), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1124": {
        "name": "System Time Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1124 (System Time Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1125": {
        "name": "Video Capture",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1125 (Video Capture), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1127": {
        "name": "Trusted Developer Utilities Proxy Execution",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1127 (Trusted Developer Utilities Proxy Execution), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1127.001": {
        "name": "MSBuild",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1127.001 (MSBuild), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1129": {
        "name": "Shared Modules",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1129 (Shared Modules), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1132": {
        "name": "Data Encoding",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1132 (Data Encoding), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1132.001": {
        "name": "Standard Encoding",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1132.001 (Standard Encoding), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1132.002": {
        "name": "Non-Standard Encoding",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1132.002 (Non-Standard Encoding), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1133": {
        "name": "External Remote Services",
        "tactics": ['Initial Access', 'Persistence'],
        "tactic_ids": ['TA0001', 'TA0003'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1133 (External Remote Services), which falls under the following tactic "
            "categories: Initial Access, Persistence. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Initial Access: An adversary gaining an initial foothold within the network, which could lead to unauthorized entry into systems, data exposure, and serve as a launching point for deeper compromise."
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
        ),
    },
    "T1134": {
        "name": "Access Token Manipulation",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1134 (Access Token Manipulation), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1134.001": {
        "name": "Token Impersonation/Theft",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1134.001 (Token Impersonation/Theft), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1134.002": {
        "name": "Create Process with Token",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1134.002 (Create Process with Token), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1134.003": {
        "name": "Make and Impersonate Token",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1134.003 (Make and Impersonate Token), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1134.004": {
        "name": "Parent PID Spoofing",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1134.004 (Parent PID Spoofing), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1134.005": {
        "name": "SID-History Injection",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1134.005 (SID-History Injection), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1135": {
        "name": "Network Share Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1135 (Network Share Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1136": {
        "name": "Create Account",
        "tactics": ['Persistence'],
        "tactic_ids": ['TA0003'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1136 (Create Account), which falls under the following tactic "
            "category: Persistence. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
        ),
    },
    "T1136.001": {
        "name": "Local Account",
        "tactics": ['Persistence'],
        "tactic_ids": ['TA0003'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1136.001 (Local Account), which falls under the following tactic "
            "category: Persistence. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
        ),
    },
    "T1136.002": {
        "name": "Domain Account",
        "tactics": ['Persistence'],
        "tactic_ids": ['TA0003'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1136.002 (Domain Account), which falls under the following tactic "
            "category: Persistence. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
        ),
    },
    "T1136.003": {
        "name": "Cloud Account",
        "tactics": ['Persistence'],
        "tactic_ids": ['TA0003'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1136.003 (Cloud Account), which falls under the following tactic "
            "category: Persistence. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
        ),
    },
    "T1137": {
        "name": "Office Application Startup",
        "tactics": ['Persistence'],
        "tactic_ids": ['TA0003'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1137 (Office Application Startup), which falls under the following tactic "
            "category: Persistence. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
        ),
    },
    "T1137.001": {
        "name": "Office Template Macros",
        "tactics": ['Persistence'],
        "tactic_ids": ['TA0003'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1137.001 (Office Template Macros), which falls under the following tactic "
            "category: Persistence. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
        ),
    },
    "T1137.002": {
        "name": "Office Test",
        "tactics": ['Persistence'],
        "tactic_ids": ['TA0003'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1137.002 (Office Test), which falls under the following tactic "
            "category: Persistence. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
        ),
    },
    "T1137.003": {
        "name": "Outlook Forms",
        "tactics": ['Persistence'],
        "tactic_ids": ['TA0003'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1137.003 (Outlook Forms), which falls under the following tactic "
            "category: Persistence. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
        ),
    },
    "T1137.004": {
        "name": "Outlook Home Page",
        "tactics": ['Persistence'],
        "tactic_ids": ['TA0003'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1137.004 (Outlook Home Page), which falls under the following tactic "
            "category: Persistence. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
        ),
    },
    "T1137.005": {
        "name": "Outlook Rules",
        "tactics": ['Persistence'],
        "tactic_ids": ['TA0003'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1137.005 (Outlook Rules), which falls under the following tactic "
            "category: Persistence. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
        ),
    },
    "T1137.006": {
        "name": "Add-ins",
        "tactics": ['Persistence'],
        "tactic_ids": ['TA0003'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1137.006 (Add-ins), which falls under the following tactic "
            "category: Persistence. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
        ),
    },
    "T1140": {
        "name": "Deobfuscate/Decode Files or Information",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1140 (Deobfuscate/Decode Files or Information), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1176": {
        "name": "Browser Extensions",
        "tactics": ['Persistence'],
        "tactic_ids": ['TA0003'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1176 (Browser Extensions), which falls under the following tactic "
            "category: Persistence. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
        ),
    },
    "T1185": {
        "name": "Browser Session Hijacking",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1185 (Browser Session Hijacking), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1187": {
        "name": "Forced Authentication",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1187 (Forced Authentication), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1189": {
        "name": "Drive-by Compromise",
        "tactics": ['Initial Access'],
        "tactic_ids": ['TA0001'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1189 (Drive-by Compromise), which falls under the following tactic "
            "category: Initial Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Initial Access: An adversary gaining an initial foothold within the network, which could lead to unauthorized entry into systems, data exposure, and serve as a launching point for deeper compromise."
        ),
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactics": ['Initial Access'],
        "tactic_ids": ['TA0001'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1190 (Exploit Public-Facing Application), which falls under the following tactic "
            "category: Initial Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Initial Access: An adversary gaining an initial foothold within the network, which could lead to unauthorized entry into systems, data exposure, and serve as a launching point for deeper compromise."
        ),
    },
    "T1195": {
        "name": "Supply Chain Compromise",
        "tactics": ['Initial Access'],
        "tactic_ids": ['TA0001'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1195 (Supply Chain Compromise), which falls under the following tactic "
            "category: Initial Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Initial Access: An adversary gaining an initial foothold within the network, which could lead to unauthorized entry into systems, data exposure, and serve as a launching point for deeper compromise."
        ),
    },
    "T1195.001": {
        "name": "Compromise Software Dependencies and Development Tools",
        "tactics": ['Initial Access'],
        "tactic_ids": ['TA0001'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1195.001 (Compromise Software Dependencies and Development Tools), which falls under the following tactic "
            "category: Initial Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Initial Access: An adversary gaining an initial foothold within the network, which could lead to unauthorized entry into systems, data exposure, and serve as a launching point for deeper compromise."
        ),
    },
    "T1195.002": {
        "name": "Compromise Software Supply Chain",
        "tactics": ['Initial Access'],
        "tactic_ids": ['TA0001'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1195.002 (Compromise Software Supply Chain), which falls under the following tactic "
            "category: Initial Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Initial Access: An adversary gaining an initial foothold within the network, which could lead to unauthorized entry into systems, data exposure, and serve as a launching point for deeper compromise."
        ),
    },
    "T1195.003": {
        "name": "Compromise Hardware Supply Chain",
        "tactics": ['Initial Access'],
        "tactic_ids": ['TA0001'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1195.003 (Compromise Hardware Supply Chain), which falls under the following tactic "
            "category: Initial Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Initial Access: An adversary gaining an initial foothold within the network, which could lead to unauthorized entry into systems, data exposure, and serve as a launching point for deeper compromise."
        ),
    },
    "T1197": {
        "name": "BITS Jobs",
        "tactics": ['Persistence', 'Defense Evasion'],
        "tactic_ids": ['TA0003', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1197 (BITS Jobs), which falls under the following tactic "
            "categories: Persistence, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1199": {
        "name": "Trusted Relationship",
        "tactics": ['Initial Access'],
        "tactic_ids": ['TA0001'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1199 (Trusted Relationship), which falls under the following tactic "
            "category: Initial Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Initial Access: An adversary gaining an initial foothold within the network, which could lead to unauthorized entry into systems, data exposure, and serve as a launching point for deeper compromise."
        ),
    },
    "T1200": {
        "name": "Hardware Additions",
        "tactics": ['Initial Access'],
        "tactic_ids": ['TA0001'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1200 (Hardware Additions), which falls under the following tactic "
            "category: Initial Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Initial Access: An adversary gaining an initial foothold within the network, which could lead to unauthorized entry into systems, data exposure, and serve as a launching point for deeper compromise."
        ),
    },
    "T1201": {
        "name": "Password Policy Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1201 (Password Policy Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1202": {
        "name": "Indirect Command Execution",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1202 (Indirect Command Execution), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1203": {
        "name": "Exploitation for Client Execution",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1203 (Exploitation for Client Execution), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1204": {
        "name": "User Execution",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1204 (User Execution), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1204.001": {
        "name": "Malicious Link",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1204.001 (Malicious Link), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1204.002": {
        "name": "Malicious File",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1204.002 (Malicious File), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1204.003": {
        "name": "Malicious Image",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1204.003 (Malicious Image), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1205": {
        "name": "Traffic Signaling",
        "tactics": ['Persistence', 'Defense Evasion'],
        "tactic_ids": ['TA0003', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1205 (Traffic Signaling), which falls under the following tactic "
            "categories: Persistence, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1205.001": {
        "name": "Port Knocking",
        "tactics": ['Persistence', 'Defense Evasion'],
        "tactic_ids": ['TA0003', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1205.001 (Port Knocking), which falls under the following tactic "
            "categories: Persistence, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1205.002": {
        "name": "Socket Filters",
        "tactics": ['Persistence', 'Defense Evasion'],
        "tactic_ids": ['TA0003', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1205.002 (Socket Filters), which falls under the following tactic "
            "categories: Persistence, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1207": {
        "name": "Rogue Domain Controller",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1207 (Rogue Domain Controller), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1210": {
        "name": "Exploitation of Remote Services",
        "tactics": ['Lateral Movement'],
        "tactic_ids": ['TA0008'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1210 (Exploitation of Remote Services), which falls under the following tactic "
            "category: Lateral Movement. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Lateral Movement: An adversary moving through the network to reach additional systems, expanding the scope of compromise, accessing segmented resources, and potentially reaching high-value targets or critical infrastructure."
        ),
    },
    "T1211": {
        "name": "Exploitation for Defense Evasion",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1211 (Exploitation for Defense Evasion), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1212": {
        "name": "Exploitation for Credential Access",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1212 (Exploitation for Credential Access), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1213": {
        "name": "Data from Information Repositories",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1213 (Data from Information Repositories), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1213.001": {
        "name": "Confluence",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1213.001 (Confluence), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1213.002": {
        "name": "Sharepoint",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1213.002 (Sharepoint), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1213.003": {
        "name": "Code Repositories",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1213.003 (Code Repositories), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1213.004": {
        "name": "Customer Relationship Management Software",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1213.004 (Customer Relationship Management Software), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1216": {
        "name": "System Script Proxy Execution",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1216 (System Script Proxy Execution), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1216.001": {
        "name": "PubPrn",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1216.001 (PubPrn), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1217": {
        "name": "Browser Information Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1217 (Browser Information Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1218": {
        "name": "System Binary Proxy Execution",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1218 (System Binary Proxy Execution), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1218.001": {
        "name": "Compiled HTML File",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1218.001 (Compiled HTML File), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1218.002": {
        "name": "Control Panel",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1218.002 (Control Panel), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1218.003": {
        "name": "CMSTP",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1218.003 (CMSTP), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1218.004": {
        "name": "InstallUtil",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1218.004 (InstallUtil), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1218.005": {
        "name": "Mshta",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1218.005 (Mshta), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1218.007": {
        "name": "Msiexec",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1218.007 (Msiexec), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1218.008": {
        "name": "Odbcconf",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1218.008 (Odbcconf), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1218.009": {
        "name": "Regsvcs/Regasm",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1218.009 (Regsvcs/Regasm), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1218.010": {
        "name": "Regsvr32",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1218.010 (Regsvr32), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1218.011": {
        "name": "Rundll32",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1218.011 (Rundll32), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1218.012": {
        "name": "Verclsid",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1218.012 (Verclsid), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1218.013": {
        "name": "Mavinject",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1218.013 (Mavinject), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1218.014": {
        "name": "MMC",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1218.014 (MMC), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1218.015": {
        "name": "Electron Applications",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1218.015 (Electron Applications), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1219": {
        "name": "Remote Access Software",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1219 (Remote Access Software), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1220": {
        "name": "XSL Script Processing",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1220 (XSL Script Processing), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1221": {
        "name": "Template Injection",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1221 (Template Injection), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1222": {
        "name": "File and Directory Permissions Modification",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1222 (File and Directory Permissions Modification), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1222.001": {
        "name": "Windows File and Directory Permissions Modification",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1222.001 (Windows File and Directory Permissions Modification), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1222.002": {
        "name": "Linux and Mac File and Directory Permissions Modification",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1222.002 (Linux and Mac File and Directory Permissions Modification), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1480": {
        "name": "Execution Guardrails",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1480 (Execution Guardrails), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1480.001": {
        "name": "Environmental Keying",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1480.001 (Environmental Keying), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1480.002": {
        "name": "Mutual Exclusion",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1480.002 (Mutual Exclusion), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1482": {
        "name": "Domain Trust Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1482 (Domain Trust Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1485": {
        "name": "Data Destruction",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1485 (Data Destruction), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1486 (Data Encrypted for Impact), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1490 (Inhibit System Recovery), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1491": {
        "name": "Defacement",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1491 (Defacement), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1491.001": {
        "name": "Internal Defacement",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1491.001 (Internal Defacement), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1491.002": {
        "name": "External Defacement",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1491.002 (External Defacement), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1495": {
        "name": "Firmware Corruption",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1495 (Firmware Corruption), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1496": {
        "name": "Resource Hijacking",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1496 (Resource Hijacking), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1496.001": {
        "name": "Compute Hijacking",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1496.001 (Compute Hijacking), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1496.002": {
        "name": "Bandwidth Hijacking",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1496.002 (Bandwidth Hijacking), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1497": {
        "name": "Virtualization/Sandbox Evasion",
        "tactics": ['Defense Evasion', 'Discovery'],
        "tactic_ids": ['TA0005', 'TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1497 (Virtualization/Sandbox Evasion), which falls under the following tactic "
            "categories: Defense Evasion, Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1497.001": {
        "name": "System Checks",
        "tactics": ['Defense Evasion', 'Discovery'],
        "tactic_ids": ['TA0005', 'TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1497.001 (System Checks), which falls under the following tactic "
            "categories: Defense Evasion, Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1497.002": {
        "name": "User Activity Based Checks",
        "tactics": ['Defense Evasion', 'Discovery'],
        "tactic_ids": ['TA0005', 'TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1497.002 (User Activity Based Checks), which falls under the following tactic "
            "categories: Defense Evasion, Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1497.003": {
        "name": "Time Based Evasion",
        "tactics": ['Defense Evasion', 'Discovery'],
        "tactic_ids": ['TA0005', 'TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1497.003 (Time Based Evasion), which falls under the following tactic "
            "categories: Defense Evasion, Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1498": {
        "name": "Network Denial of Service",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1498 (Network Denial of Service), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1498.001": {
        "name": "Direct Network Flood",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1498.001 (Direct Network Flood), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1498.002": {
        "name": "Reflection Amplification",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1498.002 (Reflection Amplification), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1499": {
        "name": "Endpoint Denial of Service",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1499 (Endpoint Denial of Service), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1499.001": {
        "name": "OS Exhaustion Flood",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1499.001 (OS Exhaustion Flood), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1499.002": {
        "name": "Service Exhaustion Flood",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1499.002 (Service Exhaustion Flood), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1499.003": {
        "name": "Application Exhaustion Flood",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1499.003 (Application Exhaustion Flood), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1499.004": {
        "name": "Application or System Exploitation",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1499.004 (Application or System Exploitation), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1505": {
        "name": "Server Software Component",
        "tactics": ['Persistence'],
        "tactic_ids": ['TA0003'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1505 (Server Software Component), which falls under the following tactic "
            "category: Persistence. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
        ),
    },
    "T1505.001": {
        "name": "SQL Stored Procedures",
        "tactics": ['Persistence'],
        "tactic_ids": ['TA0003'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1505.001 (SQL Stored Procedures), which falls under the following tactic "
            "category: Persistence. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
        ),
    },
    "T1505.002": {
        "name": "Transport Agent",
        "tactics": ['Persistence'],
        "tactic_ids": ['TA0003'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1505.002 (Transport Agent), which falls under the following tactic "
            "category: Persistence. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
        ),
    },
    "T1505.003": {
        "name": "Web Shell",
        "tactics": ['Persistence'],
        "tactic_ids": ['TA0003'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1505.003 (Web Shell), which falls under the following tactic "
            "category: Persistence. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
        ),
    },
    "T1505.004": {
        "name": "IIS Components",
        "tactics": ['Persistence'],
        "tactic_ids": ['TA0003'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1505.004 (IIS Components), which falls under the following tactic "
            "category: Persistence. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
        ),
    },
    "T1505.005": {
        "name": "Terminal Services DLL",
        "tactics": ['Persistence'],
        "tactic_ids": ['TA0003'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1505.005 (Terminal Services DLL), which falls under the following tactic "
            "category: Persistence. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
        ),
    },
    "T1518": {
        "name": "Software Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1518 (Software Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1518.001": {
        "name": "Security Software Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1518.001 (Security Software Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1525": {
        "name": "Implant Internal Image",
        "tactics": ['Persistence'],
        "tactic_ids": ['TA0003'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1525 (Implant Internal Image), which falls under the following tactic "
            "category: Persistence. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
        ),
    },
    "T1526": {
        "name": "Cloud Service Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1526 (Cloud Service Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1528": {
        "name": "Steal Application Access Token",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1528 (Steal Application Access Token), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1529": {
        "name": "System Shutdown/Reboot",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1529 (System Shutdown/Reboot), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1530": {
        "name": "Data from Cloud Storage",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1530 (Data from Cloud Storage), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1531": {
        "name": "Account Access Removal",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1531 (Account Access Removal), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1534": {
        "name": "Internal Spearphishing",
        "tactics": ['Lateral Movement'],
        "tactic_ids": ['TA0008'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1534 (Internal Spearphishing), which falls under the following tactic "
            "category: Lateral Movement. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Lateral Movement: An adversary moving through the network to reach additional systems, expanding the scope of compromise, accessing segmented resources, and potentially reaching high-value targets or critical infrastructure."
        ),
    },
    "T1535": {
        "name": "Unused/Unsupported Cloud Regions",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1535 (Unused/Unsupported Cloud Regions), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1537": {
        "name": "Transfer Data to Cloud Account",
        "tactics": ['Exfiltration'],
        "tactic_ids": ['TA0010'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1537 (Transfer Data to Cloud Account), which falls under the following tactic "
            "category: Exfiltration. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Exfiltration: An adversary stealing data from the network, potentially resulting in loss of sensitive information, intellectual property theft, regulatory compliance violations, and reputational damage."
        ),
    },
    "T1538": {
        "name": "Cloud Service Dashboard",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1538 (Cloud Service Dashboard), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1539": {
        "name": "Steal Web Session Cookie",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1539 (Steal Web Session Cookie), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1542": {
        "name": "Pre-OS Boot",
        "tactics": ['Persistence', 'Defense Evasion'],
        "tactic_ids": ['TA0003', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1542 (Pre-OS Boot), which falls under the following tactic "
            "categories: Persistence, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1542.001": {
        "name": "System Firmware",
        "tactics": ['Persistence', 'Defense Evasion'],
        "tactic_ids": ['TA0003', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1542.001 (System Firmware), which falls under the following tactic "
            "categories: Persistence, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1542.002": {
        "name": "Component Firmware",
        "tactics": ['Persistence', 'Defense Evasion'],
        "tactic_ids": ['TA0003', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1542.002 (Component Firmware), which falls under the following tactic "
            "categories: Persistence, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1542.003": {
        "name": "Bootkit",
        "tactics": ['Persistence', 'Defense Evasion'],
        "tactic_ids": ['TA0003', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1542.003 (Bootkit), which falls under the following tactic "
            "categories: Persistence, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1542.004": {
        "name": "ROMMONkit",
        "tactics": ['Persistence', 'Defense Evasion'],
        "tactic_ids": ['TA0003', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1542.004 (ROMMONkit), which falls under the following tactic "
            "categories: Persistence, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1542.005": {
        "name": "TFTP Boot",
        "tactics": ['Persistence', 'Defense Evasion'],
        "tactic_ids": ['TA0003', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1542.005 (TFTP Boot), which falls under the following tactic "
            "categories: Persistence, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1543": {
        "name": "Create or Modify System Process",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1543 (Create or Modify System Process), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1543.001": {
        "name": "Launch Agent",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1543.001 (Launch Agent), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1543.002": {
        "name": "Systemd Service",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1543.002 (Systemd Service), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1543.003": {
        "name": "Windows Service",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1543.003 (Windows Service), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1543.004": {
        "name": "Launch Daemon",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1543.004 (Launch Daemon), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1543.005": {
        "name": "Container Service",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1543.005 (Container Service), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1546": {
        "name": "Event Triggered Execution",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1546 (Event Triggered Execution), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1546.001": {
        "name": "Change Default File Association",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1546.001 (Change Default File Association), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1546.002": {
        "name": "Screensaver",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1546.002 (Screensaver), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1546.003": {
        "name": "Windows Management Instrumentation Event Subscription",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1546.003 (Windows Management Instrumentation Event Subscription), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1546.004": {
        "name": "Unix Shell Configuration Modification",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1546.004 (Unix Shell Configuration Modification), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1546.005": {
        "name": "Trap",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1546.005 (Trap), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1546.006": {
        "name": "LC_LOAD_DYLIB Addition",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1546.006 (LC_LOAD_DYLIB Addition), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1546.007": {
        "name": "Netsh Helper DLL",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1546.007 (Netsh Helper DLL), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1546.008": {
        "name": "Accessibility Features",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1546.008 (Accessibility Features), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1546.009": {
        "name": "AppCert DLLs",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1546.009 (AppCert DLLs), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1546.010": {
        "name": "AppInit DLLs",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1546.010 (AppInit DLLs), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1546.011": {
        "name": "Application Shimming",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1546.011 (Application Shimming), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1546.012": {
        "name": "Image File Execution Options Injection",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1546.012 (Image File Execution Options Injection), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1546.013": {
        "name": "PowerShell Profile",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1546.013 (PowerShell Profile), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1546.014": {
        "name": "Emond",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1546.014 (Emond), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1546.015": {
        "name": "Component Object Model Hijacking",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1546.015 (Component Object Model Hijacking), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1546.016": {
        "name": "Installer Packages",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1546.016 (Installer Packages), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1546.017": {
        "name": "Udev Rules",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1546.017 (Udev Rules), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1547 (Boot or Logon Autostart Execution), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1547.001": {
        "name": "Registry Run Keys / Startup Folder",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1547.001 (Registry Run Keys / Startup Folder), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1547.002": {
        "name": "Authentication Package",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1547.002 (Authentication Package), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1547.003": {
        "name": "Time Providers",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1547.003 (Time Providers), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1547.004": {
        "name": "Winlogon Helper DLL",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1547.004 (Winlogon Helper DLL), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1547.005": {
        "name": "Security Support Provider",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1547.005 (Security Support Provider), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1547.006": {
        "name": "Kernel Modules and Extensions",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1547.006 (Kernel Modules and Extensions), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1547.007": {
        "name": "Re-opened Applications",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1547.007 (Re-opened Applications), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1547.008": {
        "name": "LSASS Driver",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1547.008 (LSASS Driver), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1547.009": {
        "name": "Shortcut Modification",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1547.009 (Shortcut Modification), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1547.010": {
        "name": "Port Monitors",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1547.010 (Port Monitors), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1547.012": {
        "name": "Print Processors",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1547.012 (Print Processors), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1547.013": {
        "name": "XDG Autostart Entries",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1547.013 (XDG Autostart Entries), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1547.014": {
        "name": "Active Setup",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1547.014 (Active Setup), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1547.015": {
        "name": "Login Items",
        "tactics": ['Persistence', 'Privilege Escalation'],
        "tactic_ids": ['TA0003', 'TA0004'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1547.015 (Login Items), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
        ),
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1548 (Abuse Elevation Control Mechanism), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1548.001": {
        "name": "Setuid and Setgid",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1548.001 (Setuid and Setgid), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1548.002": {
        "name": "Bypass User Account Control",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1548.002 (Bypass User Account Control), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1548.003": {
        "name": "Sudo and Sudo Caching",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1548.003 (Sudo and Sudo Caching), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1548.004": {
        "name": "Elevated Execution with Prompt",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1548.004 (Elevated Execution with Prompt), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1548.005": {
        "name": "Temporary Elevated Cloud Access",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1548.005 (Temporary Elevated Cloud Access), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1548.006": {
        "name": "TCC Manipulation",
        "tactics": ['Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1548.006 (TCC Manipulation), which falls under the following tactic "
            "categories: Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1550": {
        "name": "Use Alternate Authentication Material",
        "tactics": ['Defense Evasion', 'Lateral Movement'],
        "tactic_ids": ['TA0005', 'TA0008'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1550 (Use Alternate Authentication Material), which falls under the following tactic "
            "categories: Defense Evasion, Lateral Movement. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
            "\n  - Lateral Movement: An adversary moving through the network to reach additional systems, expanding the scope of compromise, accessing segmented resources, and potentially reaching high-value targets or critical infrastructure."
        ),
    },
    "T1550.001": {
        "name": "Application Access Token",
        "tactics": ['Defense Evasion', 'Lateral Movement'],
        "tactic_ids": ['TA0005', 'TA0008'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1550.001 (Application Access Token), which falls under the following tactic "
            "categories: Defense Evasion, Lateral Movement. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
            "\n  - Lateral Movement: An adversary moving through the network to reach additional systems, expanding the scope of compromise, accessing segmented resources, and potentially reaching high-value targets or critical infrastructure."
        ),
    },
    "T1550.002": {
        "name": "Pass the Hash",
        "tactics": ['Defense Evasion', 'Lateral Movement'],
        "tactic_ids": ['TA0005', 'TA0008'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1550.002 (Pass the Hash), which falls under the following tactic "
            "categories: Defense Evasion, Lateral Movement. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
            "\n  - Lateral Movement: An adversary moving through the network to reach additional systems, expanding the scope of compromise, accessing segmented resources, and potentially reaching high-value targets or critical infrastructure."
        ),
    },
    "T1550.003": {
        "name": "Pass the Ticket",
        "tactics": ['Defense Evasion', 'Lateral Movement'],
        "tactic_ids": ['TA0005', 'TA0008'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1550.003 (Pass the Ticket), which falls under the following tactic "
            "categories: Defense Evasion, Lateral Movement. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
            "\n  - Lateral Movement: An adversary moving through the network to reach additional systems, expanding the scope of compromise, accessing segmented resources, and potentially reaching high-value targets or critical infrastructure."
        ),
    },
    "T1550.004": {
        "name": "Web Session Cookie",
        "tactics": ['Defense Evasion', 'Lateral Movement'],
        "tactic_ids": ['TA0005', 'TA0008'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1550.004 (Web Session Cookie), which falls under the following tactic "
            "categories: Defense Evasion, Lateral Movement. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
            "\n  - Lateral Movement: An adversary moving through the network to reach additional systems, expanding the scope of compromise, accessing segmented resources, and potentially reaching high-value targets or critical infrastructure."
        ),
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1552 (Unsecured Credentials), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1552.001": {
        "name": "Credentials In Files",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1552.001 (Credentials In Files), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1552.002": {
        "name": "Credentials in Registry",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1552.002 (Credentials in Registry), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1552.003": {
        "name": "Bash History",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1552.003 (Bash History), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1552.004": {
        "name": "Private Keys",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1552.004 (Private Keys), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1552.005": {
        "name": "Cloud Instance Metadata API",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1552.005 (Cloud Instance Metadata API), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1552.006": {
        "name": "Group Policy Preferences",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1552.006 (Group Policy Preferences), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1552.007": {
        "name": "Container API",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1552.007 (Container API), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1552.008": {
        "name": "Chat Messages",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1552.008 (Chat Messages), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1553": {
        "name": "Subvert Trust Controls",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1553 (Subvert Trust Controls), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1553.001": {
        "name": "Gatekeeper Bypass",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1553.001 (Gatekeeper Bypass), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1553.002": {
        "name": "Code Signing",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1553.002 (Code Signing), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1553.003": {
        "name": "SIP and Trust Provider Hijacking",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1553.003 (SIP and Trust Provider Hijacking), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1553.004": {
        "name": "Install Root Certificate",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1553.004 (Install Root Certificate), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1553.005": {
        "name": "Mark-of-the-Web Bypass",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1553.005 (Mark-of-the-Web Bypass), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1553.006": {
        "name": "Code Signing Policy Modification",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1553.006 (Code Signing Policy Modification), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1554": {
        "name": "Compromise Host Software Binary",
        "tactics": ['Persistence'],
        "tactic_ids": ['TA0003'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1554 (Compromise Host Software Binary), which falls under the following tactic "
            "category: Persistence. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
        ),
    },
    "T1555": {
        "name": "Credentials from Password Stores",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1555 (Credentials from Password Stores), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1555.001": {
        "name": "Keychain",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1555.001 (Keychain), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1555.002": {
        "name": "Securityd Memory",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1555.002 (Securityd Memory), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1555.003": {
        "name": "Credentials from Web Browsers",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1555.003 (Credentials from Web Browsers), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1555.004": {
        "name": "Windows Credential Manager",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1555.004 (Windows Credential Manager), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1555.005": {
        "name": "Password Managers",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1555.005 (Password Managers), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1555.006": {
        "name": "Cloud Secrets Management Stores",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1555.006 (Cloud Secrets Management Stores), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1556": {
        "name": "Modify Authentication Process",
        "tactics": ['Persistence', 'Defense Evasion', 'Credential Access'],
        "tactic_ids": ['TA0003', 'TA0005', 'TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1556 (Modify Authentication Process), which falls under the following tactic "
            "categories: Persistence, Defense Evasion, Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1556.001": {
        "name": "Domain Controller Authentication",
        "tactics": ['Persistence', 'Defense Evasion', 'Credential Access'],
        "tactic_ids": ['TA0003', 'TA0005', 'TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1556.001 (Domain Controller Authentication), which falls under the following tactic "
            "categories: Persistence, Defense Evasion, Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1556.002": {
        "name": "Password Filter DLL",
        "tactics": ['Persistence', 'Defense Evasion', 'Credential Access'],
        "tactic_ids": ['TA0003', 'TA0005', 'TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1556.002 (Password Filter DLL), which falls under the following tactic "
            "categories: Persistence, Defense Evasion, Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1556.003": {
        "name": "Pluggable Authentication Modules",
        "tactics": ['Persistence', 'Defense Evasion', 'Credential Access'],
        "tactic_ids": ['TA0003', 'TA0005', 'TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1556.003 (Pluggable Authentication Modules), which falls under the following tactic "
            "categories: Persistence, Defense Evasion, Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1556.004": {
        "name": "Network Device Authentication",
        "tactics": ['Persistence', 'Defense Evasion', 'Credential Access'],
        "tactic_ids": ['TA0003', 'TA0005', 'TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1556.004 (Network Device Authentication), which falls under the following tactic "
            "categories: Persistence, Defense Evasion, Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1556.005": {
        "name": "Reversible Encryption",
        "tactics": ['Persistence', 'Defense Evasion', 'Credential Access'],
        "tactic_ids": ['TA0003', 'TA0005', 'TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1556.005 (Reversible Encryption), which falls under the following tactic "
            "categories: Persistence, Defense Evasion, Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1556.006": {
        "name": "Multi-Factor Authentication",
        "tactics": ['Persistence', 'Defense Evasion', 'Credential Access'],
        "tactic_ids": ['TA0003', 'TA0005', 'TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1556.006 (Multi-Factor Authentication), which falls under the following tactic "
            "categories: Persistence, Defense Evasion, Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1556.007": {
        "name": "Hybrid Identity",
        "tactics": ['Persistence', 'Defense Evasion', 'Credential Access'],
        "tactic_ids": ['TA0003', 'TA0005', 'TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1556.007 (Hybrid Identity), which falls under the following tactic "
            "categories: Persistence, Defense Evasion, Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1556.008": {
        "name": "Network Provider DLL",
        "tactics": ['Persistence', 'Defense Evasion', 'Credential Access'],
        "tactic_ids": ['TA0003', 'TA0005', 'TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1556.008 (Network Provider DLL), which falls under the following tactic "
            "categories: Persistence, Defense Evasion, Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1556.009": {
        "name": "Conditional Access Policies",
        "tactics": ['Persistence', 'Defense Evasion', 'Credential Access'],
        "tactic_ids": ['TA0003', 'TA0005', 'TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1556.009 (Conditional Access Policies), which falls under the following tactic "
            "categories: Persistence, Defense Evasion, Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1557": {
        "name": "Adversary-in-the-Middle",
        "tactics": ['Credential Access', 'Collection'],
        "tactic_ids": ['TA0006', 'TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1557 (Adversary-in-the-Middle), which falls under the following tactic "
            "categories: Credential Access, Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1557.001": {
        "name": "LLMNR/NBT-NS Poisoning and SMB Relay",
        "tactics": ['Credential Access', 'Collection'],
        "tactic_ids": ['TA0006', 'TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay), which falls under the following tactic "
            "categories: Credential Access, Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1557.002": {
        "name": "ARP Cache Poisoning",
        "tactics": ['Credential Access', 'Collection'],
        "tactic_ids": ['TA0006', 'TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1557.002 (ARP Cache Poisoning), which falls under the following tactic "
            "categories: Credential Access, Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1557.003": {
        "name": "DHCP Spoofing",
        "tactics": ['Credential Access', 'Collection'],
        "tactic_ids": ['TA0006', 'TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1557.003 (DHCP Spoofing), which falls under the following tactic "
            "categories: Credential Access, Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1557.004": {
        "name": "Evil Twin",
        "tactics": ['Credential Access', 'Collection'],
        "tactic_ids": ['TA0006', 'TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1557.004 (Evil Twin), which falls under the following tactic "
            "categories: Credential Access, Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1558": {
        "name": "Steal or Forge Kerberos Tickets",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1558 (Steal or Forge Kerberos Tickets), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1558.001": {
        "name": "Golden Ticket",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1558.001 (Golden Ticket), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1558.002": {
        "name": "Silver Ticket",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1558.002 (Silver Ticket), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1558.003": {
        "name": "Kerberoasting",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1558.003 (Kerberoasting), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1558.004": {
        "name": "AS-REP Roasting",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1558.004 (AS-REP Roasting), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1559": {
        "name": "Inter-Process Communication",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1559 (Inter-Process Communication), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1559.001": {
        "name": "Component Object Model",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1559.001 (Component Object Model), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1559.002": {
        "name": "Dynamic Data Exchange",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1559.002 (Dynamic Data Exchange), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1559.003": {
        "name": "XPC Services",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1559.003 (XPC Services), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1560": {
        "name": "Archive Collected Data",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1560 (Archive Collected Data), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1560.001": {
        "name": "Archive via Utility",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1560.001 (Archive via Utility), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1560.002": {
        "name": "Archive via Library",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1560.002 (Archive via Library), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1560.003": {
        "name": "Archive via Custom Method",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1560.003 (Archive via Custom Method), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1561": {
        "name": "Disk Wipe",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1561 (Disk Wipe), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1561.001": {
        "name": "Disk Content Wipe",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1561.001 (Disk Content Wipe), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1561.002": {
        "name": "Disk Structure Wipe",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1561.002 (Disk Structure Wipe), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1562 (Impair Defenses), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1562.001": {
        "name": "Disable or Modify Tools",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1562.001 (Disable or Modify Tools), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1562.002": {
        "name": "Disable Windows Event Logging",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1562.002 (Disable Windows Event Logging), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1562.003": {
        "name": "Impair Command History Logging",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1562.003 (Impair Command History Logging), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1562.004": {
        "name": "Disable or Modify System Firewall",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1562.004 (Disable or Modify System Firewall), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1562.006": {
        "name": "Indicator Blocking",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1562.006 (Indicator Blocking), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1562.007": {
        "name": "Disable or Modify Cloud Firewall",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1562.007 (Disable or Modify Cloud Firewall), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1562.008": {
        "name": "Disable or Modify Cloud Logs",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1562.008 (Disable or Modify Cloud Logs), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1562.009": {
        "name": "Safe Mode Boot",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1562.009 (Safe Mode Boot), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1562.010": {
        "name": "Downgrade Attack",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1562.010 (Downgrade Attack), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1562.011": {
        "name": "Spoof Security Alerting",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1562.011 (Spoof Security Alerting), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1562.012": {
        "name": "Disable or Modify Linux Audit System",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1562.012 (Disable or Modify Linux Audit System), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1563": {
        "name": "Remote Service Session Hijacking",
        "tactics": ['Lateral Movement'],
        "tactic_ids": ['TA0008'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1563 (Remote Service Session Hijacking), which falls under the following tactic "
            "category: Lateral Movement. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Lateral Movement: An adversary moving through the network to reach additional systems, expanding the scope of compromise, accessing segmented resources, and potentially reaching high-value targets or critical infrastructure."
        ),
    },
    "T1563.001": {
        "name": "SSH Hijacking",
        "tactics": ['Lateral Movement'],
        "tactic_ids": ['TA0008'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1563.001 (SSH Hijacking), which falls under the following tactic "
            "category: Lateral Movement. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Lateral Movement: An adversary moving through the network to reach additional systems, expanding the scope of compromise, accessing segmented resources, and potentially reaching high-value targets or critical infrastructure."
        ),
    },
    "T1563.002": {
        "name": "RDP Hijacking",
        "tactics": ['Lateral Movement'],
        "tactic_ids": ['TA0008'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1563.002 (RDP Hijacking), which falls under the following tactic "
            "category: Lateral Movement. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Lateral Movement: An adversary moving through the network to reach additional systems, expanding the scope of compromise, accessing segmented resources, and potentially reaching high-value targets or critical infrastructure."
        ),
    },
    "T1564": {
        "name": "Hide Artifacts",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1564 (Hide Artifacts), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1564.001": {
        "name": "Hidden Files and Directories",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1564.001 (Hidden Files and Directories), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1564.002": {
        "name": "Hidden Users",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1564.002 (Hidden Users), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1564.003": {
        "name": "Hidden Window",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1564.003 (Hidden Window), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1564.004": {
        "name": "NTFS File Attributes",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1564.004 (NTFS File Attributes), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1564.005": {
        "name": "Hidden File System",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1564.005 (Hidden File System), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1564.006": {
        "name": "Run Virtual Instance",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1564.006 (Run Virtual Instance), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1564.007": {
        "name": "VBA Stomping",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1564.007 (VBA Stomping), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1564.008": {
        "name": "Email Hiding Rules",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1564.008 (Email Hiding Rules), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1564.009": {
        "name": "Resource Forking",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1564.009 (Resource Forking), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1564.010": {
        "name": "Process Argument Spoofing",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1564.010 (Process Argument Spoofing), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1564.011": {
        "name": "Ignore Process Interrupts",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1564.011 (Ignore Process Interrupts), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1564.012": {
        "name": "File/Path Exclusions",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1564.012 (File/Path Exclusions), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1565": {
        "name": "Data Manipulation",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1565 (Data Manipulation), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1565.001": {
        "name": "Stored Data Manipulation",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1565.001 (Stored Data Manipulation), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1565.002": {
        "name": "Transmitted Data Manipulation",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1565.002 (Transmitted Data Manipulation), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1565.003": {
        "name": "Runtime Data Manipulation",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1565.003 (Runtime Data Manipulation), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1566": {
        "name": "Phishing",
        "tactics": ['Initial Access'],
        "tactic_ids": ['TA0001'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1566 (Phishing), which falls under the following tactic "
            "category: Initial Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Initial Access: An adversary gaining an initial foothold within the network, which could lead to unauthorized entry into systems, data exposure, and serve as a launching point for deeper compromise."
        ),
    },
    "T1566.001": {
        "name": "Spearphishing Attachment",
        "tactics": ['Initial Access'],
        "tactic_ids": ['TA0001'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1566.001 (Spearphishing Attachment), which falls under the following tactic "
            "category: Initial Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Initial Access: An adversary gaining an initial foothold within the network, which could lead to unauthorized entry into systems, data exposure, and serve as a launching point for deeper compromise."
        ),
    },
    "T1566.002": {
        "name": "Spearphishing Link",
        "tactics": ['Initial Access'],
        "tactic_ids": ['TA0001'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1566.002 (Spearphishing Link), which falls under the following tactic "
            "category: Initial Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Initial Access: An adversary gaining an initial foothold within the network, which could lead to unauthorized entry into systems, data exposure, and serve as a launching point for deeper compromise."
        ),
    },
    "T1566.003": {
        "name": "Spearphishing via Service",
        "tactics": ['Initial Access'],
        "tactic_ids": ['TA0001'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1566.003 (Spearphishing via Service), which falls under the following tactic "
            "category: Initial Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Initial Access: An adversary gaining an initial foothold within the network, which could lead to unauthorized entry into systems, data exposure, and serve as a launching point for deeper compromise."
        ),
    },
    "T1566.004": {
        "name": "Spearphishing Voice",
        "tactics": ['Initial Access'],
        "tactic_ids": ['TA0001'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1566.004 (Spearphishing Voice), which falls under the following tactic "
            "category: Initial Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Initial Access: An adversary gaining an initial foothold within the network, which could lead to unauthorized entry into systems, data exposure, and serve as a launching point for deeper compromise."
        ),
    },
    "T1567": {
        "name": "Exfiltration Over Web Service",
        "tactics": ['Exfiltration'],
        "tactic_ids": ['TA0010'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1567 (Exfiltration Over Web Service), which falls under the following tactic "
            "category: Exfiltration. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Exfiltration: An adversary stealing data from the network, potentially resulting in loss of sensitive information, intellectual property theft, regulatory compliance violations, and reputational damage."
        ),
    },
    "T1567.001": {
        "name": "Exfiltration to Code Repository",
        "tactics": ['Exfiltration'],
        "tactic_ids": ['TA0010'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1567.001 (Exfiltration to Code Repository), which falls under the following tactic "
            "category: Exfiltration. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Exfiltration: An adversary stealing data from the network, potentially resulting in loss of sensitive information, intellectual property theft, regulatory compliance violations, and reputational damage."
        ),
    },
    "T1567.002": {
        "name": "Exfiltration to Cloud Storage",
        "tactics": ['Exfiltration'],
        "tactic_ids": ['TA0010'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1567.002 (Exfiltration to Cloud Storage), which falls under the following tactic "
            "category: Exfiltration. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Exfiltration: An adversary stealing data from the network, potentially resulting in loss of sensitive information, intellectual property theft, regulatory compliance violations, and reputational damage."
        ),
    },
    "T1567.003": {
        "name": "Exfiltration to Text Storage Sites",
        "tactics": ['Exfiltration'],
        "tactic_ids": ['TA0010'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1567.003 (Exfiltration to Text Storage Sites), which falls under the following tactic "
            "category: Exfiltration. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Exfiltration: An adversary stealing data from the network, potentially resulting in loss of sensitive information, intellectual property theft, regulatory compliance violations, and reputational damage."
        ),
    },
    "T1567.004": {
        "name": "Exfiltration Over Webhook",
        "tactics": ['Exfiltration'],
        "tactic_ids": ['TA0010'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1567.004 (Exfiltration Over Webhook), which falls under the following tactic "
            "category: Exfiltration. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Exfiltration: An adversary stealing data from the network, potentially resulting in loss of sensitive information, intellectual property theft, regulatory compliance violations, and reputational damage."
        ),
    },
    "T1568": {
        "name": "Dynamic Resolution",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1568 (Dynamic Resolution), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1568.001": {
        "name": "Fast Flux DNS",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1568.001 (Fast Flux DNS), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1568.002": {
        "name": "Domain Generation Algorithms",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1568.002 (Domain Generation Algorithms), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1568.003": {
        "name": "DNS Calculation",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1568.003 (DNS Calculation), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1569": {
        "name": "System Services",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1569 (System Services), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1569.001": {
        "name": "Launchctl",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1569.001 (Launchctl), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1569.002": {
        "name": "Service Execution",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1569.002 (Service Execution), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1570": {
        "name": "Lateral Tool Transfer",
        "tactics": ['Lateral Movement'],
        "tactic_ids": ['TA0008'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1570 (Lateral Tool Transfer), which falls under the following tactic "
            "category: Lateral Movement. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Lateral Movement: An adversary moving through the network to reach additional systems, expanding the scope of compromise, accessing segmented resources, and potentially reaching high-value targets or critical infrastructure."
        ),
    },
    "T1571": {
        "name": "Non-Standard Port",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1571 (Non-Standard Port), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1572": {
        "name": "Protocol Tunneling",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1572 (Protocol Tunneling), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1573": {
        "name": "Encrypted Channel",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1573 (Encrypted Channel), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1573.001": {
        "name": "Symmetric Cryptography",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1573.001 (Symmetric Cryptography), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1573.002": {
        "name": "Asymmetric Cryptography",
        "tactics": ['Command and Control'],
        "tactic_ids": ['TA0011'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1573.002 (Asymmetric Cryptography), which falls under the following tactic "
            "category: Command and Control. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Command and Control: An adversary establishing communication channels to remotely control compromised systems, enabling ongoing command execution, data exfiltration, and coordinated attack activities from external infrastructure."
        ),
    },
    "T1574": {
        "name": "Hijack Execution Flow",
        "tactics": ['Persistence', 'Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0003', 'TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1574 (Hijack Execution Flow), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1574.001": {
        "name": "DLL Search Order Hijacking",
        "tactics": ['Persistence', 'Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0003', 'TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1574.001 (DLL Search Order Hijacking), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1574.002": {
        "name": "DLL Side-Loading",
        "tactics": ['Persistence', 'Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0003', 'TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1574.002 (DLL Side-Loading), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1574.004": {
        "name": "Dylib Hijacking",
        "tactics": ['Persistence', 'Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0003', 'TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1574.004 (Dylib Hijacking), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1574.005": {
        "name": "Executable Installer File Permissions Weakness",
        "tactics": ['Persistence', 'Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0003', 'TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1574.005 (Executable Installer File Permissions Weakness), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1574.006": {
        "name": "Dynamic Linker Hijacking",
        "tactics": ['Persistence', 'Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0003', 'TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1574.006 (Dynamic Linker Hijacking), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1574.007": {
        "name": "Path Interception by PATH Environment Variable",
        "tactics": ['Persistence', 'Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0003', 'TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1574.007 (Path Interception by PATH Environment Variable), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1574.008": {
        "name": "Path Interception by Search Order Hijacking",
        "tactics": ['Persistence', 'Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0003', 'TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1574.008 (Path Interception by Search Order Hijacking), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1574.009": {
        "name": "Path Interception by Unquoted Path",
        "tactics": ['Persistence', 'Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0003', 'TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1574.009 (Path Interception by Unquoted Path), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1574.010": {
        "name": "Services File Permissions Weakness",
        "tactics": ['Persistence', 'Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0003', 'TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1574.010 (Services File Permissions Weakness), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1574.011": {
        "name": "Services Registry Permissions Weakness",
        "tactics": ['Persistence', 'Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0003', 'TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1574.011 (Services Registry Permissions Weakness), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1574.012": {
        "name": "COR_PROFILER",
        "tactics": ['Persistence', 'Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0003', 'TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1574.012 (COR_PROFILER), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1574.013": {
        "name": "KernelCallbackTable",
        "tactics": ['Persistence', 'Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0003', 'TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1574.013 (KernelCallbackTable), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1574.014": {
        "name": "AppDomainManager",
        "tactics": ['Persistence', 'Privilege Escalation', 'Defense Evasion'],
        "tactic_ids": ['TA0003', 'TA0004', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1574.014 (AppDomainManager), which falls under the following tactic "
            "categories: Persistence, Privilege Escalation, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
            "\n  - Privilege Escalation: An adversary gaining higher-level permissions on a system or network, potentially achieving administrative or root-level control, enabling unrestricted access to sensitive resources and system configurations."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1578": {
        "name": "Modify Cloud Compute Infrastructure",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1578 (Modify Cloud Compute Infrastructure), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1578.001": {
        "name": "Create Snapshot",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1578.001 (Create Snapshot), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1578.002": {
        "name": "Create Cloud Instance",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1578.002 (Create Cloud Instance), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1578.003": {
        "name": "Delete Cloud Instance",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1578.003 (Delete Cloud Instance), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1578.004": {
        "name": "Revert Cloud Instance",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1578.004 (Revert Cloud Instance), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1578.005": {
        "name": "Modify Cloud Compute Configurations",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1578.005 (Modify Cloud Compute Configurations), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1580": {
        "name": "Cloud Infrastructure Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1580 (Cloud Infrastructure Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1583": {
        "name": "Acquire Infrastructure",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1583 (Acquire Infrastructure), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1583.001": {
        "name": "Domains",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1583.001 (Domains), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1583.002": {
        "name": "DNS Server",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1583.002 (DNS Server), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1583.003": {
        "name": "Virtual Private Server",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1583.003 (Virtual Private Server), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1583.004": {
        "name": "Server",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1583.004 (Server), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1583.005": {
        "name": "Botnet",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1583.005 (Botnet), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1583.006": {
        "name": "Web Services",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1583.006 (Web Services), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1583.007": {
        "name": "Serverless",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1583.007 (Serverless), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1583.008": {
        "name": "Malvertising",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1583.008 (Malvertising), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1584": {
        "name": "Compromise Infrastructure",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1584 (Compromise Infrastructure), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1584.001": {
        "name": "Domains",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1584.001 (Domains), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1584.002": {
        "name": "DNS Server",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1584.002 (DNS Server), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1584.003": {
        "name": "Virtual Private Server",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1584.003 (Virtual Private Server), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1584.004": {
        "name": "Server",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1584.004 (Server), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1584.005": {
        "name": "Botnet",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1584.005 (Botnet), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1584.006": {
        "name": "Web Services",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1584.006 (Web Services), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1584.007": {
        "name": "Serverless",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1584.007 (Serverless), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1585": {
        "name": "Establish Accounts",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1585 (Establish Accounts), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1585.001": {
        "name": "Social Media Accounts",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1585.001 (Social Media Accounts), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1585.002": {
        "name": "Email Accounts",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1585.002 (Email Accounts), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1585.003": {
        "name": "Cloud Accounts",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1585.003 (Cloud Accounts), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1586": {
        "name": "Compromise Accounts",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1586 (Compromise Accounts), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1586.001": {
        "name": "Social Media Accounts",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1586.001 (Social Media Accounts), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1586.002": {
        "name": "Email Accounts",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1586.002 (Email Accounts), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1586.003": {
        "name": "Cloud Accounts",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1586.003 (Cloud Accounts), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1587": {
        "name": "Develop Capabilities",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1587 (Develop Capabilities), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1587.001": {
        "name": "Malware",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1587.001 (Malware), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1587.002": {
        "name": "Code Signing Certificates",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1587.002 (Code Signing Certificates), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1587.003": {
        "name": "Digital Certificates",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1587.003 (Digital Certificates), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1587.004": {
        "name": "Exploits",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1587.004 (Exploits), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1588": {
        "name": "Obtain Capabilities",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1588 (Obtain Capabilities), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1588.001": {
        "name": "Malware",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1588.001 (Malware), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1588.002": {
        "name": "Tool",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1588.002 (Tool), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1588.003": {
        "name": "Code Signing Certificates",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1588.003 (Code Signing Certificates), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1588.004": {
        "name": "Digital Certificates",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1588.004 (Digital Certificates), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1588.005": {
        "name": "Exploits",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1588.005 (Exploits), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1588.006": {
        "name": "Vulnerabilities",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1588.006 (Vulnerabilities), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1589": {
        "name": "Gather Victim Identity Information",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1589 (Gather Victim Identity Information), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1589.001": {
        "name": "Credentials",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1589.001 (Credentials), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1589.002": {
        "name": "Email Addresses",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1589.002 (Email Addresses), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1589.003": {
        "name": "Employee Names",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1589.003 (Employee Names), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1590": {
        "name": "Gather Victim Network Information",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1590 (Gather Victim Network Information), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1590.001": {
        "name": "Domain Properties",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1590.001 (Domain Properties), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1590.002": {
        "name": "DNS",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1590.002 (DNS), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1590.003": {
        "name": "Network Trust Dependencies",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1590.003 (Network Trust Dependencies), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1590.004": {
        "name": "Network Topology",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1590.004 (Network Topology), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1590.005": {
        "name": "IP Addresses",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1590.005 (IP Addresses), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1590.006": {
        "name": "Network Security Appliances",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1590.006 (Network Security Appliances), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1591": {
        "name": "Gather Victim Org Information",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1591 (Gather Victim Org Information), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1591.001": {
        "name": "Determine Physical Locations",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1591.001 (Determine Physical Locations), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1591.002": {
        "name": "Business Relationships",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1591.002 (Business Relationships), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1591.003": {
        "name": "Identify Business Tempo",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1591.003 (Identify Business Tempo), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1591.004": {
        "name": "Identify Roles",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1591.004 (Identify Roles), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1592": {
        "name": "Gather Victim Host Information",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1592 (Gather Victim Host Information), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1592.001": {
        "name": "Hardware",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1592.001 (Hardware), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1592.002": {
        "name": "Software",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1592.002 (Software), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1592.003": {
        "name": "Firmware",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1592.003 (Firmware), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1592.004": {
        "name": "Client Configurations",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1592.004 (Client Configurations), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1593": {
        "name": "Search Open Websites/Domains",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1593 (Search Open Websites/Domains), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1593.001": {
        "name": "Social Media",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1593.001 (Social Media), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1593.002": {
        "name": "Search Engines",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1593.002 (Search Engines), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1593.003": {
        "name": "Code Repositories",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1593.003 (Code Repositories), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1594": {
        "name": "Search Victim-Owned Websites",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1594 (Search Victim-Owned Websites), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1595": {
        "name": "Active Scanning",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1595 (Active Scanning), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1595.001": {
        "name": "Scanning IP Blocks",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1595.001 (Scanning IP Blocks), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1595.002": {
        "name": "Vulnerability Scanning",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1595.002 (Vulnerability Scanning), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1595.003": {
        "name": "Wordlist Scanning",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1595.003 (Wordlist Scanning), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1596": {
        "name": "Search Open Technical Databases",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1596 (Search Open Technical Databases), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1596.001": {
        "name": "DNS/Passive DNS",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1596.001 (DNS/Passive DNS), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1596.002": {
        "name": "WHOIS",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1596.002 (WHOIS), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1596.003": {
        "name": "Digital Certificates",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1596.003 (Digital Certificates), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1596.004": {
        "name": "CDNs",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1596.004 (CDNs), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1596.005": {
        "name": "Scan Databases",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1596.005 (Scan Databases), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1597": {
        "name": "Search Closed Sources",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1597 (Search Closed Sources), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1597.001": {
        "name": "Threat Intel Vendors",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1597.001 (Threat Intel Vendors), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1597.002": {
        "name": "Purchase Technical Data",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1597.002 (Purchase Technical Data), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1598": {
        "name": "Phishing for Information",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1598 (Phishing for Information), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1598.001": {
        "name": "Spearphishing Service",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1598.001 (Spearphishing Service), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1598.002": {
        "name": "Spearphishing Attachment",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1598.002 (Spearphishing Attachment), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1598.003": {
        "name": "Spearphishing Link",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1598.003 (Spearphishing Link), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1598.004": {
        "name": "Spearphishing Voice",
        "tactics": ['Reconnaissance'],
        "tactic_ids": ['TA0043'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1598.004 (Spearphishing Voice), which falls under the following tactic "
            "category: Reconnaissance. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Reconnaissance: An adversary gathering information to plan future operations, potentially exposing organizational structure, technology stack, employee details, or network topology to inform targeted attacks."
        ),
    },
    "T1600": {
        "name": "Weaken Encryption",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1600 (Weaken Encryption), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1600.001": {
        "name": "Reduce Key Space",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1600.001 (Reduce Key Space), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1600.002": {
        "name": "Disable Crypto Hardware",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1600.002 (Disable Crypto Hardware), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1601": {
        "name": "Modify System Image",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1601 (Modify System Image), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1601.001": {
        "name": "Patch System Image",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1601.001 (Patch System Image), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1601.002": {
        "name": "Downgrade System Image",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1601.002 (Downgrade System Image), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1602": {
        "name": "Data from Configuration Repository",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1602 (Data from Configuration Repository), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1602.001": {
        "name": "SNMP (MIB Dump)",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1602.001 (SNMP (MIB Dump)), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1602.002": {
        "name": "Network Device Configuration Dump",
        "tactics": ['Collection'],
        "tactic_ids": ['TA0009'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1602.002 (Network Device Configuration Dump), which falls under the following tactic "
            "category: Collection. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Collection: An adversary gathering data of interest from target systems, potentially including sensitive documents, communications, credentials, intellectual property, or operationally critical information."
        ),
    },
    "T1606": {
        "name": "Forge Web Credentials",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1606 (Forge Web Credentials), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1606.001": {
        "name": "Web Cookies",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1606.001 (Web Cookies), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1606.002": {
        "name": "SAML Tokens",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1606.002 (SAML Tokens), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1608": {
        "name": "Stage Capabilities",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1608 (Stage Capabilities), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1608.001": {
        "name": "Upload Malware",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1608.001 (Upload Malware), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1608.002": {
        "name": "Upload Tool",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1608.002 (Upload Tool), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1608.003": {
        "name": "Install Digital Certificate",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1608.003 (Install Digital Certificate), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1608.004": {
        "name": "Drive-by Target",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1608.004 (Drive-by Target), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1608.005": {
        "name": "Link Target",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1608.005 (Link Target), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1608.006": {
        "name": "SEO Poisoning",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1608.006 (SEO Poisoning), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1609": {
        "name": "Container Administration Command",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1609 (Container Administration Command), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1610": {
        "name": "Deploy Container",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1610 (Deploy Container), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1612": {
        "name": "Build Image on Host",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1612 (Build Image on Host), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1613": {
        "name": "Container and Resource Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1613 (Container and Resource Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1614": {
        "name": "System Location Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1614 (System Location Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1614.001": {
        "name": "System Language Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1614.001 (System Language Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1615": {
        "name": "Group Policy Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1615 (Group Policy Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1619": {
        "name": "Cloud Storage Object Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1619 (Cloud Storage Object Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1621": {
        "name": "Multi-Factor Authentication Request Generation",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1621 (Multi-Factor Authentication Request Generation), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1622": {
        "name": "Debugger Evasion",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1622 (Debugger Evasion), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1647": {
        "name": "Plist File Modification",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1647 (Plist File Modification), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1648": {
        "name": "Serverless Execution",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1648 (Serverless Execution), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1649": {
        "name": "Steal or Forge Authentication Certificates",
        "tactics": ['Credential Access'],
        "tactic_ids": ['TA0006'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1649 (Steal or Forge Authentication Certificates), which falls under the following tactic "
            "category: Credential Access. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Credential Access: An adversary stealing credentials such as account names, passwords, tokens, or hashes, enabling unauthorized access to systems and data, lateral movement, and potential identity impersonation."
        ),
    },
    "T1650": {
        "name": "Acquire Access",
        "tactics": ['Resource Development'],
        "tactic_ids": ['TA0042'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1650 (Acquire Access), which falls under the following tactic "
            "category: Resource Development. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Resource Development: An adversary establishing infrastructure, accounts, or capabilities to support targeting, enabling future attack operations with purpose-built tools and staging resources."
        ),
    },
    "T1651": {
        "name": "Cloud Administration Command",
        "tactics": ['Execution'],
        "tactic_ids": ['TA0002'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1651 (Cloud Administration Command), which falls under the following tactic "
            "category: Execution. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Execution: An adversary running malicious code on a local or remote system, potentially leading to payload delivery, data manipulation, system compromise, or further propagation of the attack."
        ),
    },
    "T1652": {
        "name": "Device Driver Discovery",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1652 (Device Driver Discovery), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1654": {
        "name": "Log Enumeration",
        "tactics": ['Discovery'],
        "tactic_ids": ['TA0007'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1654 (Log Enumeration), which falls under the following tactic "
            "category: Discovery. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Discovery: An adversary gaining knowledge about the internal environment, including system configurations, network topology, installed software, and organizational structure to inform subsequent attack actions."
        ),
    },
    "T1656": {
        "name": "Impersonation",
        "tactics": ['Defense Evasion'],
        "tactic_ids": ['TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1656 (Impersonation), which falls under the following tactic "
            "category: Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1657": {
        "name": "Financial Theft",
        "tactics": ['Impact'],
        "tactic_ids": ['TA0040'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1657 (Financial Theft), which falls under the following tactic "
            "category: Impact. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Impact: An adversary disrupting availability or compromising integrity of systems and data, potentially causing business interruption, data destruction, ransomware encryption, or manipulation of critical processes."
        ),
    },
    "T1659": {
        "name": "Content Injection",
        "tactics": ['Initial Access', 'Defense Evasion'],
        "tactic_ids": ['TA0001', 'TA0005'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1659 (Content Injection), which falls under the following tactic "
            "categories: Initial Access, Defense Evasion. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Initial Access: An adversary gaining an initial foothold within the network, which could lead to unauthorized entry into systems, data exposure, and serve as a launching point for deeper compromise."
            "\n  - Defense Evasion: An adversary avoiding detection throughout the course of their intrusion, undermining security monitoring, disabling protections, and reducing the effectiveness of incident response capabilities."
        ),
    },
    "T1671": {
        "name": "Cloud Application Integration",
        "tactics": ['Persistence'],
        "tactic_ids": ['TA0003'],
        "description": (
            "{cve_id} in {software_name} is associated with MITRE ATT&CK technique "
            "T1671 (Cloud Application Integration), which falls under the following tactic "
            "category: Persistence. "
            "Exploitation of this vulnerability could lead to the following impacts:"
            "\n  - Persistence: An adversary maintaining their foothold across system restarts, credential changes, or other disruptions, ensuring continued unauthorized access and long-term compromise of affected systems."
        ),
    },
}


def get_scenario(technique_id: str, cve_id: str = "{cve_id}", software_name: str = "{software_name}") -> str:
    """Get a formatted scenario description for a given technique.
    
    Args:
        technique_id: MITRE ATT&CK technique ID (e.g., "T1190")
        cve_id: CVE identifier (e.g., "CVE-2024-1234")
        software_name: Name of the affected software
    
    Returns:
        Formatted scenario description string
    """
    if technique_id not in TECHNIQUE_SCENARIOS:
        return f"No scenario mapping found for technique {technique_id}"
    
    return TECHNIQUE_SCENARIOS[technique_id]["description"].format(
        cve_id=cve_id,
        software_name=software_name
    )


def get_tactics(technique_id: str) -> list:
    """Get the tactic categories for a given technique.
    
    Args:
        technique_id: MITRE ATT&CK technique ID
    
    Returns:
        List of tactic names
    """
    if technique_id not in TECHNIQUE_SCENARIOS:
        return []
    return TECHNIQUE_SCENARIOS[technique_id]["tactics"]


def get_impact(technique_id: str) -> str:
    """Get combined impact description for a technique based on its tactics.
    
    Args:
        technique_id: MITRE ATT&CK technique ID
    
    Returns:
        Combined impact description string
    """
    if technique_id not in TECHNIQUE_SCENARIOS:
        return ""
    tactic_ids = TECHNIQUE_SCENARIOS[technique_id]["tactic_ids"]
    impacts = []
    for tid in tactic_ids:
        if tid in TACTICS:
            impacts.append(f"{TACTICS[tid]['name']}: {TACTICS[tid]['impact']}")
    return "\n".join(impacts)


if __name__ == "__main__":
    # Example usage
    print("=== Example: T1190 (Exploit Public-Facing Application) ===")
    print(get_scenario("T1190", "CVE-2024-3400", "Palo Alto PAN-OS"))
    print()
    print("=== Example: T1078 (Valid Accounts) ===")
    print(get_scenario("T1078", "CVE-2024-9474", "FortiGate VPN"))
    print()
    print(f"Total techniques mapped: {len(TECHNIQUE_SCENARIOS)}")
    print(f"Parent techniques: {len([k for k in TECHNIQUE_SCENARIOS if chr(46) not in k])}")
    print(f"Sub-techniques: {len([k for k in TECHNIQUE_SCENARIOS if chr(46) in k])}")
