# This Python script defines classes for threat detection using Yara rules.
# It includes sample Yara rules for various threat categories and demonstrates
# threat analysis with a ThreatAnalyzer class.

import yara
from typing import List, Dict, Any, Tuple, Union
from dataclasses import dataclass, field


@dataclass
class YaraMatch:
    rule: str
    namespace: str
    tags: List[str]
    description: str
    strings: List[str] = field(default_factory=list)

class YaraRules:
    RULES = """
    rule potential_malware {
        meta:
            description = "Detects potential malware indicators"
        strings:
            $suspicious_func1 = "CreateRemoteThread" nocase
            $suspicious_func2 = "VirtualAlloc" nocase
            $suspicious_func3 = "WriteProcessMemory" nocase
            $encoded_command = /powershell\.exe.*-enc/
            $shellcode = {90 90 90 90}  // NOP sled
        condition:
            2 of ($suspicious_func*) or $encoded_command or $shellcode
    }

    rule suspicious_network_activity {
        meta:
            description = "Detects suspicious network communication patterns"
        strings:
            $http_request = /POST.*\.php HTTP\/1\.(0|1)/
            $unusual_dns = /\.bit$|\.dd$|\.eu\.org$/
            $tor_address = /\.onion$/
            $ip_literal = /http:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
        condition:
            any of them
    }

    rule potential_data_exfiltration {
        meta:
            description = "Detects patterns that might indicate data exfiltration"
        strings:
            $base64_data = /[A-Za-z0-9+\/]{50,}={0,2}/
            $hex_data = /[0-9A-Fa-f]{50,}/
            $compressed_data = /(gzip|deflate|compress|zip|rar)/
        condition:
            any of them and filesize > 1MB
    }

    rule ransomware_indicators {
        meta:
            description = "Detects common ransomware indicators"
        strings:
            $ransom_note = "Your files have been encrypted" nocase wide ascii
            $bitcoin = "bitcoin" nocase
            $file_extension = /\.encrypted$|\.locked$|\.crypted$/
        condition:
            2 of them
    }

    rule credential_harvesting {
        meta:
            description = "Detects potential credential harvesting attempts"
        strings:
            $password_regex = /password\s*=\s*['"][^'"]{6,}['"]/ nocase
            $api_key_regex = /api[_-]?key\s*=\s*['"][0-9a-zA-Z]{32,}['"]/ nocase
            $ssh_key = "BEGIN RSA PRIVATE KEY" wide ascii
        condition:
            any of them
    }
    """

class ThreatDetector:
    def __init__(self):
        self.rules = yara.compile(source=YaraRules.RULES)

    def detect_threats(self, data: Union[str, bytes]) -> List[YaraMatch]:
        if isinstance(data, str):
            data = data.encode('utf-8')

        matches = self.rules.match(data=data)
        return [self._process_match(match) for match in matches]

    def _process_match(self, match: yara.Match) -> YaraMatch:
        string_matches = []
        for string_match in match.strings:
            for instance in string_match.instances:
                match_info = (
                    f"{string_match.identifier}: "
                    f"{instance.matched_data.decode('utf-8', errors='ignore')} "
                    f"at offset {instance.offset}"
                )
                if string_match.is_xor():
                    match_info += f" (XOR key: {instance.xor_key})"
                string_matches.append(match_info)

        return YaraMatch(
            rule=match.rule,
            namespace=match.namespace,
            tags=match.tags,
            description=match.meta.get("description", "No description provided"),
            strings=string_matches
        )

class ThreatAnalyzer:
    def __init__(self):
        self.detector = ThreatDetector()

    def analyze_threats(self, data: Union[str, bytes]) -> str:
        threats = self.detector.detect_threats(data)

        if not threats:
            return "No threats detected."

        analysis = "Threat Analysis Report\n"
        analysis += "=" * 25 + "\n\n"

        for threat in threats:
            analysis += f"Rule Triggered: {threat.rule}\n"
            analysis += f"Namespace: {threat.namespace}\n"
            analysis += f"Tags: {', '.join(threat.tags)}\n"
            analysis += f"Description: {threat.description}\n"
            analysis += "Matched Strings:\n"
            for string in threat.strings:
                analysis += f"  - {string}\n"
            analysis += "\n"

        analysis += f"Total threats detected: {len(threats)}\n"
        return analysis

if __name__ == "__main__":
    ThreatAnalyzer()
