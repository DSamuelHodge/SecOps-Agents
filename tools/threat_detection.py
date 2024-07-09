import yara
from typing import Union, Dict, Any, List
from .yara_rules import YaraRules
from .suricata_integration import SuricataIntegration


class ThreatDetector:
    def __init__(self):
        self.yara_rules = YaraRules()
        self.yara_rules.add_rule_string(YaraRules.EXAMPLE_RULES)
        self.compile_rules()
        self.suricata = SuricataIntegration()

    def compile_rules(self):
        self.yara_rules.compile_rules()
        if self.yara_rules.get_compiled_rules() is None:
            raise RuntimeError("Failed to compile YARA rules")

    def detect_threats(
        self, data: Union[str, bytes], timeout: int = 60
    ) -> List[yara.Match]:
        if isinstance(data, str):
            data = data.encode("utf-8")
        return self.yara_rules.get_compiled_rules().match(
            data=data, timeout=timeout, callback=self._yara_callback
        )

    def detect_threats_with_suricata(self, pcap_file: str) -> Dict[str, Any]:
        with open(pcap_file, "rb") as f:
            yara_threats = self.detect_threats(f.read())
        suricata_analysis = self.suricata.analyze_pcap(pcap_file)
        return {"yara_threats": yara_threats, "suricata_analysis": suricata_analysis}

    @staticmethod
    def _yara_callback(data):
        print(f"Scanning rule: {data['rule']}")
        print(
            f"Rule '{data['rule']}' {'matched' if data['matches'] else 'did not match'}"
        )
        return yara.CALLBACK_CONTINUE


class ThreatAnalyzer:
    def __init__(self):
        try:
            self.detector = ThreatDetector()
        except RuntimeError as e:
            print(f"Failed to initialize ThreatDetector: {e}")
            self.detector = None

    def analyze_threats(self, data: Union[str, bytes], timeout: int = 60) -> str:
        if self.detector is None:
            return "Threat analysis is unavailable due to initialization error."

        threats = self.detector.detect_threats(data, timeout=timeout)
        return self._format_yara_analysis(threats)

    def analyze_pcap(self, pcap_file: str) -> str:
        if self.detector is None:
            return "Threat analysis is unavailable due to initialization error."

        results = self.detector.detect_threats_with_suricata(pcap_file)

        analysis = "Threat Analysis Report (PCAP)\n"
        analysis += "=" * 30 + "\n\n"

        analysis += "YARA Analysis:\n"
        analysis += "-" * 20 + "\n"
        analysis += self._format_yara_analysis(results["yara_threats"])

        analysis += "Suricata Analysis:\n"
        analysis += "-" * 20 + "\n"
        analysis += str(results["suricata_analysis"])
        analysis += "\n"

        return analysis

    def _format_yara_analysis(self, threats: List[yara.Match]) -> str:
        if not threats:
            return "No threats detected.\n"

        analysis = ""
        for threat in threats:
            analysis += f"Rule Triggered: {threat.rule}\n"
            analysis += f"Namespace: {threat.namespace}\n"
            analysis += f"Tags: {', '.join(threat.tags)}\n"
            analysis += "Metadata:\n"
            for key, value in threat.meta.items():
                analysis += f"  {key}: {value}\n"
            analysis += "Matched Strings:\n"
            for string in threat.strings:
                analysis += f"  - Identifier: {string.identifier}\n"
                analysis += f"    Data: {string.string}\n"
                analysis += f"    Offset: {string.instances[0].offset}\n"
            analysis += "\n"

        analysis += f"Total threats detected: {len(threats)}\n"
        return analysis


if __name__ == "__main__":
    analyzer = ThreatAnalyzer()

    # # Example usage with a string
    # test_data = "This is a test string with potential threat content."
    # result = analyzer.analyze_threats(test_data)
    # print(result)

    # # Example usage with a PCAP file
    # pcap_file = "path/to/your/capture.pcap"
    # result = analyzer.analyze_pcap(pcap_file)
    # print(result)

    # Example usage with YARA rules
    # test_data = """
    # CreateRemoteThread VirtualAllocEx
    # powershell.exe -e TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    # System32\\cmd.exe
    # """

    # result = analyzer.analyze_threats(test_data)
    # print(result)

    # Traceback (most recent call last):
    #   File "/Users/argosmacdevelopmentsystem/Desktop/SecOps-Agents/tools/threat_detection.py", line 185, in <module>
    #     result = analyzer.analyze_threats(test_data)
    #              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    #   File "/Users/argosmacdevelopmentsystem/Desktop/SecOps-Agents/tools/threat_detection.py", line 138, in analyze_threats
    #     threats = self.detector.detect_threats(
    #               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    #   File "/Users/argosmacdevelopmentsystem/Desktop/SecOps-Agents/tools/threat_detection.py", line 73, in detect_threats
    #     return [self._process_match(match) for match in matches]
    #             ^^^^^^^^^^^^^^^^^^^^^^^^^^
    #   File "/Users/argosmacdevelopmentsystem/Desktop/SecOps-Agents/tools/threat_detection.py", line 96, in _process_match
    #     "data": string.data,
    #             ^^^^^^^^^^^
    # AttributeError: 'yara.StringMatch' object has no attribute 'data'
