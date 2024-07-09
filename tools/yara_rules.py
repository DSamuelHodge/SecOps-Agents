import yara
import os
from typing import List, Dict, Any, Optional


class YaraRules:
    EXAMPLE_RULES = r"""
    import "pe"
    import "math"

    global rule FileSize
    {
        condition:
            filesize < 10MB
    }

    rule SuspiciousStrings
    {
        meta:
            description = "Detects suspicious strings often found in malware"
            author = "SecOps Team"
            severity = "High"

        strings:
            $s1 = "CreateRemoteThread" nocase wide ascii
            $s2 = "VirtualAlloc" nocase wide ascii
            $s3 = "WriteProcessMemory" nocase wide ascii
            $s4 = /(cmd|powershell).{0,10}exe/i
            $hex_string = { E2 34 ?? C8 A? FB }

        condition:
            (2 of ($s*)) or $hex_string
    }

    rule EncodedPowerShell
    {
        meta:
            description = "Detects encoded PowerShell commands"
            author = "SecOps Team"
            severity = "Medium"

        strings:
            $encoded = /powershell.{0,10}-e\s+[A-Za-z0-9+\/=]{20,}/i

        condition:
            $encoded
    }

    rule SuspiciousFileOperations
    {
        meta:
            description = "Detects suspicious file operations"
            author = "SecOps Team"
            severity = "Medium"

        strings:
            $op1 = "DeleteFile" nocase wide ascii
            $op2 = "MoveFile" nocase wide ascii
            $op3 = "CopyFile" nocase wide ascii
            $sys = "System32" nocase wide ascii

        condition:
            (2 of ($op*)) and $sys in (0..1024)
    }

    rule PEAnomalies
    {
        meta:
            description = "Detects anomalies in PE files"
            author = "SecOps Team"
            severity = "High"

        condition:
            pe.is_pe and
            (
                pe.number_of_sections > 8 or
                math.entropy(0, filesize) > 7.0 or
                pe.entry_point >= pe.sections[pe.section_index(".text")].raw_data_size
            )
    }

    private rule PrivateHelper
    {
        strings:
            $helper = "HelperFunction"

        condition:
            $helper
    }

    rule UsingPrivateRule
    {
        condition:
            PrivateHelper and filesize < 1MB
    }
    """

    def __init__(self):
        self.rules_source: str = ""
        self.compiled_rules: Optional[yara.Rules] = None
        self.warnings: List[str] = []

    def add_rule_string(self, rule_string: str) -> None:
        """Add a rule string to the existing rules."""
        self.rules_source += rule_string + "\n"

    def add_rule_file(self, filepath: str) -> None:
        """Add rules from a file to the existing rules."""
        with open(filepath, "r") as file:
            self.rules_source += file.read() + "\n"

    def add_rule_directory(self, directory: str) -> None:
        """Add all .yar and .yara files from a directory to the existing rules."""
        for filename in os.listdir(directory):
            if filename.endswith((".yar", ".yara")):
                filepath = os.path.join(directory, filename)
                self.add_rule_file(filepath)

    def compile_rules(self, externals: Dict[str, Any] = None) -> None:
        """Compile the rules and store any warnings."""
        try:
            self.compiled_rules = yara.compile(
                source=self.rules_source, externals=externals, error_on_warning=False
            )
            self.warnings = getattr(self.compiled_rules, "warnings", [])
        except yara.Error as e:
            print(f"Error compiling rules: {e}")
            self.compiled_rules = None
            self.warnings = []

    def save_compiled_rules(self, filepath: str) -> None:
        """Save compiled rules to a file."""
        if self.compiled_rules:
            try:
                self.compiled_rules.save(filepath)
                print(f"Compiled rules saved to {filepath}")
            except yara.Error as e:
                print(f"Error saving compiled rules: {e}")
        else:
            print("No compiled rules to save. Compile rules first.")

    def load_compiled_rules(self, filepath: str) -> None:
        """Load compiled rules from a file."""
        try:
            self.compiled_rules = yara.load(filepath)
            print(f"Compiled rules loaded from {filepath}")
        except yara.Error as e:
            print(f"Error loading compiled rules: {e}")
            self.compiled_rules = None

    def get_compiled_rules(self) -> Optional[yara.Rules]:
        """Get the compiled rules object."""
        return self.compiled_rules

    def get_warnings(self) -> List[str]:
        """Get the list of warnings from the last compilation."""
        return self.warnings

    def reset_rules(self) -> None:
        """Reset the rules, clearing all added rules."""
        self.rules_source = ""
        self.compiled_rules = None
        self.warnings = []

    def get_rule_count(self) -> int:
        """Get the number of rules in the compiled ruleset."""
        if self.compiled_rules:
            # Count the number of rule objects in the compiled rules
            return sum(1 for _ in self.compiled_rules)
        return 0

    def print_rules_summary(self) -> None:
        """Print a summary of the compiled rules."""
        if self.compiled_rules:
            print(f"Total rules: {self.get_rule_count()}")
            print(f"Warnings: {len(self.warnings)}")
            for warning in self.warnings:
                print(f"  - {warning}")
        else:
            print("No compiled rules available.")


if __name__ == "__main__":
    YaraRules()
    # Example usage
    # yara_rules = YaraRules()
    # yara_rules.add_rule_string(YaraRules.EXAMPLE_RULES)
    # yara_rules.compile_rules()
    # yara_rules.print_rules_summary()
