# SecOps Llama Agents

This project implements a Security Operations (SecOps) system using Llama Agents, providing advanced network analysis, threat detection using YARA rules, and log analysis capabilities.

## Prerequisites

- Python 3.11+
- pip (Python package manager)
- YARA (Yet Another Recursive/Ridiculous Acronym) - for threat detection

## Installation

1. Clone the repository:

   ```
   git clone https://github.com/your-username/secops-llama-agents.git
   cd secops-llama-agents
   ```

2. Install the required dependencies:

   ```
   pip install -r requirements.txt
   ```

3. Install YARA:

   - On Ubuntu/Debian: `sudo apt-get install yara`
   - On macOS with Homebrew: `brew install yara`
   - For other systems, refer to the [YARA documentation](https://yara.readthedocs.io/en/stable/gettingstarted.html)

4. Set up environment variables:
   Create a `.env` file in the project root and add your Groq API key:

   ```
   GROQ_API_KEY=your_groq_api_key_here
   ```

## Usage

1. Run the main script:

   ```
   python secops_llama_agents.py
   ```

2. The system will start and display a message indicating that it's running.

3. To interact with the system, open a new terminal and use the following command:

   ```
   llama-agents monitor --control-plane-url http://127.0.0.1:8000
   ```

4. You can now send commands to the system through the monitor. For example:

   ```
   analyze network traffic for the last 5 minutes
   ```

## YARA Threat Detection

YARA is integrated into our system for advanced threat detection. Here's how to use and configure YARA rules:

1. YARA rules are stored in the `yara_rules.py` file. You can modify existing rules or add new ones in this file.

2. To add a new YARA rule:

   - Open `yara_rules.py`
   - Add your rule to the `EXAMPLE_RULES` string or create a new string for your rules
   - Format your rule like this:

     ```
     rule example_rule {
         meta:
             description = "Description of your rule"
             threat_level = "medium"
         strings:
             $suspicious_string = "example suspicious string" nocase
         condition:
             $suspicious_string
     }
     ```

3. To use rules from external files:

   - Place your `.yar` or `.yara` files in a designated directory (e.g., `yara_rules/`)
   - In `threat_detection.py`, use the `load_rules_from_file` or `load_rules_from_directory` methods:

     ```python
     analyzer.detector.load_rules_from_file("path/to/your/rules.yar")
     # or
     analyzer.detector.load_rules_from_directory("path/to/yara_rules/")
     ```

4. You can also compile and save rules for faster loading:

   ```python
   analyzer.detector.save_compiled_rules("path/to/save/compiled_rules")
   analyzer.detector.load_compiled_rules("path/to/load/compiled_rules")
   ```

5. To run a threat detection analysis, use a command like:
   ```
   detect threats in file /path/to/suspicious/file
   ```

## Available Commands

The SecOps Llama Agents system provides the following capabilities:

- Capture and analyze network traffic
- Detect threats using YARA rules
- Perform vulnerability assessments
- Analyze log data for security events

You can interact with these capabilities by sending natural language commands through the monitor.

## Configuration

You can modify the `secops_llama_agents.py` file to adjust the following:

- LLM model: Change the `model` parameter in the `Groq` initialization.
- Embedding model: Modify the `model_name` in the `HuggingFaceEmbedding` initialization.
- Agent tools: Add or remove tools in the `tools` list.
- Network interface: Change the default interface in the `capture_network_traffic` function.
- YARA configuration: Adjust YARA-related settings in `threat_detection.py`

## Troubleshooting

- If you encounter permission errors when capturing network traffic, try running the script with sudo privileges.
- Ensure that your Groq API key is correctly set in the `.env` file.
- Check that all required dependencies are installed by running `pip install -r requirements.txt` again.
- If YARA is not detected, ensure it's properly installed and added to your system's PATH.

## Contributing

Contributions to improve the SecOps Llama Agents system are welcome. Please follow these steps:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/your-feature-name`)
3. Make your changes
4. Commit your changes (`git commit -am 'Add some feature'`)
5. Push to the branch (`git push origin feature/your-feature-name`)
6. Create a new Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Additional:
Usage

Ensure Suricata is running with the Unix socket enabled:
Copysuricata -c /etc/suricata/suricata.yaml --unix-socket=/var/run/suricata/suricata-command.socket

Run the main script:
Copypython threat_detection.py

To analyze a PCAP file:
pythonCopyanalyzer = ThreatAnalyzer()
result = analyzer.analyze_pcap("path/to/your/capture.pcap")
print(result)

Features

YARA-based threat detection
Suricata integration for network traffic analysis
Combined analysis of PCAP files using both YARA and Suricata

Configuration

YARA rules can be modified in the yara_rules.py file
Suricata settings can be adjusted in the suricata_integration.py file
