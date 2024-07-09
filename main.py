# Function Calling Fine-tuned Llama 3 Instruct
# https://huggingface.co/Trelis/Meta-Llama-3-70B-Instruct-function-calling

import os
import logging
from dotenv import load_dotenv
from llama_index.core import Settings
from llama_index.llms.groq import Groq
from llama_index.embeddings.huggingface import HuggingFaceEmbedding
from llama_index.core.agent import ReActAgent
from llama_index.core.tools import FunctionTool
from llama_agents import (
    AgentService,
    AgentOrchestrator,
    CallableMessageConsumer,
    ControlPlaneServer,
    ServerLauncher,
    SimpleMessageQueue,
    QueueMessage,
)

from tools.packet_analyzer import run_network_analysis
from tools.threat_detection import ThreatAnalyzer
from tools.vuln_log_analysis import SecurityAnalyzer
from utils.logging_config import setup_logging

# Load environment variables and set up logging
load_dotenv()
logger = setup_logging(logger_name="secops_agents", log_level=logging.INFO)


# Set Groq API key
groq_api_key = os.getenv("GROQ_API_KEY")

# Set up LLM and embedding model
llm = Groq(model="mixtral-8x7b-32768")
embed_model = HuggingFaceEmbedding(model_name="BAAI/bge-small-en-v1.5")

# Define global settings
Settings.llm = llm
Settings.embed_model = embed_model

# Initialize ThreatAnalyzer and SecurityAnalyzer
threat_analyzer = ThreatAnalyzer()
security_analyzer = SecurityAnalyzer()


# Define SecOps functions
async def capture_network_traffic(duration: int = 30, interface: str = "eth0") -> str:
    """Capture and analyze network packets for a specified duration."""
    analysis_result = await run_network_analysis(duration=duration, interface=interface)
    return f"Captured and analyzed {analysis_result['packet_count']} packets. Full report available."


def analyze_network_traffic(packet_data: str) -> str:
    """Process captured traffic data."""
    # Simplified analysis for demonstration
    return f"Analyzed {packet_data}. Found X suspicious patterns."


def detect_threats(data: str) -> str:
    """Detect threats using advanced Yara rules."""
    analysis_report = threat_analyzer.analyze_threats(data)
    return analysis_report


def assess_vulnerabilities(target: str) -> str:
    """Perform advanced vulnerability assessment."""
    assessment = security_analyzer.assess_vulnerabilities(target)
    report = f"Vulnerability Assessment for {assessment.target}:\n"
    report += "Open Ports:\n"
    for port_info in assessment.open_ports:
        report += f"  - Port {port_info.port}: {port_info.service}\n"
    report += "Potential Vulnerabilities:\n"
    for vuln in assessment.vulnerabilities:
        report += f"  - {vuln}\n"
    return report


def analyze_logs(log_data: str) -> str:
    """Analyze log data for security events."""
    analysis = security_analyzer.analyze_logs(log_data)
    report = "Log Analysis Report:\n"
    report += f"Total logs processed: {analysis.total_logs_processed}\n"
    report += "Event Summary:\n"
    for event, count in analysis.event_summary.items():
        report += f"  - {event}: {count}\n"
    report += f"Suspicious IPs: {', '.join(analysis.suspicious_ips)}\n"
    report += f"Suspicious Users: {', '.join(analysis.suspicious_users)}\n"
    report += "User Activities:\n"
    for user, activities in analysis.user_activities.items():
        report += f"  - {user}: {', '.join(activities)}\n"
    return report


# Create tools from functions
tools = [
    FunctionTool.from_defaults(fn=capture_network_traffic),
    FunctionTool.from_defaults(fn=analyze_network_traffic),
    FunctionTool.from_defaults(fn=detect_threats),
    FunctionTool.from_defaults(fn=assess_vulnerabilities),
    FunctionTool.from_defaults(fn=analyze_logs),
]

# Create message queue and queue client
message_queue = SimpleMessageQueue()
queue_client = message_queue.client

# Set up control plane and orchestrator
control_plane = ControlPlaneServer(
    message_queue=queue_client,
    orchestrator=AgentOrchestrator(llm=llm),
)

# Create agents and services
agents = []
for i, tool in enumerate(tools):
    agent = ReActAgent.from_tools([tool], llm=llm)
    service = AgentService(
        agent=agent,
        message_queue=queue_client,
        description=f"SecOps Agent {i+1}",
        service_name=f"secops_agent_{i+1}",
        host="localhost",
        port=8010 + i,
    )
    agents.append(service)


# Define human consumer for handling results
def handle_result(message: QueueMessage) -> None:
    logger.info(f"SecOps Result: {message.data}")


human_consumer = CallableMessageConsumer(handler=handle_result, message_type="human")

# Create and launch the system
launcher = ServerLauncher(
    agents,
    control_plane,
    message_queue,
    additional_consumers=[human_consumer],
)


if __name__ == "__main__":
    launcher.launch_servers()
    logger.info("SecOps Llama Agents system is running.")
    logger.info(
        "Use the following command in another terminal to interact with the system:"
    )
    logger.info("llama-agents monitor --control-plane-url http://127.0.0.1:8000")
