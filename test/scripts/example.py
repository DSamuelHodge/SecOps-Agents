import os
import json
import asyncio
import logging
from dotenv import load_dotenv
from llama_index.core import Settings
from llama_index.llms.groq import Groq
from llama_index.embeddings.huggingface import HuggingFaceEmbedding
from llama_index.core.agent import ReActAgent
from llama_index.core.tools import FunctionTool
from llama_agents import (
    AgentService,
    ControlPlaneServer,
    SimpleMessageQueue,
    AgentOrchestrator,
    CallableMessageConsumer,
)

from tools.packet_analyzer import run_network_analysis
from tools.threat_detection import ThreatAnalyzer
from tools.vuln_log_analysis import SecurityAnalyzer

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Set Groq API key
groq_api_key = os.getenv("GROQ_API_KEY")
if not groq_api_key:
    logger.error("GROQ_API_KEY not found in environment variables")
    raise ValueError("GROQ_API_KEY not set")

# Set up LLM and embedding model
llm = Groq(model="llama3-8b-8192", api_key=groq_api_key)
embed_model = HuggingFaceEmbedding(model_name="BAAI/bge-small-en-v1.5")

# Define global settings
Settings.llm = llm
Settings.embed_model = embed_model

# Initialize ThreatAnalyzer and SecurityAnalyzer
threat_analyzer = ThreatAnalyzer()
security_analyzer = SecurityAnalyzer()


# Define SecOps functions
async def capture_network_traffic(duration: int = 30, interface: str = "eth0") -> str:
    logger.info(
        f"Capturing network traffic for {duration} seconds on interface {interface}"
    )
    analysis_result = await run_network_analysis(duration=duration, interface=interface)
    return f"Captured and analyzed {analysis_result['packet_count']} packets. Full report available."


def analyze_network_traffic(packet_data: str) -> str:
    logger.info(f"Starting analyze_network_traffic with data: {packet_data[:100]}...")
    result = f"Analyzed {packet_data}. Found X suspicious patterns."
    logger.info(f"Finished analyze_network_traffic: {result}")
    return result


def detect_threats(data: str) -> str:
    return threat_analyzer.analyze_threats(data)


def assess_vulnerabilities(target: str) -> str:
    assessment = security_analyzer.assess_vulnerabilities(target)
    return f"Vulnerability assessment complete for {assessment.target}"


def analyze_logs(log_data: str) -> str:
    analysis = security_analyzer.analyze_logs(log_data)
    return f"Log analysis complete. Processed {analysis.total_logs_processed} logs."


# Create tools from functions
tools = [
    FunctionTool.from_defaults(fn=capture_network_traffic),
    FunctionTool.from_defaults(fn=analyze_network_traffic),
    FunctionTool.from_defaults(fn=detect_threats),
    FunctionTool.from_defaults(fn=assess_vulnerabilities),
    FunctionTool.from_defaults(fn=analyze_logs),
]

# Create message queue and control plane
message_queue = SimpleMessageQueue()
control_plane = ControlPlaneServer(
    message_queue=message_queue,
    orchestrator=AgentOrchestrator(llm=llm),
)

# Create agents and services
agents = []
for i, tool in enumerate(tools):
    agent = ReActAgent.from_tools([tool], llm=llm)
    service = AgentService(
        agent=agent,
        message_queue=message_queue,
        description=f"SecOps Agent {i+1}",
        service_name=f"secops_agent_{i+1}",
        host="localhost",
        port=8010 + i,
    )
    agents.append(service)


# Define human consumer for handling results
def handle_result(message) -> None:
    logger.info("Received result from agent:")
    logger.info(f"Message type: {message.type}")
    logger.info(f"Message data: {message.data}")

    if isinstance(message.data, dict):
        if "response" in message.data:
            logger.info(f"Agent response: {message.data['response']}")
        if "error" in message.data:
            logger.error(f"Agent error: {message.data['error']}")
    else:
        logger.info(f"Full message data: {message.data}")

    # You might want to pretty print the result for the user here
    print("\nSecOps Agent Result:")
    print(json.dumps(message.data, indent=2))


human_consumer = CallableMessageConsumer(handler=handle_result, message_type="human")


async def launch_system():
    # Launch the message queue
    queue_task = asyncio.create_task(message_queue.launch_server())
    await asyncio.sleep(1)  # Wait for the message queue to be ready

    # Launch the control plane
    control_plane_task = asyncio.create_task(control_plane.launch_server())
    await asyncio.sleep(1)  # Wait for the control plane to be ready

    # Register the control plane as a consumer
    start_consuming_callable = await control_plane.register_to_message_queue()
    start_consuming_callables = [start_consuming_callable]

    # Register the services
    control_plane_url = f"http://{control_plane.host}:{control_plane.port}"
    service_tasks = []
    for service in agents:
        # Launch the service
        service_tasks.append(asyncio.create_task(service.launch_server()))

        # Register the service to the message queue
        start_consuming_callable = await service.register_to_message_queue()
        start_consuming_callables.append(start_consuming_callable)

        # Register the service to the control plane
        await service.register_to_control_plane(control_plane_url)

    # Register and start the human consumer
    human_start_consuming = await message_queue.register_consumer(human_consumer)
    start_consuming_callables.append(human_start_consuming)

    # Start consuming
    start_consuming_tasks = []
    for start_consuming_callable in start_consuming_callables:
        task = asyncio.create_task(start_consuming_callable())
        start_consuming_tasks.append(task)

    # Keep the system running
    await asyncio.gather(
        queue_task, control_plane_task, *service_tasks, *start_consuming_tasks
    )


if __name__ == "__main__":
    try:
        asyncio.run(launch_system())
        logger.info("SecOps Llama Agents system is running.")
        logger.info(
            "Use the following command in another terminal to interact with the system:"
        )
        logger.info("llama-agents monitor --control-plane-url http://127.0.0.1:8000")
    except Exception as e:
        logger.error(f"Error launching system: {e}")
        raise
