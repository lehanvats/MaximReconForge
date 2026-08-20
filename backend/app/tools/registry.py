"""
Tool registry — Pydantic-validated schemas for every tool a Commander can call.

Each tool is defined with: input schema, timeout, output size cap, risky flag,
and a reference to its result parser. Commanders only ever emit a tool name +
validated arguments from this registry — never raw shell text.

The registry also provides phase-scoped tool lists so each Commander only
sees the tools it's allowed to use.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, ConfigDict


# ---------------------------------------------------------------------------
# Tool input schemas — one per whitelisted tool
# ---------------------------------------------------------------------------

class SubfinderInput(BaseModel):
    """Subdomain discovery via subfinder."""
    domain: str = Field(..., description="Target root domain")


class AmassInput(BaseModel):
    """Subdomain enumeration via amass."""
    domain: str = Field(..., description="Target root domain")


class HttpxInput(BaseModel):
    """HTTP probing for live hosts."""
    targets: list[str] = Field(..., description="List of hostnames/URLs to probe")


class NaabuInput(BaseModel):
    """Fast port scanning."""
    target: str = Field(..., description="Hostname or IP to scan")
    ports: str = Field(default="top-1000", description="Port specification (e.g. '80,443' or 'top-1000')")


class NmapInput(BaseModel):
    """Service/version fingerprinting.

    Nmap flags are fixed (``-sV -sC``) and hardcoded in the worker executor —
    they are deliberately not exposed as a Commander-controllable field, so an
    LLM can never influence the nmap invocation beyond target and ports.
    """
    target: str = Field(..., description="Hostname or IP to scan")
    ports: str = Field(..., description="Comma-separated ports from naabu output")


class NucleiInput(BaseModel):
    """Template-based vulnerability scanning."""
    target: str = Field(..., description="Hostname or URL to scan")
    templates: list[str] = Field(default_factory=list, description="Specific template IDs (empty = all)")
    severity: str = Field(default="", description="Filter by severity: info,low,medium,high,critical")


class FfufInput(BaseModel):
    """Directory/path fuzzing."""
    target_url: str = Field(..., description="Base URL with FUZZ placeholder")
    wordlist: str = Field(default="common.txt", description="Wordlist name from the whitelisted set")
    extensions: str = Field(default="", description="File extensions to append (e.g. '.php,.html')")


class SqlmapInput(BaseModel):
    """SQL injection testing (risky — gated behind engagement toggle)."""
    target_url: str = Field(..., description="URL with injectable parameter")
    method: str = Field(default="GET", description="HTTP method")
    data: str = Field(default="", description="POST data if method=POST")
    level: int = Field(default=1, ge=1, le=5, description="Detection level (1-5)")
    risk: int = Field(default=1, ge=1, le=3, description="Risk level (1-3)")


class PhaseCompleteInput(BaseModel):
    """Typed termination signal — Commander calls this to end a phase."""
    summary: str = Field(..., description="Short rationale for completing the phase")


class SearchWhiteboardInput(BaseModel):
    """Semantic search against the engagement's whiteboard embeddings."""
    query: str = Field(..., description="Natural-language query for similarity search")
    top_k: int = Field(default=5, ge=1, le=20, description="Number of results to return")


# ---------------------------------------------------------------------------
# Tool definition
# ---------------------------------------------------------------------------

class ToolDefinition(BaseModel):
    """Registry entry for a single whitelisted tool."""

    name: str
    description: str
    input_schema: type[BaseModel]
    timeout_seconds: int = 300
    output_size_cap_bytes: int = 1_000_000  # 1 MB default
    risky: bool = False
    phase_available: list[str] = Field(
        default_factory=lambda: ["recon", "enumeration", "vuln_analysis", "exploitation"]
    )

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def to_openai_tool(self) -> dict[str, Any]:
        """Convert to OpenAI function-calling tool format."""
        schema = self.input_schema.model_json_schema()
        # Remove title/description from top-level to keep it clean
        schema.pop("title", None)
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": schema,
            },
        }


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------

TOOL_REGISTRY: dict[str, ToolDefinition] = {
    "run_subfinder": ToolDefinition(
        name="run_subfinder",
        description="Discover subdomains for a target domain using subfinder.",
        input_schema=SubfinderInput,
        timeout_seconds=120,
        phase_available=["recon"],
    ),
    "run_amass": ToolDefinition(
        name="run_amass",
        description="Enumerate subdomains using amass (passive mode).",
        input_schema=AmassInput,
        timeout_seconds=300,
        phase_available=["recon"],
    ),
    "run_httpx": ToolDefinition(
        name="run_httpx",
        description="Probe a list of hostnames for live HTTP services, returning status codes, titles, and tech fingerprints.",
        input_schema=HttpxInput,
        timeout_seconds=180,
        phase_available=["recon"],
    ),
    "run_naabu": ToolDefinition(
        name="run_naabu",
        description="Fast port scan against a target host.",
        input_schema=NaabuInput,
        timeout_seconds=120,
        phase_available=["recon"],
    ),
    "run_nmap": ToolDefinition(
        name="run_nmap",
        description="Service/version fingerprinting on specific open ports.",
        input_schema=NmapInput,
        timeout_seconds=300,
        phase_available=["enumeration"],
    ),
    "run_nuclei": ToolDefinition(
        name="run_nuclei",
        description="Run nuclei vulnerability scanner with template-based detection.",
        input_schema=NucleiInput,
        timeout_seconds=600,
        output_size_cap_bytes=5_000_000,  # nuclei can produce verbose output
        phase_available=["enumeration", "vuln_analysis"],
    ),
    "run_ffuf": ToolDefinition(
        name="run_ffuf",
        description="Fuzz directories/paths on a target URL to discover hidden endpoints.",
        input_schema=FfufInput,
        # Matches the worker's ffuf timeout floor (_SLOW_TOOL_MIN_TIMEOUT). ffuf
        # scales with wordlist size and can exceed the generic 300s; keeping the
        # registry value >= the worker floor ensures the backend's result-wait
        # (timeout + 60) always outlasts the actual worker run.
        timeout_seconds=450,
        phase_available=["vuln_analysis", "exploitation"],
    ),
    "run_sqlmap": ToolDefinition(
        name="run_sqlmap",
        description="Test for SQL injection vulnerabilities. RISKY: requires explicit engagement-level opt-in.",
        input_schema=SqlmapInput,
        timeout_seconds=600,
        risky=True,
        phase_available=["exploitation"],
    ),
    "phase_complete": ToolDefinition(
        name="phase_complete",
        description="Signal that the current phase is complete. Provide a short summary of what was accomplished.",
        input_schema=PhaseCompleteInput,
        timeout_seconds=5,
        phase_available=["vuln_analysis", "exploitation"],
    ),
    "search_whiteboard": ToolDefinition(
        name="search_whiteboard",
        description="Semantic search across the engagement's accumulated findings and notes. Use for fuzzy cross-finding pattern matching.",
        input_schema=SearchWhiteboardInput,
        timeout_seconds=10,
        phase_available=["vuln_analysis", "exploitation"],
    ),
}


def get_tools_for_phase(
    phase: str,
    risky_enabled: bool = False,
) -> list[ToolDefinition]:
    """Return only the tools available to a Commander in the given phase.

    Risky tools (e.g. sqlmap) are excluded unless the engagement has
    explicitly opted in via ``risky_tools_enabled``.
    """
    tools = []
    for tool in TOOL_REGISTRY.values():
        if phase not in tool.phase_available:
            continue
        if tool.risky and not risky_enabled:
            continue
        tools.append(tool)
    return tools


def get_openai_tools_for_phase(
    phase: str,
    risky_enabled: bool = False,
) -> list[dict[str, Any]]:
    """Return OpenAI function-calling format tools for a phase."""
    return [t.to_openai_tool() for t in get_tools_for_phase(phase, risky_enabled)]


def validate_tool_call(tool_name: str, arguments: dict[str, Any]) -> BaseModel:
    """Validate a tool call against its registered Pydantic schema.

    Raises ValueError if the tool doesn't exist or arguments are invalid.
    """
    if tool_name not in TOOL_REGISTRY:
        raise ValueError(f"Unknown tool: {tool_name}")

    tool_def = TOOL_REGISTRY[tool_name]
    return tool_def.input_schema(**arguments)
