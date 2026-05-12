"""HTTP client + contract types for the target Co-Pilot."""

from cats.target.client import TargetClient
from cats.target.contracts import CopilotRequest, CopilotResponse

__all__ = ["CopilotRequest", "CopilotResponse", "TargetClient"]
