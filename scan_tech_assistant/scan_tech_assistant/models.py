"""Models for the Scan Tech Assistant."""

from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class Outcome(BaseModel):
    """Represents the outcome of a step in the procedure."""

    model_config = ConfigDict(extra="forbid")

    observation: str
    meaning: str
    next_action: str


class Step(BaseModel):
    """Represents a single step in the procedure."""

    model_config = ConfigDict(extra="forbid")

    order: int
    title: str
    explanation: str
    command: str | None
    payload_origin: Literal["plugin", "model_designed"] | None = None
    outcomes: list[Outcome] = Field(default_factory=list)


class ProcedureResponse(BaseModel):
    """Represents the response from the model containing the procedure steps and an optional note."""

    model_config = ConfigDict(extra="forbid")

    steps: list[Step]
    note: str = ""
