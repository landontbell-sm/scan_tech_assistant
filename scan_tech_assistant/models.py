"""Models for the Scan Tech Assistant."""

from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator


class Outcome(BaseModel):
    """Represents the outcome of a step in the procedure."""

    model_config = ConfigDict(extra="forbid")

    observation: str
    meaning: str
    next_action: str


class Step(BaseModel):
    """Represents a single step in the procedure."""

    model_config = ConfigDict(extra="forbid")

    title: str
    explanation: str
    command: str | None
    payload_origin: Literal["plugin", "model_designed"] | None
    outcomes: list[Outcome] = Field(default_factory=list)

    @field_validator("payload_origin", mode="before")
    @classmethod
    def lowercase_payload_origin(cls, value):
        """Normalizes payload_origin casing before the Literal check."""
        return value.lower() if isinstance(value, str) else value


class ProcedureResponse(BaseModel):
    """Represents the response from the model containing the procedure steps and an optional note."""

    model_config = ConfigDict(extra="forbid")

    steps: list[Step]
    note: str = ""
